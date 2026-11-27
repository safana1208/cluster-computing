"""Execution of screened programs: standard (reference) run vs. distributed cluster run (SRS 3.4, 3.5, 5.4-5.6).

* Standard run = the reference run of FR-5.2: the original, untransformed program and its input files
  are sent to one Worker Node and run there sequentially; timing markers around the parallel regions
  give T_seq (FR-5.5). Its output is the reference output.
* Cluster run: the transformed program runs on the Master Server in a restricted process
  (NFR-2.6, :mod:`master.program_host`). At each GO region the Mediator hands the data to this
  module, which splits it (Table 5.3.2), smoke-tests the first task on the Master (FR-4.2, sets the
  task timeout), lets the Scheduler distribute the tasks (FR-4.1), aggregates the results (FR-5.1)
  and returns them. T_par runs from the first dispatch to the end of aggregation, summed over regions.
* The cluster output is compared with the reference output (FR-5.2) and speedup = T_seq / T_par.
* Speedup graph (FR-5.5, 7.9): the cluster run repeated with 1 ... N Worker Nodes.

One run executes at a time; further requests wait in a queue (SRS 2.1.3). A run can be cancelled
(OI-17). Every run writes its outputs (SRS 2.1.4) under ``runs/<job>/runs/<run>/`` and one row in the
run history database.
"""

from __future__ import annotations

import ast
import base64
import collections
import contextlib
import hashlib
import json
import logging
import math
import os
import queue
import secrets
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from master.cluster import ProgramError, RunAborted, Scheduler
from worker.worker import Runner, isolation_prefix, rss_mb

logger = logging.getLogger("master.runs")

LEVELS = {"basic": 0, "detailed": 1, "debug": 2}
HOST_CODE = (Path(__file__).resolve().parent / "program_host.py").read_text(encoding="utf-8")
THREAD_KINDS = ("thread-group", "executor-map", "executor-submit")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class Run:
    id: str
    job_id: str
    filename: str
    mode: str                      # standard | cluster | sweep
    workers: int | None
    debug: str
    state: str = "PENDING"         # PENDING | RUNNING | COMPLETED | FAILED | CANCELLED
    phase: str = "waiting in the run queue"
    created_at: str = field(default_factory=_now)
    finished_at: str | None = None
    error: dict[str, Any] | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    validation: dict[str, Any] | None = None
    sweep: list[dict[str, Any]] = field(default_factory=list)
    logs: collections.deque = field(default_factory=lambda: collections.deque(maxlen=400))
    files: list[str] = field(default_factory=list)
    out_dir: Path | None = None
    started: float | None = None

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "job_id": self.job_id, "filename": self.filename, "mode": self.mode,
                "workers": self.workers, "debug": self.debug, "state": self.state, "phase": self.phase,
                "created_at": self.created_at, "finished_at": self.finished_at, "error": self.error,
                "metrics": self.metrics, "validation": self.validation, "sweep": self.sweep, "files": self.files,
                "elapsed_s": round(time.time() - self.started, 1) if self.started and not self.finished_at else None}


# ====================================================================== helpers
PREVIEW_CHARS = 4096  # live dashboard updates carry at most this much of a program's output


def keep_output(result: dict[str, Any], path: Path) -> dict[str, Any]:
    """Write the full output to ``path``; return the metrics without it (a short preview + size + file name)."""
    text = result.get("stdout") or ""
    path.write_text(text, encoding="utf-8")
    slim = {k: v for k, v in result.items() if k != "stdout"}
    slim.update(stdout_preview=text[:PREVIEW_CHARS], stdout_bytes=len(text.encode("utf-8")), stdout_file=path.name)
    return slim


def release_memory() -> None:
    """Give freed heap back to the OS after a run (glibc keeps it otherwise); a no-op elsewhere."""
    import gc

    gc.collect()
    try:
        import ctypes

        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except (OSError, AttributeError):
        pass


def bounds(n: int, parts: int) -> list[tuple[int, int]]:
    parts = max(1, min(parts, n))
    size, extra = divmod(n, parts)
    out, a = [], 0
    for i in range(parts):
        b = a + size + (1 if i < extra else 0)
        out.append((a, b))
        a = b
    return out


def aggregate(region: dict[str, Any], results: list[dict[str, Any] | None], best: int | None,
              calls: bool) -> tuple[dict[str, Any], str]:
    """Result Aggregator (FR-5.1, Table 5.3.1): rebuild every accumulator in task order."""
    vals = [r["value"] for r in results if r is not None]
    stdout = "".join(r.get("stdout") or "" for r in results if r is not None)
    out: dict[str, Any] = {}
    for acc in region.get("accumulators") or []:
        name, kind = acc["name"], acc["kind"]
        parts = [v[name] for v in vals if isinstance(v, dict) and name in v]
        if kind == "list":
            out[name] = [x for p in parts for x in p]
        elif kind == "sum":
            out[name] = sum(parts) if parts else 0
        elif kind == "set":
            seen: dict[str, Any] = {}
            for p in parts:
                for x in p:
                    seen.setdefault(json.dumps(x, sort_keys=True), x)
            out[name] = list(seen.values())
        elif kind in ("dict", "counter"):
            merged: dict[str, list[Any]] = {}
            for p in parts:
                for k, v in p:
                    key = json.dumps(k, sort_keys=True)
                    if key not in merged:
                        merged[key] = [k, v]
                    elif kind == "counter":
                        merged[key][1] += v
                    else:
                        merged[key][1] = v
            out[name] = list(merged.values())
    if any(a["kind"] == "first" for a in region.get("accumulators") or []):
        out["__match__"] = (results[best] or {}).get("value", {}).get("__match__") if best is not None else None
    if region["kind"] in THREAD_KINDS:
        if calls:
            out["__return__"] = [v.get("__return__") for v in vals]
        else:
            out["__return__"] = [x for v in vals for x in (v.get("__return__") or [])]
    return out, stdout


def _close(a: Any, b: Any, unordered: bool) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-9)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        if type(a) is not type(b) or len(a) != len(b):  # [1, 2] and (1, 2) print differently: not equal
            return False
        if unordered:
            a, b = sorted(a, key=repr), sorted(b, key=repr)
        return all(_close(x, y, unordered) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_close(a[k], b[k], unordered) for k in a)
    return a == b


def _line_equal(x: str, y: str, unordered: bool) -> bool:
    if x == y:
        return True
    try:
        return _close(ast.literal_eval(x.strip()), ast.literal_eval(y.strip()), unordered)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        pass
    tx, ty = x.split(), y.split()
    if len(tx) != len(ty):
        return False
    for a, b in zip(tx, ty):
        if a == b:
            continue
        try:
            if not math.isclose(float(a.strip(",()[]")), float(b.strip(",()[]")), rel_tol=1e-9, abs_tol=1e-9):
                return False
        except ValueError:
            if not _line_equal(a, b, unordered):
                return False
    return True


def compare_outputs(ref: str, par: str, unordered: bool) -> dict[str, Any]:
    """FR-5.2: exact, tolerance-based for floats, collections for unordered types and thread groups."""
    if ref == par:
        return {"status": "PASSED", "method": "exact match"}
    a, b = ref.splitlines(), par.splitlines()
    if len(a) != len(b):
        return {"status": "FAILED", "method": "line count", "detail": f"{len(a)} reference vs {len(b)} cluster lines"}
    if unordered:
        rest = list(b)
        for line in a:
            hit = next((i for i, other in enumerate(rest) if _line_equal(line, other, True)), None)
            if hit is None:
                return {"status": "FAILED", "method": "collection", "detail": f"no match for: {line[:200]}"}
            rest.pop(hit)
        return {"status": "PASSED", "method": "compared as collections (thread group)"}
    for i, (x, y) in enumerate(zip(a, b), 1):
        if not _line_equal(x, y, False):
            return {"status": "FAILED", "method": "line by line", "detail": f"line {i}: {x[:150]!r} vs {y[:150]!r}"}
    return {"status": "PASSED", "method": "floating-point tolerance / unordered collections"}


def source_line(source: str, region: dict[str, Any] | None, text: str | None) -> int | None:
    """Best effort: the original source line of an error raised inside a task template (FR-5.4)."""
    if not text:
        return region["line"] if region else None
    norm = lambda s: s.replace(" ", "").replace('"', "'")  # noqa: E731
    want = norm(text)
    lines = source.splitlines()
    lo, hi = (region["line"], region["end_line"]) if region else (1, len(lines))
    order = list(range(lo, hi + 1)) + [i for i in range(1, len(lines) + 1) if not lo <= i <= hi]
    for i in order:
        if 0 < i <= len(lines) and norm(lines[i - 1].strip()) == want:
            return i
    return region["line"] if region else None


def tests_report(results: list[list[Any]]) -> str:
    """Deterministic unittest report: one line per test in name order, then a summary (compared by FR-5.2)."""
    rows = sorted(results, key=lambda r: r[0])
    count = collections.Counter(r[1] for r in rows)
    lines = [f"{name} ... {status}" + (f": {detail}" if detail else "") for name, status, detail, _ in rows]
    lines.append(f"Ran {len(rows)} tests: {count['ok']} passed, {count['FAIL']} failed, {count['ERROR']} errors, "
                 f"{count['skipped']} skipped")
    return "\n".join(lines) + "\n"


def speedup_svg(points: list[tuple[int, float]]) -> str:
    """Speedup vs. number of Worker Nodes with the ideal linear speedup dashed (SRS 7.9)."""
    w, h, pad = 360, 220, 34
    n = max(k for k, _ in points)
    top = max([n] + [s for _, s in points]) * 1.1 or 1

    def xy(k: float, s: float) -> str:
        x = pad + (k - 1) / max(1, n - 1) * (w - 2 * pad) if n > 1 else w / 2
        return f"{x:.1f},{h - pad - s / top * (h - 2 * pad):.1f}"

    line = " ".join(xy(k, s) for k, s in points)
    dots = "".join(f'<circle cx="{xy(k, s).split(",")[0]}" cy="{xy(k, s).split(",")[1]}" r="3"/>' for k, s in points)
    labels = "".join(f'<text x="{xy(k, 0).split(",")[0]}" y="{h - pad + 14}" text-anchor="middle">{k}</text>'
                     for k, _ in points)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
            f'font-family="sans-serif" font-size="11">'
            f'<line x1="{pad}" y1="{h - pad}" x2="{w - pad}" y2="{h - pad}" stroke="#888"/>'
            f'<line x1="{pad}" y1="{pad}" x2="{pad}" y2="{h - pad}" stroke="#888"/>'
            f'<polyline points="{xy(1, 1)} {xy(n, n)}" fill="none" stroke="#999" stroke-dasharray="4 3"/>'
            f'<polyline points="{line}" fill="none" stroke="#1565c0" stroke-width="2"/><g fill="#1565c0">{dots}</g>'
            f'{labels}<text x="{w / 2}" y="{h - 4}" text-anchor="middle">Worker Nodes</text>'
            f'<text x="10" y="{pad - 10}">speedup (y axis 0 to {top / 1.1:.1f}; dashed = ideal linear)</text></svg>')


def speedup_png(points: list[tuple[int, float]], path: Path) -> bool:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False
    ks = [k for k, _ in points]
    fig, ax = plt.subplots(figsize=(5, 3.2))
    ax.plot(ks, [s for _, s in points], "o-", label="measured")
    ax.plot([1, max(ks)], [1, max(ks)], "--", color="grey", label="ideal")
    ax.set_xlabel("Worker Nodes")
    ax.set_ylabel("speedup")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return True


# ====================================================================== the run manager
class RunManager:
    def __init__(self, node: Any) -> None:
        self.node = node
        self.cfg = node.cfg
        c = self.cfg.cluster
        self.token = c.token or secrets.token_hex(24)
        hosts = [w.rsplit(":", 1)[0] for w in c.workers]
        if hosts and c.local_workers:
            hosts += ["127.0.0.1", "::1"]
        self.sched = Scheduler(c.bind, c.port, self.token, c.heartbeat_interval, c.retry_limit,
                               c.worker_wait_timeout, hosts, self.log)
        self.runs: dict[str, Run] = {}
        self.order: collections.deque[str] = collections.deque(maxlen=200)
        self.requests: queue.Queue[Run | None] = queue.Queue()
        self.current: Run | None = None
        self.cancel_event = threading.Event()
        self._host: subprocess.Popen | None = None
        self._local: dict[int, subprocess.Popen] = {}
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.smoke = Runner(str(node.cfg.data_dir / "smoke"), c.task_memory_mb, c.isolation)
        self.isolated = bool(isolation_prefix(c.isolation))

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.sched.start()
        for i in range(1, self.cfg.cluster.local_workers + 1):
            self._spawn_local(i)
        threading.Thread(target=self._loop, name="mn-runs", daemon=True).start()
        if self.cfg.cluster.local_workers:
            threading.Thread(target=self._keep_local, name="mn-local-workers", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self.cancel_event.set()
        self.sched.cancel_all("Master Server stopping")
        self.requests.put(None)
        self._kill_host()
        self.sched.stop()
        for p in self._local.values():
            with contextlib.suppress(OSError):
                p.terminate()
        for p in self._local.values():
            with contextlib.suppress(subprocess.TimeoutExpired):
                p.wait(timeout=5)
        self.smoke.kill()

    def _spawn_local(self, i: int) -> None:
        c = self.cfg.cluster
        env = {**os.environ, "CLUSTER_TOKEN": self.token, "PYTHONHASHSEED": "0"}
        cmd = [sys.executable, "-m", "worker", "--master", f"127.0.0.1:{self.sched.port}", "--name",
               f"local-{i}", "--slots", str(c.worker_slots), "--memory-mb", str(c.task_memory_mb), "--isolation",
               c.isolation, "--workdir", str(self.cfg.data_dir / "workers"), "--parent-pid", str(os.getpid())]
        from master.config import PROJECT_ROOT
        self._local[i] = subprocess.Popen(cmd, cwd=PROJECT_ROOT, env=env, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL, start_new_session=True)

    def _keep_local(self) -> None:
        """Restart a local Worker Node that stopped (it re-registers as a new node)."""
        while not self._stop.wait(2.0):
            for i, p in list(self._local.items()):
                if p.poll() is not None and not self._stop.is_set():
                    self.log("detailed", f"local Worker Node local-{i} exited ({p.returncode}); restarting")
                    self._spawn_local(i)

    # ------------------------------------------------------------------ logging
    def log(self, level: str, msg: str, **data: Any) -> None:
        run = self.current
        if run is None:
            if LEVELS.get(level, 0) == 0:
                self.node.bus.publish("log", level=level, msg=msg)
            return
        if LEVELS.get(level, 0) > LEVELS.get(run.debug, 0):
            return
        line = {"ts": _now()[11:23], "level": level, "msg": msg}
        run.logs.append(line)
        if run.out_dir:
            with contextlib.suppress(OSError), open(run.out_dir / "run.log", "a", encoding="utf-8") as fh:
                fh.write(f"{line['ts']} [{level}] {msg}\n")
        self.node.bus.publish("log", run=run.id, **line)

    def _update(self, run: Run, phase: str | None = None) -> None:
        if phase:
            run.phase = phase
            self.log("basic", phase)
        self.node.bus.publish("run", run=run.summary())

    # ------------------------------------------------------------------ requests
    def request(self, job_id: str, mode: str, debug: str | None, workers: int | None) -> Run:
        job = self.node.jobs.get(job_id)
        if job is None:
            raise ValueError("unknown job")
        if job.state == "BLOCKED":
            raise ValueError("this file was blocked as malicious and purged; it can't be executed")
        if job.state == "NOT_ELIGIBLE":
            raise ValueError("not eligible for parallelization: the program is not executed (SRS 3.2, FR-3.10)")
        if job.state == "REJECTED" and job.disposition == "SECURITY_VIOLATION":
            raise ValueError("rejected for a security violation: fix the listed lines and resubmit (FR-2.3)")
        if job.state != "READY":
            raise ValueError(f"the job is {job.state}; only screened, eligible programs can run")
        other = self.node.batch_restricted(job)
        if other:
            raise ValueError(f"{other} in the same folder was rejected for a security violation and could be "
                             "imported by this program: fix it and resubmit the folder")
        if mode not in ("standard", "cluster", "sweep"):
            raise ValueError("mode must be standard, cluster or sweep")
        debug = debug or self.cfg.master.debug_level
        if debug not in LEVELS:
            raise ValueError("debug level must be basic, detailed or debug")
        if workers is not None and workers < 1:
            raise ValueError("workers must be >= 1")
        run = Run(f"{datetime.now():%H%M%S}-{secrets.token_hex(2)}", job.id, job.filename, mode, workers, debug)
        with self._lock:
            self.runs[run.id] = run
            self.order.append(run.id)
            while len(self.runs) > 200:
                self.runs.pop(next(iter(self.runs)), None)
        self.requests.put(run)
        self._update(run)
        return run

    def cancel(self, run_id: str) -> Run:
        run = self.runs.get(run_id)
        if run is None:
            raise ValueError("unknown run")
        if run.state == "PENDING":
            run.state, run.finished_at, run.phase = "CANCELLED", _now(), "cancelled before it started"
        elif run.state == "RUNNING":
            self.cancel_event.set()
            self.sched.cancel_all("cancelled by the user")
            self._kill_host()
        self._update(run)
        return run

    def busy(self) -> bool:
        return self.current is not None or any(r.state == "PENDING" for r in self.runs.values())

    def list_runs(self, job_id: str | None = None) -> list[dict[str, Any]]:
        ids = list(self.order)
        return [self.runs[i].summary() for i in reversed(ids) if i in self.runs
                and (job_id is None or self.runs[i].job_id == job_id)]

    def status(self) -> dict[str, Any]:
        s = self.sched.status()
        with self.sched.lock:
            regions = list(self.sched.regions.values())
            total = sum(len(r.tasks) for r in regions)
            done = sum(1 for r in regions for t in r.tasks if t.state == "done")
        cur = self.current
        return {**s, "isolation": "namespaces (no network, user nobody) + rlimits" if self.isolated else "rlimits only",
                "current_run": cur.summary() if cur else None, "progress": {"done": done, "total": total},
                "pending_runs": sum(1 for r in self.runs.values() if r.state == "PENDING"),
                "local_workers": self.cfg.cluster.local_workers}

    # ------------------------------------------------------------------ execution loop
    def _loop(self) -> None:
        while not self._stop.is_set():
            run = self.requests.get()
            if run is None:
                return
            if run.state != "PENDING":
                continue
            self.cancel_event.clear()
            self.current = run
            try:
                self._execute(run)
            except Exception as exc:  # noqa: BLE001 - never kill the run loop
                logger.exception("run %s failed", run.id)
                self._fail(run, "internal", {"type": type(exc).__name__, "message": str(exc)[:400]})
            finally:
                self.current = None
                self.sched.allowed = None
                self._finish(run)
                release_memory()

    def _fail(self, run: Run, category: str, error: dict[str, Any], stage: str | None = None) -> None:
        run.state = "CANCELLED" if self.cancel_event.is_set() else "FAILED"
        run.error = {"category": category, "stage": stage or run.phase, **{k: v for k, v in error.items()
                                                                             if k != "trace"}}
        self.log("basic", f"run {run.state.lower()} ({category}): {error.get('type', '')}: {error.get('message', '')}"
                 + (f" (line {error['line']})" if error.get("line") else ""))

    def _finish(self, run: Run) -> None:
        run.finished_at = _now()
        if run.state == "RUNNING":
            run.state = "COMPLETED"
        run.phase = {"COMPLETED": "completed", "FAILED": "failed", "CANCELLED": "cancelled"}.get(run.state, run.phase)
        if run.out_dir:
            perf = {"run": run.summary(), "logs": list(run.logs)}
            (run.out_dir / "performance.json").write_text(json.dumps(perf, indent=2, default=str), encoding="utf-8")
            run.files = sorted(p.name for p in run.out_dir.iterdir() if p.is_file())
        with contextlib.suppress(Exception):
            self.node.history.save_run(run)
        self._update(run)

    def _job_context(self, run: Run) -> dict[str, Any]:
        job = self.node.jobs[run.job_id]
        run_dir = self.node.dirs["runs"] / job.id
        # The full report lives on disk (core keeps only a summary in RAM); it is read for this run only.
        report = job.report if "eligibility" in job.report else json.loads(
            (run_dir / "report.json").read_text(encoding="utf-8"))
        elig = report["eligibility"]
        source = (run_dir / "program.py").read_text(encoding="utf-8")
        go = [r for r in elig["regions"] if r["decision"] == "GO"]
        inputs_dir = run_dir / "inputs"
        prep = sum(t["ms"] for t in job.timeline if t["stage"] in ("validation", "security", "eligibility"))
        return {"job": job, "run_dir": run_dir, "elig": elig, "source": source, "go": go,
                "inputs": lambda: self._read_inputs(inputs_dir),  # loaded when a task message is built
                "inputs_dir": inputs_dir, "prep_ms": prep, "unordered": any(r["kind"] in THREAD_KINDS for r in go)}

    @staticmethod
    def _read_inputs(inputs_dir: Path) -> dict[str, dict[str, str]]:
        inputs: dict[str, dict[str, str]] = {}
        if inputs_dir.is_dir():
            for p in sorted(inputs_dir.rglob("*")):
                if p.is_file():
                    raw = p.read_bytes()
                    try:
                        inputs[str(p.relative_to(inputs_dir))] = {"text": raw.decode("utf-8")}
                    except UnicodeDecodeError:
                        inputs[str(p.relative_to(inputs_dir))] = {"b64": base64.b64encode(raw).decode()}
        return inputs

    def _execute(self, run: Run) -> None:
        run.state, run.started = "RUNNING", time.time()
        ctx = self._job_context(run)
        run.out_dir = ctx["run_dir"] / "runs" / run.id
        run.out_dir.mkdir(parents=True, exist_ok=True)
        self.log("basic", f"run {run.id}: {run.mode} mode, {ctx['job'].filename}, debug level {run.debug}")
        if self.node.batch_tainted(ctx["job"]):
            self._fail(run, "security violation", {"type": "Blocked", "message": "a file of this folder is malicious"})
            return
        try:
            if self.cfg.cluster.local_workers:
                self.sched.wait_for_workers(1, self.cfg.cluster.worker_wait_timeout)
            suite = ctx["elig"].get("test_suite")
            reference = self._reference_tests if suite else self._reference
            distributed = self._distributed_tests if suite else self._distributed
            ref = reference(run, ctx, force=run.mode == "standard")
            if run.mode == "standard":
                run.metrics = {"standard": keep_output(ref, run.out_dir / "result.txt"),
                               "preparation_ms": round(ctx["prep_ms"], 1)}
                return
            if run.mode == "cluster":
                par = distributed(run, ctx, run.workers)
                self._report(run, ctx, ref, par)
                return
            n = len(self.sched.online())
            if run.workers:
                n = min(n, run.workers)
            points = []
            for k in range(1, n + 1):
                par = distributed(run, ctx, k)
                val = compare_outputs(ref["stdout"], par["stdout"], ctx["unordered"])
                sp = ref["t_seq_ms"] / par["t_par_ms"] if par["t_par_ms"] > 0 and ref["t_seq_ms"] > 0 else None
                run.sweep.append({"workers": k, "t_par_ms": par["t_par_ms"], "wall_ms": par["wall_ms"],
                                  "speedup": round(sp, 3) if sp else None, "validation": val["status"],
                                  "retries": par["retries"]})
                if sp:
                    points.append((k, sp))
                del par  # each step's output is compared, then dropped
                self._update(run)
            run.metrics = {"standard": keep_output(ref, run.out_dir / "reference_output.txt"),
                           "preparation_ms": round(ctx["prep_ms"], 1)}
            if points:
                (run.out_dir / "speedup.svg").write_text(speedup_svg(points), encoding="utf-8")
                speedup_png(points, run.out_dir / "speedup.png")
                best = max(points, key=lambda p: p[1])
                run.metrics["sweep_best"] = {"workers": best[0], "speedup": round(best[1], 3)}
                self.log("basic", f"speedup graph: best {best[1]:.2f}x with {best[0]} Worker Node(s)")
        except ProgramError as exc:
            err = dict(exc.error)
            self._fail(run, "program error", err, exc.where)
        except RunAborted as exc:
            self._fail(run, "cancelled" if self.cancel_event.is_set() else "worker failure",
                       {"type": "RunAborted", "message": str(exc)})

    def _report(self, run: Run, ctx: dict[str, Any], ref: dict[str, Any], par: dict[str, Any]) -> None:
        val = compare_outputs(ref["stdout"], par["stdout"], ctx["unordered"])
        ref = keep_output(ref, run.out_dir / "reference_output.txt")
        par = keep_output(par, run.out_dir / "result.txt")
        run.validation = val
        sp = ref["t_seq_ms"] / par["t_par_ms"] if par["t_par_ms"] > 0 and ref["t_seq_ms"] > 0 else None
        prep = ctx["prep_ms"] + par["smoke_ms"]
        run.metrics = {"standard": ref, "cluster": par, "preparation_ms": round(prep, 1),
                       "speedup": round(sp, 3) if sp else None,
                       "program_speedup": round(ref["wall_ms"] / par["wall_ms"], 3) if par["wall_ms"] else None}
        if val["status"] != "PASSED":
            self.log("basic", f"validation FAILED: {val.get('detail')} (AF-5.6.2)")
        else:
            self.log("basic", f"validation passed ({val['method']}); T_seq {ref['t_seq_ms']:.0f} ms, T_par "
                              f"{par['t_par_ms']:.0f} ms, speedup {sp:.2f}x" if sp else "validation passed")

    # ------------------------------------------------------------------ standard = reference run (FR-5.2)
    def _reference(self, run: Run, ctx: dict[str, Any], force: bool) -> dict[str, Any]:
        cached = self._cached_reference(ctx, force)
        if cached:
            return cached
        self._update(run, "standard run: original program on one Worker Node (reference, FR-5.2)")
        self.sched.use_workers(None)
        marks = [[r["id"], r["line"], r["end_line"]] for r in ctx["go"]]
        msg = lambda: {"kind": "program", "src": ctx["source"], "files": ctx["inputs"](), "marks": marks}  # noqa: E731
        results, region = self.sched.run_tasks("reference run", [msg], float(self.cfg.cluster.run_timeout),
                                               cancelled=self.cancel_event)
        res = results[0] or {}
        if not res.get("ok"):
            raise ProgramError(res.get("error") or {}, "standard (reference) run")
        marks_ms = (res.get("value") or {}).get("marks") or {}
        ref = {"node": next(iter(region.workers_used), None), "wall_ms": round(res.get("ms", 0.0), 1),
               "t_seq_ms": round(sum(marks_ms.values()), 1), "regions": marks_ms, "stdout": res.get("stdout", "")}
        self._store_reference(ctx, ref)
        self.log("basic", f"standard run done on {ref['node']}: program {ref['wall_ms']:.0f} ms, "
                          f"T_seq (parallel regions) {ref['t_seq_ms']:.0f} ms")
        return ref

    def _cached_reference(self, ctx: dict[str, Any], force: bool) -> dict[str, Any] | None:
        cached = getattr(ctx["job"], "reference", None)
        path = ctx["run_dir"] / "reference_output.txt"
        if force or not cached or not path.exists():
            return None
        self.log("detailed", "using the reference run measured earlier for this program")
        return {**cached, "stdout": path.read_text(encoding="utf-8")}

    @staticmethod
    def _store_reference(ctx: dict[str, Any], ref: dict[str, Any]) -> None:
        """The reference output is kept in the job folder; RAM keeps only its metrics."""
        ctx["job"].reference = keep_output(ref, ctx["run_dir"] / "reference_output.txt")

    # ------------------------------------------------------------------ test suites (extension)
    def _tests_failed(self, res: dict[str, Any], where: str) -> ProgramError:
        err = dict(res.get("error") or {})
        if err.get("type") in ("ModuleNotFoundError", "ImportError"):
            err["message"] = (f"{err.get('message')} - the tests import a module that was not submitted: "
                              "submit the folder that contains the test file and that module")
        return ProgramError(err, where)

    def _reference_tests(self, run: Run, ctx: dict[str, Any], force: bool) -> dict[str, Any]:
        """Standard run of a test suite: every test, sequentially, in one process on one Worker Node."""
        job = ctx["job"]
        cached = self._cached_reference(ctx, force)
        if cached:
            return cached
        cases = ctx["elig"]["test_suite"]["cases"]
        self._update(run, f"standard run: all {len(cases)} tests in one process on one Worker Node (reference)")
        self.sched.use_workers(None)
        msg = lambda: {"kind": "tests", "src": ctx["source"], "filename": job.filename,  # noqa: E731
                       "files": ctx["inputs"](), "names": cases}
        try:
            results, region = self.sched.run_tasks("reference run", [msg], float(self.cfg.cluster.run_timeout),
                                                   cancelled=self.cancel_event)
        except ProgramError as exc:
            raise self._tests_failed({"error": exc.error}, "standard (reference) run") from None
        res = results[0] or {}
        if not res.get("ok"):
            raise self._tests_failed(res, "standard (reference) run")
        tests = res["value"]["tests"]
        t_seq = round(sum(t[3] for t in tests), 1)
        ref = {"node": next(iter(region.workers_used), None), "wall_ms": round(res.get("ms", 0.0), 1),
               "t_seq_ms": t_seq, "regions": {"tests": t_seq}, "stdout": tests_report(tests)}
        self._store_reference(ctx, ref)
        self.log("basic", f"standard run done on {ref['node']}: {len(tests)} tests in {t_seq:.0f} ms")
        return ref

    def _distributed_tests(self, run: Run, ctx: dict[str, Any], workers: int | None) -> dict[str, Any]:
        """Cluster run of a test suite: one task per test method, pulled by the Worker Nodes."""
        chosen = self.sched.use_workers(workers)
        if not chosen:
            raise RunAborted("no Worker Node is online (AF-5.4.1)")
        job, cases = ctx["job"], ctx["elig"]["test_suite"]["cases"]
        names = [w.name for w in chosen]
        self._update(run, f"cluster run: {len(cases)} tests as tasks on {len(chosen)} Worker Node(s) "
                          f"({', '.join(names)})")
        base = {"kind": "tests", "src": ctx["source"], "filename": job.filename}
        msgs = [lambda name=name: {**base, "files": ctx["inputs"](), "names": [name]} for name in cases]
        t0 = time.perf_counter()
        smoke = self.smoke.run({**msgs[0](), "task": "smoke", "attempt": 0}, float(self.cfg.cluster.run_timeout))
        smoke_ms = (time.perf_counter() - t0) * 1000
        if not smoke.get("ok"):
            if smoke.get("timeout") or smoke.get("infra"):
                raise RunAborted(f"smoke test failed: {(smoke.get('error') or {}).get('message')}")
            raise self._tests_failed(smoke, "smoke test (T2)")
        # Test durations differ a lot, so the smoke test can't predict them: the run time limit applies per test.
        timeout = float(self.cfg.cluster.run_timeout)
        self._update(run, f"test suite: {len(msgs)} task(s) → scheduler")
        try:
            results, reg = self.sched.run_tasks("test suite", msgs, timeout, False, self.cancel_event)
        except ProgramError as exc:
            raise self._tests_failed({"error": exc.error}, "test suite on the Worker Nodes") from None
        failed = next((r for r in results if r is not None and not r.get("ok")), None)
        if failed:
            raise self._tests_failed(failed, "test suite on the Worker Nodes")
        tests = [t for r in results if r is not None for t in r["value"]["tests"]]
        t_par = round((time.perf_counter() - reg.t_first_dispatch) * 1000, 1)
        entry = {"task": "tests", "id": "tests", "kind": "test-suite", "line": 1, "tasks": len(msgs),
                 "retries": reg.retries, "workers": sorted(reg.workers_used), "smoke_ms": round(smoke_ms, 1),
                 "timeout_s": timeout, "t_par_ms": t_par, "early_stop": None}
        self.log("basic", f"cluster run done with {len(chosen)} Worker Node(s): {len(tests)} tests, T_par {t_par:.0f} ms")
        return {"workers": names, "worker_count": len(chosen),
                "wall_ms": round((time.perf_counter() - t0) * 1000, 1), "t_par_ms": t_par,
                "smoke_ms": round(smoke_ms, 1), "regions": [entry], "tasks": len(msgs), "retries": reg.retries,
                "stdout": tests_report(tests)}

    # ------------------------------------------------------------------ cluster run
    def _kill_host(self) -> None:
        proc = self._host
        if proc and proc.poll() is None:
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, 9)

    def _distributed(self, run: Run, ctx: dict[str, Any], workers: int | None) -> dict[str, Any]:
        chosen = self.sched.use_workers(workers)
        if not chosen:
            raise RunAborted("no Worker Node is online (AF-5.4.1)")
        names = [w.name for w in chosen]
        self._update(run, f"cluster run: transformed program on the Master, regions on {len(chosen)} Worker "
                          f"Node(s) ({', '.join(names)})")
        work = run.out_dir / f"work-{len(chosen)}"
        shutil.rmtree(work, ignore_errors=True)
        if ctx["inputs_dir"].is_dir():
            shutil.copytree(ctx["inputs_dir"], work)
        work.mkdir(parents=True, exist_ok=True)
        (work / "output").mkdir(exist_ok=True)
        transformed = ctx["elig"].get("transformed_program")
        if not transformed:
            raise RunAborted("no transformed program was generated")
        by_task = {r["task_name"]: r for r in ctx["go"]}
        meta = [{"task": r["task_name"], "kind": r["kind"], "target": r.get("target"),
                 "acc": {a["name"]: a["kind"] for a in r["accumulators"]}} for r in ctx["go"]]
        state: dict[str, Any] = {"regions": [], "smoke_ms": 0.0, "error": None, "merge": collections.Counter()}
        c = self.cfg.cluster
        r1, w1 = os.pipe()
        r2, w2 = os.pipe()
        cmd = [*isolation_prefix(c.isolation), sys.executable, "-I", "-c", HOST_CODE, str(r1), str(w2),
               str(c.run_memory_mb)]
        env = {"PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1", "MALLOC_ARENA_MAX": "2", "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "LANG": "C.UTF-8"}
        t0 = time.perf_counter()
        proc = subprocess.Popen(cmd, pass_fds=(r1, w2), cwd=work, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        self._host = proc
        os.close(r1)
        os.close(w2)
        to_host = os.fdopen(w1, "w", encoding="utf-8", buffering=1)
        from_host = os.fdopen(r2, "r", encoding="utf-8")
        out_buf: list[bytes] = []
        err_buf: list[bytes] = []

        def drain(stream, buf, cap=8 * 1024 * 1024) -> None:
            size = 0
            for chunk in iter(lambda: stream.read(65536), b""):
                if size < cap:
                    buf.append(chunk)
                    size += len(chunk)

        readers = [threading.Thread(target=drain, args=(proc.stdout, out_buf), daemon=True),
                   threading.Thread(target=drain, args=(proc.stderr, err_buf), daemon=True)]
        for t in readers:
            t.start()
        killer = threading.Timer(float(c.run_timeout), self._kill_host)
        killer.daemon = True
        killer.start()
        over: list[float] = []

        def watch_memory() -> None:  # NFR-2.6 memory limit of the transformed program, on real memory (RSS)
            while proc.poll() is None:
                used = rss_mb(proc.pid)
                if used is not None and used > c.run_memory_mb:
                    over.append(used)
                    self._kill_host()
                    return
                time.sleep(0.1)

        threading.Thread(target=watch_memory, name="mn-run-memory", daemon=True).start()
        exit_msg: dict[str, Any] | None = None
        try:
            to_host.write(json.dumps({"source": transformed, "regions": meta}) + "\n")
            for line in from_host:
                msg = json.loads(line)
                msg["_bytes"] = len(line)  # used to size the chunks without re-serialising them
                del line
                op = msg.get("op")
                if op in ("region", "calls"):
                    reply = self._region(run, ctx, by_task.get(msg.get("task")), msg, state)
                    try:
                        to_host.write(json.dumps(reply) + "\n")
                    except (BrokenPipeError, OSError):
                        break
                    if isinstance(state["error"], RunAborted):
                        self._kill_host()
                elif op == "note":
                    state["merge"][msg.get("task")] += float(msg.get("merge_ms", 0))
                elif op == "exit":
                    exit_msg = msg
                    break
        except (BrokenPipeError, OSError, json.JSONDecodeError):
            pass
        finally:
            killer.cancel()
            with contextlib.suppress(OSError):
                to_host.close()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._kill_host()
                proc.wait(timeout=5)
            for t in readers:
                t.join(timeout=5)
            from_host.close()
            self._host = None
            shutil.rmtree(work, ignore_errors=True)  # the run's copy of the inputs is not kept
        wall = (time.perf_counter() - t0) * 1000
        if state["error"] is not None:
            raise state["error"]
        if self.cancel_event.is_set():
            raise RunAborted("cancelled by the user")
        if exit_msg is None and over:
            raise ProgramError({"type": "MemoryError", "message": f"the program used {over[0]:.0f} MB, more than "
                                f"run_memory_mb ({c.run_memory_mb} MB)"}, "transformed program on the Master Server")
        if exit_msg is None:
            tail = b"".join(err_buf).decode("utf-8", "replace")[-400:]
            if wall >= c.run_timeout * 1000:
                raise RunAborted(f"the run exceeded run_timeout ({c.run_timeout}s)")
            raise RunAborted(f"the transformed program's process ended unexpectedly: {tail or 'no output'}")
        if not exit_msg.get("ok"):
            err = exit_msg.get("error") or {}
            raise ProgramError({**err, "line_in": "transformed program"}, "transformed program on the Master Server")
        for r in state["regions"]:
            r["t_par_ms"] = round(r["t_par_ms"] + state["merge"].get(r["task"], 0.0), 1)
        t_par = round(sum(r["t_par_ms"] for r in state["regions"]), 1)
        res = {"workers": names, "worker_count": len(chosen), "wall_ms": round(exit_msg.get("ms", wall), 1),
               "t_par_ms": t_par, "smoke_ms": round(state["smoke_ms"], 1), "regions": state["regions"],
               "tasks": sum(r["tasks"] for r in state["regions"]),
               "retries": sum(r["retries"] for r in state["regions"]),
               "stdout": b"".join(out_buf).decode("utf-8", "replace")}
        self.log("basic", f"cluster run done with {len(chosen)} Worker Node(s): T_par {t_par:.0f} ms, "
                          f"{res['tasks']} task(s), {res['retries']} retr{'y' if res['retries'] == 1 else 'ies'}")
        return res

    def _payloads(self, region: dict[str, Any], msg: dict[str, Any]) -> tuple[list[Callable[[], dict[str, Any]]], str]:
        """Split a region's data (Table 5.3.2) into chunk *factories*: a chunk is sliced only when its task is
        dispatched, and dropped when its result arrives, so the Master never holds every chunk message at once."""
        c = self.cfg.cluster
        if msg["op"] == "calls":
            calls = msg["calls"]
            return [lambda i=i: {"args": calls[i].get("args") or [], "kwargs": calls[i].get("kwargs") or {}}
                    for i in range(len(calls))], "args"
        data = msg.get("data") or {}
        units = max(1, self.sched.active_slots())
        if "range" in data:
            start, stop, step = data["range"]
            n = len(range(start, stop, step))
            parts = math.ceil(n / c.chunk_size) if c.chunk_size else c.chunk_factor * units
            return [lambda a=a, b=b: {"start": start + a * step, "stop": start + b * step, "step": step,
                                      "first_index": a} for a, b in bounds(n, parts)] if n else [], "chunk"
        key = "files" if "files" in data else "items"
        seq = data.get(key) or []
        if not seq:
            return [], "chunk"
        parts = math.ceil(len(seq) / c.chunk_size) if c.chunk_size else c.chunk_factor * units
        # OI-18: keep every chunk message under the size limit, estimated from the Mediator message size.
        parts = max(parts, math.ceil(msg.get("_bytes", 0) / (0.8 * c.max_message_bytes)))
        if key == "files" and any(len(text) > c.max_message_bytes for _, text in seq):
            raise RunAborted(f"a file is larger than the message-size limit ({c.max_message_bytes} bytes)")
        return [lambda a=a, b=b: {key: seq[a:b], "start": a} for a, b in bounds(len(seq), parts)], "chunk"

    def _region(self, run: Run, ctx: dict[str, Any], region: dict[str, Any] | None, msg: dict[str, Any],
                state: dict[str, Any]) -> dict[str, Any]:
        if region is None or state["error"] is not None:
            return {"ok": False, "error": {"type": "RunAborted", "message": "unknown region or run aborted"}}
        label = f"region {region['id']} ({region['kind']}, line {region['line']})"
        try:
            payloads, call = self._payloads(region, msg)
            template = region["task_template"]
            tid = hashlib.sha256(template.encode()).hexdigest()[:16]
            base = {"kind": "template", "tid": tid, "src": template, "entry": region["task_name"], "call": call,
                    "consts": msg.get("consts") or {}}
            msgs = [lambda p=p: {**base, "payload": p()} for p in payloads]
            entry = {"task": region["task_name"], "id": region["id"], "kind": region["kind"], "line": region["line"],
                     "tasks": len(msgs), "retries": 0, "workers": [], "smoke_ms": 0.0, "timeout_s": None,
                     "t_par_ms": 0.0, "early_stop": None}
            state["regions"].append(entry)
            if not msgs:
                result, stdout = aggregate(region, [], None, call == "args")
                return {"ok": True, "result": result, "stdout": stdout, "chunks": []}
            # FR-4.2 smoke test: the first task on the Master Server, restricted (NFR-2.6); counted as preparation
            self._update(run, f"{label}: smoke test of task 0 on the Master Server")
            t = time.perf_counter()
            smoke = self.smoke.run({**msgs[0](), "task": "smoke", "attempt": 0}, float(self.cfg.cluster.run_timeout))
            smoke_ms = (time.perf_counter() - t) * 1000
            state["smoke_ms"] += smoke_ms
            entry["smoke_ms"] = round(smoke_ms, 1)
            if not smoke.get("ok"):
                err = smoke.get("error") or {}
                if smoke.get("timeout") or smoke.get("infra"):
                    raise RunAborted(f"smoke test failed: {err.get('message')}")
                err = {**err, "line": source_line(ctx["source"], region, err.get("text")), "line_in": "original"}
                raise ProgramError(err, f"smoke test of {label} (T2)")
            timeout = max(self.cfg.cluster.task_timeout_min, smoke_ms / 1000 * self.cfg.cluster.timeout_factor)
            entry["timeout_s"] = round(timeout, 2)
            self._update(run, f"{label}: {len(msgs)} task(s) → scheduler")
            first = any(a["kind"] == "first" for a in region["accumulators"])
            results, reg = self.sched.run_tasks(label, msgs, timeout, first, self.cancel_event)
            if region["kind"] == "sort":
                chunks = [r["value"] for r in results if r is not None]
                entry.update(retries=reg.retries, workers=sorted(reg.workers_used),
                             t_par_ms=(time.perf_counter() - reg.t_first_dispatch) * 1000)
                return {"ok": True, "chunks": chunks}
            result, stdout = aggregate(region, results, reg.best, call == "args")
            entry.update(retries=reg.retries, workers=sorted(reg.workers_used),
                         t_par_ms=(time.perf_counter() - reg.t_first_dispatch) * 1000,
                         early_stop=(f"match in task {reg.best}; {sum(1 for r in results if r is None)} task(s) "
                                     f"skipped" if reg.best is not None else None))
            return {"ok": True, "result": result, "stdout": stdout}
        except ProgramError as exc:
            if exc.error.get("line_in") != "original":
                exc.error = {**exc.error, "line": source_line(ctx["source"], region, exc.error.get("text")),
                             "line_in": "original"}
            state["error"] = exc
            return {"ok": False, "error": exc.error}
        except RunAborted as exc:
            state["error"] = exc
            return {"ok": False, "error": {"type": "RunAborted", "message": str(exc)}}
