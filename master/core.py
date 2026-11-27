"""Master Node orchestrator: intake -> validation -> sandboxed security + eligibility -> routing.

Concurrency model (each tool used where it fits the work):

====================  =========================  ===============================================
Work                  Runs in                    Why
====================  =========================  ===============================================
HTTP / WebSocket      uvicorn event loop thread  many idle connections, async I/O
Job orchestration     ThreadPoolExecutor         blocking I/O: pipes to sandboxes, disk, SQLite
(``mn-pipeline``)
Syntax validation     ProcessPoolExecutor        CPU-bound parsing of untrusted code, kept out of
(SRS 5.1)             (forkserver)               the Master's process; real multi-core parallelism
Security + AST        Docker sandbox pool        isolation: the untrusted file only ever meets a
eligibility                                      locked-down container (separate processes)
Import folder         ``mn-import-watcher``      periodic polling (FR-1.11)
Live status push      ``mn-status``              1 Hz dashboard refresh (NFR-1.2: < 2 s)
Sandbox healing       ``mn-sandbox-supervisor``  replaces crashed / recycled sandboxes

Cluster scheduler     ``mn-cluster-*`` threads   TCP server, one reader per Worker Node, watchdog
Runs                  ``mn-runs`` (one at a time) standard (reference) and cluster runs, see runs.py
====================  =========================  ===============================================

Files are handled fail-closed: a program can run only after the complete configured screening
passed (FR-2.4). A malicious program is a hard stop: its file is deleted, it is purged from the run
history database and the run files (for a folder: every file of that folder), a security event
is logged, and it can never be executed.

On every start the run history database and the run files are wiped (``master.reset_on_start``),
so a long-running Raspberry Pi never fills its SD card.
"""

from __future__ import annotations

import collections
import concurrent.futures as cf
import contextlib
import json
import logging
import multiprocessing
import os
import re
import secrets
import shutil
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from master import __version__
from master.config import Config
from master.precheck import precheck, warm_up
from master.sandbox import SandboxError, SandboxPool

logger = logging.getLogger("master")

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")
ACTIVE_STATES = ("RECEIVED", "QUEUED", "VALIDATING", "SCREENING")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


LOG_CAP_BYTES = 20 * 1024 * 1024


def append_capped(path: Path, line: str, lock: threading.Lock, cap: int = LOG_CAP_BYTES) -> None:
    """Append one JSON line; at ``cap`` bytes the file is rotated to ``<name>.1`` (one old copy is kept)."""
    with lock:
        try:
            if path.exists() and path.stat().st_size >= cap:
                os.replace(path, path.with_name(path.name + ".1"))
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            logger.warning("could not write %s: %s", path.name, exc)


def sanitize_filename(raw: str) -> str | None:
    """Base name with safe characters only; must end in .py."""
    name = _SAFE_NAME.sub("_", os.path.basename(str(raw).replace("\\", "/")))[:100].lstrip(".")
    return name if name.lower().endswith(".py") and len(name) > 3 else None


@dataclass
class Job:
    id: str
    filename: str
    via: str
    size: int
    submitted_at: str
    t0: float = field(default_factory=time.perf_counter)
    sha256: str | None = None
    state: str = "RECEIVED"
    stage: str = "received"
    security_verdict: str | None = None
    eligibility_verdict: str | None = None
    disposition: str | None = None
    error: str | None = None
    total_ms: float | None = None
    working_copy: Path | None = None
    timeline: list[dict[str, Any]] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)
    lane: str | None = None
    started_epoch: float | None = None
    finished_epoch: float | None = None
    batch: str | None = None
    inputs: dict[str, bytes] = field(default_factory=dict)
    reference: dict[str, Any] | None = None
    go_regions: int | None = None
    region_count: int = 0

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "filename": self.filename, "via": self.via, "size": self.size,
                "submitted_at": self.submitted_at, "sha256": self.sha256, "state": self.state, "stage": self.stage,
                "security_verdict": self.security_verdict, "eligibility_verdict": self.eligibility_verdict,
                "disposition": self.disposition, "error": self.error, "total_ms": self.total_ms, "lane": self.lane,
                "started_epoch": self.started_epoch, "finished_epoch": self.finished_epoch,
                "go_regions": self.go_regions if self.go_regions is not None
                else (self.report.get("eligibility") or {}).get("go_regions"),
                "regions": self.region_count or len((self.report.get("eligibility") or {}).get("regions") or []),
                "batch": self.batch, "inputs": len(self.inputs) if isinstance(self.inputs, dict) else 0}


class EventBus:
    """Thread-safe fan-out of events to subscribers (the web layer bridges them into asyncio)."""

    def __init__(self, size: int = 1000) -> None:
        self.recent: collections.deque[dict[str, Any]] = collections.deque(maxlen=size)
        self._subs: list[Callable[[dict[str, Any]], None]] = []
        self._lock = threading.Lock()

    def subscribe(self, fn: Callable[[dict[str, Any]], None]) -> None:
        with self._lock:
            self._subs.append(fn)

    def unsubscribe(self, fn: Callable[[dict[str, Any]], None]) -> None:
        with self._lock:
            if fn in self._subs:
                self._subs.remove(fn)

    def publish(self, kind: str, **data: Any) -> dict[str, Any]:
        event = {"ts": _now(), "kind": kind, "thread": threading.current_thread().name, **data}
        with self._lock:
            if kind != "status":
                self.recent.append(event)
            subs = list(self._subs)
        for fn in subs:
            try:
                fn(event)
            except Exception:  # a broken subscriber must not break the pipeline
                logger.debug("subscriber failed", exc_info=True)
        return event


#: SQLite tuned for a Raspberry Pi: a few hundred KB of page cache, no memory-mapped I/O, temporary tables on
#: disk, write-ahead log capped at 1 MB. The database stores concise metadata only - sources, reports and
#: program outputs stay in the run folder (report.json, result.txt), never in the database or in RAM.
_SQLITE_PRAGMAS = (
    "PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL", "PRAGMA cache_size=-256", "PRAGMA mmap_size=0",
    "PRAGMA temp_store=FILE", "PRAGMA journal_size_limit=1048576", "PRAGMA wal_autocheckpoint=256",
    "PRAGMA foreign_keys=ON",
)
SCHEMA_VERSION = 2
_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY, filename TEXT NOT NULL, sha256 TEXT, via TEXT, size INTEGER, batch TEXT,
    submitted_at TEXT NOT NULL, finished_at TEXT, state TEXT NOT NULL, security TEXT, eligibility TEXT,
    disposition TEXT, error TEXT, total_ms REAL, go_regions INTEGER, regions INTEGER
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS jobs_by_time ON jobs(submitted_at);
CREATE TABLE IF NOT EXISTS job_runs (
    id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE, mode TEXT NOT NULL,
    workers INTEGER, state TEXT NOT NULL, created_at TEXT NOT NULL, finished_at TEXT, t_seq_ms REAL,
    t_par_ms REAL, speedup REAL, tasks INTEGER, retries INTEGER, validation TEXT, error TEXT, out_dir TEXT
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS job_runs_by_job ON job_runs(job_id);
CREATE INDEX IF NOT EXISTS job_runs_by_time ON job_runs(created_at);
"""


class History:
    """Run history database (SRS 2.1.4): one compact row per submission and one per run.

    Bounded: at most ``max_jobs`` jobs and ``max_runs`` runs are kept; the oldest are pruned through the
    time indexes (a job's runs are deleted with it, ON DELETE CASCADE).
    """

    def __init__(self, path: Path, max_jobs: int = 500, max_runs: int = 1000) -> None:
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        self.max_jobs, self.max_runs = max_jobs, max_runs
        self._writes = 0
        with self._lock:
            for pragma in _SQLITE_PRAGMAS:
                self._db.execute(pragma)
            if self._db.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
                self._db.executescript("DROP TABLE IF EXISTS runs; DROP TABLE IF EXISTS executions;")  # v1 blobs
            self._db.executescript(_SCHEMA)
            self._db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self._prune()

    def _prune(self) -> None:
        """Delete the oldest rows beyond the caps (index range scans, no table scan)."""
        self._db.execute("DELETE FROM jobs WHERE id IN (SELECT id FROM jobs ORDER BY submitted_at DESC LIMIT -1 "
                         "OFFSET ?)", (self.max_jobs,))
        self._db.execute("DELETE FROM job_runs WHERE id IN (SELECT id FROM job_runs ORDER BY created_at DESC "
                         "LIMIT -1 OFFSET ?)", (self.max_runs,))

    def _write(self, sql: str, args: tuple[Any, ...]) -> None:
        with self._lock:
            self._db.execute(sql, args)
            self._writes += 1
            if self._writes % 50 == 0:
                self._prune()

    def save(self, job: Job) -> None:
        self._write("INSERT OR REPLACE INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            job.id, job.filename, job.sha256, job.via, job.size, job.batch, job.submitted_at, _now(), job.state,
            job.security_verdict, job.eligibility_verdict, job.disposition, (job.error or "")[:500] or None,
            job.total_ms, job.go_regions, job.region_count))

    def init_runs(self) -> None:  # kept for compatibility: the schema is created in __init__
        return None

    def save_run(self, run: Any) -> None:
        m = run.metrics or {}
        cluster = m.get("cluster") or {}
        err = run.error or {}
        self._write("INSERT OR REPLACE INTO job_runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            run.id, run.job_id, run.mode, run.workers, run.state, run.created_at, run.finished_at,
            (m.get("standard") or {}).get("t_seq_ms"), cluster.get("t_par_ms"), m.get("speedup"),
            cluster.get("tasks"), cluster.get("retries"), (run.validation or {}).get("status"),
            (f"{err.get('type')}: {err.get('message')}"[:300] if err else None),
            str(run.out_dir) if run.out_dir else None))

    def delete(self, job_id: str) -> None:
        """Purge a submission and its runs (malicious files leave no record in the run history database)."""
        with self._lock:
            self._db.execute("DELETE FROM jobs WHERE id = ?", (job_id,))

    def recent(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, filename, via, size, submitted_at, sha256, state, security, eligibility, disposition, "
                "error, total_ms, go_regions, regions, batch FROM jobs ORDER BY submitted_at DESC LIMIT ?",
                (limit,)).fetchall()
        keys = ("id", "filename", "via", "size", "submitted_at", "sha256", "state", "security_verdict",
                "eligibility_verdict", "disposition", "error", "total_ms", "go_regions", "regions", "batch")
        return [dict(zip(keys, r), stage="done") for r in rows]

    def counts(self) -> dict[str, int]:
        with self._lock:
            return {"jobs": self._db.execute("SELECT count(*) FROM jobs").fetchone()[0],
                    "runs": self._db.execute("SELECT count(*) FROM job_runs").fetchone()[0]}

    def close(self) -> None:
        with self._lock:
            with contextlib.suppress(sqlite3.Error):
                self._db.execute("PRAGMA optimize")
            self._db.close()


class MasterNode:
    """The Master Node service (no web code here; see :mod:`master.app`)."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.bus = EventBus()
        self.started_at = time.time()
        root = cfg.data_dir
        self.dirs = {name: root / name for name in ("incoming", "quarantine", "runs", "import", "logs")}
        self.dirs["rejected_imports"] = root / "import" / "rejected"
        if cfg.master.reset_on_start:
            self._reset(root)
        for d in (root, *self.dirs.values()):
            d.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        self.history = History(root / "history.sqlite3")
        self.tainted: dict[str, str] = {}        # batch id -> malicious file name
        self.restricted: dict[str, str] = {}     # batch id -> file rejected for a security violation
        self.jobs: dict[str, Job] = {}
        self.order: collections.deque[str] = collections.deque(maxlen=500)
        self._jobs_lock = threading.Lock()
        self._security_lock = threading.Lock()
        self.counters: collections.Counter[str] = collections.Counter()
        self.pool = SandboxPool(cfg, on_event=lambda kind, data: self.bus.publish(kind, **data))
        self.pipeline = cf.ThreadPoolExecutor(cfg.pipeline.pipeline_threads, thread_name_prefix="mn-pipeline")
        method = "forkserver" if "forkserver" in multiprocessing.get_all_start_methods() else "spawn"
        self._ctx = multiprocessing.get_context(method)  # forkserver on Linux/macOS, spawn elsewhere
        self.prechecks = self._new_process_pool()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.ready = False
        self.startup_error: str | None = None
        self.pending = 0
        from master.runs import RunManager  # noqa: PLC0415 - keeps check/precheck imports light
        self.runs = RunManager(self)
        for s in reversed(self.history.recent(200)):
            job = Job(s["id"], s["filename"], s["via"], s["size"], s["submitted_at"])
            for k in ("sha256", "state", "stage", "security_verdict", "eligibility_verdict", "disposition", "error",
                      "total_ms", "batch", "go_regions"):
                setattr(job, k, s.get(k))
            job.region_count = s.get("regions") or 0
            if job.state in ACTIVE_STATES:
                job.state, job.disposition, job.error = "ERROR", "INTERRUPTED", "Master stopped during processing"
            self.jobs[job.id] = job
            self.order.append(job.id)

    # ------------------------------------------------------------------ lifecycle
    @staticmethod
    def _reset(root: Path) -> None:
        """Wipe the run history database and every run file (Raspberry Pi storage protection).

        The import folder is kept: files waiting there are user input, not run data.
        """
        if not root.exists():
            return
        for name in ("history.sqlite3", "history.sqlite3-journal", "history.sqlite3-wal", "history.sqlite3-shm"):
            with contextlib.suppress(FileNotFoundError):
                (root / name).unlink()
        for name in ("incoming", "quarantine", "runs", "logs", "cluster_queue", "smoke", "workers"):
            shutil.rmtree(root / name, ignore_errors=True)
        shutil.rmtree(root / "import" / "rejected", ignore_errors=True)
        logger.info("reset_on_start: run history database and run files cleared in %s", root)

    def _new_process_pool(self) -> cf.ProcessPoolExecutor:
        return cf.ProcessPoolExecutor(self.cfg.pipeline.precheck_processes, mp_context=self._ctx)

    def start(self, cluster: bool = True) -> None:
        """Start pools and background threads. Raises SandboxError if screening can't be provided.

        ``cluster=False`` (headless ``check``) screens and analyzes only: no scheduler, no Worker Nodes.
        """
        logger.info("Master Node %s starting (data dir %s)", __version__, self.cfg.data_dir)
        for f in [self.prechecks.submit(warm_up) for _ in range(self.cfg.pipeline.precheck_processes)]:
            f.result(timeout=60)
        self.pool.start()
        if cluster:
            self.runs.start()
        self._cluster_started = cluster
        for target, name in ((self._status_loop, "mn-status"), (self._import_loop, "mn-import-watcher")):
            if name == "mn-import-watcher" and not self.cfg.master.import_poll_seconds:
                continue
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)
        self.ready = True
        self.bus.publish("master.ready", status=self.status())
        logger.info("Master Node ready: %d sandbox(es), %d pipeline threads, %d precheck processes",
                    self.cfg.sandbox.pool_size, self.cfg.pipeline.pipeline_threads,
                    self.cfg.pipeline.precheck_processes)

    def stop(self) -> None:
        self._stop.set()
        self.ready = False
        if getattr(self, "_cluster_started", False):
            self.runs.stop()
        self.pipeline.shutdown(wait=True, cancel_futures=True)
        self.prechecks.shutdown(wait=False, cancel_futures=True)
        self.pool.close()
        self.history.close()
        logger.info("Master Node stopped; sandboxes removed")

    # ------------------------------------------------------------------ intake
    def submit(self, filename: str, data: bytes, via: str = "upload", batch: str | None = None,
               inputs: dict[str, bytes] | None = None) -> Job:
        """Accept one file (HTTP thread / import watcher). Raises ValueError for unacceptable submissions.

        ``inputs`` are the program's input files (FR-5.2); ``batch`` groups the .py files of one folder.
        """
        name = sanitize_filename(filename)
        if name is None:
            raise ValueError("only Python source files (.py) are accepted (AF-5.1.1)")
        if not data:
            raise ValueError("empty file")
        if len(data) > self.cfg.master.max_file_bytes:
            raise ValueError(f"file larger than {self.cfg.master.max_file_bytes} bytes")
        if not self.ready:
            raise RuntimeError(self.startup_error or "Master Node is not ready yet")
        if inputs and sum(len(v) for v in inputs.values()) > self.cfg.master.max_input_bytes:
            raise ValueError(f"input files larger than {self.cfg.master.max_input_bytes} bytes in total")
        job = Job(f"{datetime.now():%Y%m%d-%H%M%S}-{secrets.token_hex(3)}", name, via, len(data), _now())
        job.batch, job.inputs = batch, dict(inputs or {})
        # Working copy for inspection, isolation and tracking: owner-only, never executable.
        job.working_copy = self.dirs["incoming"] / f"{job.id}__{name}"
        fd = os.open(job.working_copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        job.state, job.stage = "QUEUED", "queued"
        self._mark(job, "received", f"working copy saved ({len(data)} bytes, mode 0600)", 0.0, 0.0,
                   f"thread {threading.current_thread().name}")
        with self._jobs_lock:
            self.jobs[job.id] = job
            self.order.append(job.id)
            self.pending += 1
            while len(self.jobs) > 500:
                self.jobs.pop(next(iter(self.jobs)), None)
        self.counters["submitted"] += 1
        self._publish_job(job)
        self.pipeline.submit(self._run_job, job, data)
        return job

    # ------------------------------------------------------------------ pipeline
    def _mark(self, job: Job, stage: str, detail: str, start: float, end: float, executor: str,
              status: str = "ok") -> None:
        job.timeline.append({"stage": stage, "detail": detail, "start_ms": round(start, 1), "end_ms": round(end, 1),
                             "ms": round(end - start, 1), "executor": executor, "status": status})

    def _elapsed(self, job: Job) -> float:
        return (time.perf_counter() - job.t0) * 1000

    def _run_job(self, job: Job, data: bytes) -> None:
        thread = threading.current_thread().name
        job.started_epoch = time.time()
        with self._jobs_lock:
            self.pending -= 1
        try:
            # Stage 1: validation in a worker process (SRS 5.1)
            job.state, job.stage = "VALIDATING", "validation"
            self._publish_job(job)
            t = self._elapsed(job)
            pre = self._precheck(job, data)
            job.sha256 = pre["sha256"]
            job.report["precheck"] = pre
            self._mark(job, "validation", pre["error"] or f"valid Python, {pre['census']['lines']} lines",
                       t, self._elapsed(job), f"process pid {pre['pid']} (precheck pool)",
                       "ok" if pre["ok"] else "fail")
            if not pre["ok"]:
                self._finish(job, "REJECTED", "REJECTED_INVALID", f"{pre['error']}"
                             + (f" (line {pre['line']})" if pre.get("line") else ""))
                self._discard(job)
                return

            # Stage 2+3: security screening, then (only if not blocked) eligibility, in a sandbox
            job.state, job.stage = "SCREENING", "security"
            self._publish_job(job)
            t = self._elapsed(job)
            result, sandbox = self._inspect(job, data.decode("utf-8"))
            sec, elig = result["security"], result.get("eligibility")
            job.lane = sandbox.get("name")
            executor = {
                "docker": f"sandbox {sandbox.get('name')} (container pid {result.get('pid')})",
                "services": f"inspector pid {result.get('pid')} → AI node → AST node",
            }.get(self.cfg.sandbox.backend, f"process pid {result.get('pid')} (no isolation)")
            # time waiting for a free sandbox, then the round trip = transport + security + eligibility
            wait_ms = sandbox.get("wait_ms") or 0.0
            if wait_ms >= 1:
                self._mark(job, "sandbox wait", f"all {self.cfg.sandbox.pool_size} sandboxes busy", t, t + wait_ms,
                           "sandbox pool queue", "warn")
            transport = max(0.0, (sandbox.get("last_ms") or 0.0) - result.get("duration_ms", 0.0))
            t = t + wait_ms
            t_sec_end = t + transport + sec["duration_ms"]
            self._mark(job, "security", "; ".join(sec["reasons"])[:300], t, t_sec_end, executor,
                       "fail" if sec["blocked"] else "warn" if sec["verdict"] == "SUSPICIOUS" else "ok")
            job.security_verdict = sec["verdict"]
            job.report["security"] = sec
            if sec["blocked"]:
                if sec.get("malicious", True):  # fail-safe: an inspector without the field means malicious
                    self._handle_malicious(job, sec)
                else:
                    self._handle_violation(job, sec, data)
                return
            job.stage = "eligibility"
            job.eligibility_verdict = elig["verdict"]
            job.report["eligibility"] = elig
            self._mark(job, "eligibility", elig["summary"][:300], t_sec_end, t_sec_end + elig["duration_ms"], executor,
                       "ok" if elig["eligible"] else "warn")

            # Stage 4: routing on the Master
            if self.batch_tainted(job):
                self._block_by_batch(job)
                return
            t = self._elapsed(job)
            run_dir = self.dirs["runs"] / job.id
            run_dir.mkdir(mode=0o700)
            program = run_dir / "program.py"
            shutil.move(str(job.working_copy), program)
            os.chmod(program, 0o600)
            job.working_copy = program
            job.report["source"] = data.decode("utf-8")
            if elig["eligible"]:
                manifest = self._package(job, run_dir, elig)
                job.report["dispatch"] = manifest
                self._mark(job, "routing", f"ready: {elig['go_regions']} GO region(s); run it in standard or "
                                           "cluster mode", t, self._elapsed(job), f"thread {thread}")
                self._finish(job, "READY", "READY_TO_RUN", None)
            else:
                self._mark(job, "routing", "not eligible for parallelization: not executed (SRS 3.2, FR-3.10)", t,
                           self._elapsed(job), f"thread {thread}", "warn")
                self._finish(job, "NOT_ELIGIBLE", "NOT_ELIGIBLE", None)
        except SandboxError as exc:
            # Fail-closed (AF-5.2.3/5.2.4): incomplete screening never reaches the cluster.
            job.report["error"] = str(exc)
            self._mark(job, job.stage, f"screening could not complete: {exc}"[:300], self._elapsed(job),
                       self._elapsed(job), f"thread {thread}", "fail")
            self._quarantine(job, "screening incomplete")
            self._finish(job, "ERROR", "SCREENING_INCOMPLETE", f"security screening could not complete: {exc}"[:400])
        except Exception as exc:
            logger.exception("job %s failed", job.id)
            job.report["error"] = f"{type(exc).__name__}: {exc}"
            if job.working_copy and job.working_copy.parent == self.dirs["incoming"]:
                self._quarantine(job, "internal error")
            self._finish(job, "ERROR", "INTERNAL_ERROR", f"{type(exc).__name__}: {exc}"[:400])

    def _precheck(self, job: Job, data: bytes) -> dict[str, Any]:
        future = self.prechecks.submit(precheck, job.id, job.filename, data)
        try:
            return future.result(timeout=self.cfg.pipeline.precheck_timeout)
        except cf.TimeoutError:
            self._restart_process_pool()
            return {"ok": False, "error": f"validation timed out after {self.cfg.pipeline.precheck_timeout}s",
                    "pid": None, "sha256": None, "line": None}
        except cf.process.BrokenProcessPool:
            self._restart_process_pool()
            return {"ok": False, "error": "validation worker crashed on this file", "pid": None, "sha256": None,
                    "line": None}

    def _restart_process_pool(self) -> None:
        old = self.prechecks
        self.prechecks = self._new_process_pool()
        for proc in list(getattr(old, "_processes", {}).values()):
            proc.kill()
        old.shutdown(wait=False, cancel_futures=True)
        self.bus.publish("precheck.pool_restarted")

    def _inspect(self, job: Job, source: str) -> tuple[dict[str, Any], dict[str, Any]]:
        options = {"output_dirs": self.cfg.security.output_dirs,
                   "block_on_suspicious": self.cfg.security.block_on_suspicious,
                   "library_allowlist": self.cfg.cluster.library_allowlist,
                   "chunk_factor": self.cfg.cluster.chunk_factor,
                   "worker_nodes": max(1, len(self.cfg.cluster.workers))}
        last: Exception | None = None
        for attempt in range(1 + self.cfg.pipeline.sandbox_retries):
            try:
                result, sandbox = self.pool.run(job.id, job.filename, source, options)
            except SandboxError as exc:  # infrastructure failure: retry on a fresh sandbox
                last = exc
                self.counters["sandbox_failures"] += 1
                self.bus.publish("sandbox.retry", job_id=job.id, attempt=attempt + 1, error=str(exc)[:300])
                continue
            if not result.get("ok"):
                raise SandboxError(result.get("error") or "inspection failed")
            return result, sandbox
        raise SandboxError(str(last))

    # ------------------------------------------------------------------ dispositions
    def _handle_malicious(self, job: Job, sec: dict[str, Any]) -> None:
        """Halt immediately: purge (or quarantine) the file, log a security event, never forward it."""
        action = self.cfg.security.malicious_action
        t = self._elapsed(job)
        if action == "quarantine":
            where = self._quarantine(job, "malicious")
            detail = f"quarantined read-only at {where}"
            disposition = "QUARANTINED"
        else:
            self._discard(job)
            detail = "working copy deleted"
            disposition = "DELETED"
        policy = sec["layers"]["policy"]
        event = {
            "ts": _now(), "event": "supply_chain_attack_blocked", "job_id": job.id, "filename": job.filename,
            "sha256": job.sha256, "via": job.via, "size": job.size, "action": disposition,
            "verdict": sec["verdict"], "reasons": sec["reasons"],
            "policy_findings": [{k: f[k] for k in ("rule", "category", "severity", "line", "snippet")}
                                for f in policy["findings"] if f["action"] == "block"][:30],
            "astmaster_verdict": sec["layers"]["ast"]["verdict"],
            "ai": {k: sec["layers"]["ai"].get(k) for k in ("risk_score", "severity", "action",
                                                           "predicted_attack_type")},
        }
        self._security_event(event)
        logger.warning("SECURITY: blocked %s (%s, sha256 %s): %s", job.filename, job.id, job.sha256,
                       "; ".join(sec["reasons"]))
        self.counters["malicious"] += 1
        self._mark(job, "disposition", f"halted: {detail}; purged from the run history database; security event "
                                       "logged", t, self._elapsed(job), f"thread {threading.current_thread().name}",
                   "fail")
        self.bus.publish("security.blocked", job_id=job.id, filename=job.filename, reasons=sec["reasons"],
                         action=disposition)
        self._finish(job, "BLOCKED", disposition, "MALICIOUS: file deleted, processing stopped (not executed)")
        self._purge(job)
        if job.batch:
            self.tainted[job.batch] = job.filename
            for other in list(self.jobs.values()):
                if other.batch == job.batch and other.id != job.id and other.state not in ACTIVE_STATES:
                    self._block_by_batch(other)

    def _handle_violation(self, job: Job, sec: dict[str, Any], data: bytes) -> None:
        """Rejected by the SRS policy (FR-2.3) without attack indicators: never executed, but kept for editing."""
        t = self._elapsed(job)
        run_dir = self.dirs["runs"] / job.id
        run_dir.mkdir(mode=0o700, exist_ok=True)
        if job.working_copy and job.working_copy.exists():
            shutil.move(str(job.working_copy), run_dir / "program.py")
            os.chmod(run_dir / "program.py", 0o600)
            job.working_copy = run_dir / "program.py"
        job.report["source"] = data.decode("utf-8")
        blocking = [f for f in sec["layers"]["policy"]["findings"] if f["action"] == "block"]
        cats = sorted({f["category"] for f in blocking})
        self._security_event({"ts": _now(), "event": "security_violation_rejected", "job_id": job.id,
                              "filename": job.filename, "sha256": job.sha256, "verdict": sec["verdict"],
                              "reasons": sec["reasons"],
                              "policy_findings": [{k: f[k] for k in ("rule", "category", "line", "snippet")}
                                                  for f in blocking][:30]})
        self.counters["violations"] += 1
        if job.batch:
            self.restricted[job.batch] = job.filename
        self._mark(job, "disposition", f"rejected: {', '.join(cats)} not allowed; kept for editing, not executed",
                   t, self._elapsed(job), f"thread {threading.current_thread().name}", "fail")
        self._finish(job, "REJECTED", "SECURITY_VIOLATION",
                     f"security violation ({', '.join(cats)}): not executed - fix the listed lines and resubmit")

    def _security_event(self, event: dict[str, Any]) -> None:
        append_capped(self.dirs["logs"] / "security_events.jsonl", json.dumps(event), self._security_lock)

    # ------------------------------------------------------------------ purge
    def batch_restricted(self, job: Job) -> str | None:
        """A file of the same folder was rejected for a security violation (it could be imported)."""
        return self.restricted.get(job.batch or "")

    def batch_tainted(self, job: Job) -> bool:
        return bool(job.batch and job.batch in self.tainted)

    def _purge(self, job: Job) -> None:
        """Remove every trace of the file's content: working copy, run folder, inputs, run history rows.

        With ``malicious_action = "quarantine"`` the read-only quarantined copy is the one thing kept.
        """
        if not (job.working_copy and self.dirs["quarantine"] in job.working_copy.parents):
            self._discard(job)
        shutil.rmtree(self.dirs["runs"] / job.id, ignore_errors=True)
        job.inputs = {}
        job.report.pop("source", None)
        job.report.pop("dispatch", None)
        self.history.delete(job.id)

    def _block_by_batch(self, job: Job) -> None:
        if job.state == "BLOCKED":
            return
        culprit = self.tainted.get(job.batch or "", "?")
        self._mark(job, "disposition", f"blocked: {culprit} in the same folder is malicious; purged",
                   self._elapsed(job), self._elapsed(job), f"thread {threading.current_thread().name}", "fail")
        self._finish(job, "BLOCKED", "BLOCKED_BY_FOLDER",
                     f"processing stopped: {culprit} in the same folder is MALICIOUS; this file was deleted too")
        self._purge(job)

    def _discard(self, job: Job) -> None:
        if job.working_copy and job.working_copy.exists():
            job.working_copy.unlink()
        job.working_copy = None

    def _quarantine(self, job: Job, why: str) -> str | None:
        if not job.working_copy or not job.working_copy.exists():
            return None
        target = self.dirs["quarantine"] / f"{job.id}__{job.filename}.quarantined"
        shutil.move(str(job.working_copy), target)
        os.chmod(target, 0o400)
        (target.with_suffix(".json")).write_text(json.dumps({"job_id": job.id, "reason": why, "sha256": job.sha256,
                                                             "at": _now()}), encoding="utf-8")
        job.working_copy = target
        return str(target.relative_to(self.cfg.data_dir))

    def _package(self, job: Job, run_dir: Path, elig: dict[str, Any]) -> dict[str, Any]:
        """Write the run package: transformed program, task templates, input files (SRS 2.1.4)."""
        tasks_dir = run_dir / "tasks"
        tasks_dir.mkdir()
        regions = []
        for r in elig["regions"]:
            entry = {k: r[k] for k in ("id", "kind", "line", "end_line", "decision", "template", "split",
                                       "split_rule", "accumulators", "constants", "planned_tasks", "thread_pattern",
                                       "task_name", "reason", "failed_check")}
            if r["decision"] == "GO" and r["task_template"]:
                path = tasks_dir / f"{r['task_name']}.py"
                path.write_text(r["task_template"], encoding="utf-8")
                entry["task_template_file"] = str(path.relative_to(run_dir))
            regions.append(entry)
        transformed = None
        if elig.get("transformed_program"):
            (run_dir / "transformed.py").write_text(elig["transformed_program"], encoding="utf-8")
            transformed = "transformed.py"
        am = elig.get("astmaster_transform") or {}
        am_file = None
        if am.get("transformed_program"):
            (run_dir / "astmaster_transformed.py").write_text(am["transformed_program"], encoding="utf-8")
            am_file = "astmaster_transformed.py"
        manifest = {
            "job_id": job.id, "created_at": _now(), "filename": job.filename, "sha256": job.sha256,
            "run_dir": str(run_dir), "program": "program.py", "security_verdict": job.security_verdict,
            "eligibility": elig["verdict"], "summary": elig["summary"], "regions": regions,
            "transformed_program": transformed, "astmaster_transformed_program": am_file,
            "cluster": {"workers": self.cfg.cluster.workers, **elig["cluster_plan"]},
            "status": "READY",
        }
        inputs_dir = run_dir / "inputs"
        for rel, content in job.inputs.items():
            target = (inputs_dir / rel).resolve()
            if inputs_dir.resolve() not in target.parents:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        manifest["inputs"] = sorted(job.inputs)
        job.inputs = {k: b"" for k in job.inputs}  # content now lives in the run folder only
        (run_dir / "dispatch.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest

    def _finish(self, job: Job, state: str, disposition: str, error: str | None) -> None:
        job.state, job.disposition, job.error, job.stage = state, disposition, error, "done"
        job.inputs = {k: b"" for k in job.inputs}  # input content lives only in the run folder
        job.total_ms = round(self._elapsed(job), 1)
        job.finished_epoch = time.time()
        self.counters[state.lower()] += 1
        report = {"job": job.summary(), "timeline": job.timeline, **job.report,
                  "config": {"ai_mode": self.cfg.security.ai_mode, "sandbox": self.cfg.sandbox.backend,
                             "malicious_action": self.cfg.security.malicious_action}}
        elig = report.get("eligibility") or {}
        job.go_regions, job.region_count = elig.get("go_regions"), len(elig.get("regions") or [])
        job.report = report
        if state != "BLOCKED":  # malicious files leave no run folder and no history row
            run_dir = self.dirs["runs"] / job.id
            run_dir.mkdir(mode=0o700, exist_ok=True)
            (run_dir / "report.json").write_text(json.dumps(report, default=str), encoding="utf-8")
            self.history.save(job)
            # The full report (source, findings, regions, templates) now lives on disk; RAM keeps the summary.
            job.report = {}
            job.timeline = list(report.get("timeline") or [])
        self._publish_job(job)
        logger.info("%s %s → %s / %s (%.0f ms)", job.id, job.filename, state, disposition, job.total_ms)

    def _publish_job(self, job: Job) -> None:
        self.bus.publish("job", job=job.summary())

    # ------------------------------------------------------------------ queries
    def get_report(self, job_id: str) -> dict[str, Any] | None:
        job = self.jobs.get(job_id)
        if job is not None and job.state not in ACTIVE_STATES and job.report.get("job"):
            return job.report  # BLOCKED jobs: kept in memory only (purged from disk)
        if job is not None and job.state in ACTIVE_STATES:
            return {"job": job.summary(), "timeline": job.timeline, **job.report}
        if not re.fullmatch(r"[\w-]{1,64}", job_id):
            return None
        path = self.dirs["runs"] / job_id / "report.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def list_jobs(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._jobs_lock:
            ids = list(self.order)[-limit:]
        return [self.jobs[i].summary() for i in reversed(ids) if i in self.jobs]

    def status(self) -> dict[str, Any]:
        procs = getattr(self.prechecks, "_processes", None) or {}
        threads = sorted(({"name": t.name, "daemon": t.daemon, "alive": t.is_alive()}
                          for t in threading.enumerate()), key=lambda t: (not t["name"].startswith("mn-"), t["name"]))
        active = [j.summary() for j in list(self.jobs.values()) if j.state in ACTIVE_STATES]
        return {
            "version": __version__, "ready": self.ready, "startup_error": self.startup_error,
            "uptime_s": round(time.time() - self.started_at, 1), "pid": os.getpid(),
            "counters": dict(self.counters), "pending": self.pending, "active_jobs": active,
            "threads": threads,
            "thread_pool": {"name": "mn-pipeline", "max_workers": self.cfg.pipeline.pipeline_threads,
                            "busy": len([j for j in active if j["state"] != "QUEUED"])},
            "process_pool": {"name": "precheck", "max_workers": self.cfg.pipeline.precheck_processes,
                             "start_method": self._ctx.get_start_method(), "pids": sorted(procs)},
            "sandbox": self.pool.status(),
            "cluster": self.runs.status(),
            "security": {"ai_mode": self.cfg.security.ai_mode, "malicious_action": self.cfg.security.malicious_action,
                         "block_on_suspicious": self.cfg.security.block_on_suspicious},
        }

    # ------------------------------------------------------------------ background threads
    def _status_loop(self) -> None:
        while not self._stop.wait(1.0):
            self.bus.publish("status", status=self.status())

    def _import_loop(self) -> None:
        """FR-1.11: a .py file dropped into the import folder follows exactly the upload flow."""
        folder = self.dirs["import"]
        while not self._stop.wait(self.cfg.master.import_poll_seconds):
            for path in sorted(folder.iterdir()):
                if not path.is_file() or path.name.startswith("."):
                    continue
                try:
                    if time.time() - path.stat().st_mtime < 0.5:
                        continue  # still being written
                    if path.is_symlink() or not path.name.lower().endswith(".py"):
                        shutil.move(str(path), self.dirs["rejected_imports"] / path.name)
                        self.bus.publish("import.rejected", filename=path.name, reason="not a .py file")
                        continue
                    data = path.read_bytes()
                    path.unlink()
                    job = self.submit(path.name, data, via="import-folder")
                    self.bus.publish("import.accepted", filename=path.name, job_id=job.id)
                except (OSError, ValueError, RuntimeError) as exc:
                    self.bus.publish("import.rejected", filename=path.name, reason=str(exc)[:200])
                    if path.exists():
                        shutil.move(str(path), self.dirs["rejected_imports"] / path.name)
