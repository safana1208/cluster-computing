"""Isolated inspection sandboxes (Docker) and the pool that runs them in parallel.

Each sandbox is one ``docker run -i`` container started from the ``scs-inspector`` image:

* ``--network none``: no network at all; the file is sent over stdin, results come back on stdout,
* ``--read-only`` root filesystem, a small ``noexec`` tmpfs, nothing from the host mounted except
  the trained models (read-only),
* ``--cap-drop ALL``, ``no-new-privileges``, non-root user, memory / CPU / PID limits,
* labelled ``scs.role=mn-inspector`` so stale containers are always cleaned up.

The submitted program is never written into the container and never executed there: the
inspector only parses it. A sandbox that times out, crashes or answers garbage is killed and
replaced; a warm sandbox is also recycled after ``max_jobs_per_sandbox`` inspections.

``mode = "warm"`` keeps ``pool_size`` sandboxes running with the models already loaded (an
inspection then takes ~0.1-0.3 s); ``mode = "ephemeral"`` starts a fresh container per file and
removes it afterwards (strongest isolation, ~1-3 s per file on a Raspberry Pi 4).

``backend = "process"`` runs the same inspector as a plain child process. It is NOT isolated and
exists only for development machines without Docker.
"""

from __future__ import annotations

import collections
import hashlib
import itertools
import json
import logging
import os
import queue
import secrets
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, Callable

from master.config import PROJECT_ROOT, Config

logger = logging.getLogger("master.sandbox")

ROLE_LABEL = "scs.role=mn-inspector"
DOCKERFILE = "master/Dockerfile"


class SandboxError(RuntimeError):
    """The sandbox could not complete an inspection (infrastructure failure, not a verdict)."""


def docker_available() -> tuple[bool, str]:
    """Whether the Docker CLI exists and the daemon answers."""
    if not shutil.which("docker"):
        return False, "docker CLI not found"
    try:
        proc = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True,
                              text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"docker not responding: {exc}"
    if proc.returncode != 0:
        return False, (proc.stderr.strip() or "docker daemon unavailable")[:300]
    return True, proc.stdout.strip()


#: Everything the Dockerfile copies into the image. Their hash is stamped on the image as a label.
IMAGE_SOURCES = ("master/Dockerfile", "ai_engine", "analyzer", "vendor/ast_master",
                 "master/__init__.py", "master/eligibility.py", "master/inspector.py")


def source_hash() -> str:
    """SHA-256 over the files baked into the sandbox image (detects a stale image after a code change)."""
    digest = hashlib.sha256()
    for rel in IMAGE_SOURCES:
        root = PROJECT_ROOT / rel
        files = [root] if root.is_file() else sorted(f for f in root.rglob("*") if f.is_file()
                                                     and "__pycache__" not in f.parts and f.suffix != ".pyc")
        for f in files:
            digest.update(str(f.relative_to(PROJECT_ROOT)).encode())
            digest.update(f.read_bytes())
    return digest.hexdigest()[:16]


def image_hash(image: str) -> str | None:
    """The source hash label of ``image``; None if the image doesn't exist, "" if it has no label."""
    proc = subprocess.run(["docker", "image", "inspect", "--format", '{{index .Config.Labels "scs.source_hash"}}',
                           image], capture_output=True, text=True, timeout=30)
    return proc.stdout.strip().replace("<no value>", "") if proc.returncode == 0 else None


def image_exists(image: str) -> bool:
    return image_hash(image) is not None


def build_image(image: str, log: Callable[[str], None] = print) -> None:
    """``docker build -f master/Dockerfile -t <image> .`` from the project root."""
    log(f"building sandbox image {image} (the Python wheels are cached after the first build)")
    proc = subprocess.run(["docker", "build", "-f", DOCKERFILE, "-t", image, "--label",
                           f"scs.source_hash={source_hash()}", "."], cwd=PROJECT_ROOT,
                          capture_output=True, text=True, timeout=3600)
    if proc.returncode != 0:
        raise SandboxError(f"docker build failed:\n{proc.stderr[-3000:]}")
    log(f"image {image} built")


def remove_stale_containers(instance: str | None = None) -> int:
    """Force-remove inspector containers: one Master instance's, or (instance=None) those whose Master is gone.

    Containers of another *running* Master on this host (e.g. a ``check`` run next to ``serve``) are kept.
    """
    try:
        if instance:
            ids = subprocess.run(["docker", "ps", "-aq", "--filter", f"label=scs.master={instance}"],
                                 capture_output=True, text=True, timeout=30).stdout.split()
        else:
            rows = subprocess.run(["docker", "ps", "-a", "--filter", f"label={ROLE_LABEL}", "--format",
                                   '{{.ID}} {{.Label "scs.master_pid"}}'], capture_output=True, text=True,
                                  timeout=30).stdout.splitlines()
            ids = [cid for cid, _, pid in (r.partition(" ") for r in rows) if not _pid_alive(pid)]
        if ids:
            subprocess.run(["docker", "rm", "-f", *ids], capture_output=True, timeout=60)
        return len(ids)
    except (OSError, subprocess.TimeoutExpired):
        return 0


def _pid_alive(pid: str) -> bool:
    try:
        os.kill(int(pid), 0)
    except (ValueError, ProcessLookupError):
        return False
    except PermissionError:
        return True
    return True


class Sandbox:
    """One inspection worker (container or process) speaking JSON lines."""

    _counter = itertools.count(1)

    def __init__(self, cfg: Config, instance: str, lane: int) -> None:
        self.cfg = cfg
        self.instance = instance
        self.lane = lane
        self.seq = next(self._counter)
        self.name = f"scs-sbx-{instance}-{lane}-{self.seq}"
        self.state = "new"
        self.jobs = 0
        self.started_at: float | None = None
        self.ready: dict[str, Any] = {}
        self.last_ms: float | None = None
        self.current_job: str | None = None
        self._proc: subprocess.Popen[str] | None = None
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._stderr: collections.deque[str] = collections.deque(maxlen=40)
        self._write_lock = threading.Lock()

    # ------------------------------------------------------------------ lifecycle
    def command(self) -> list[str]:
        sb, sec = self.cfg.sandbox, self.cfg.security
        if sb.backend == "process":
            return [sys.executable, "-m", "master.inspector", "--serve", "--ai-mode", sec.ai_mode,
                    "--artifacts", str(self.cfg.artifacts_dir)]
        if sb.backend == "services":
            return [sys.executable, "-m", "master.inspector", "--serve", "--ai-mode", sec.ai_mode,
                    "--ai-url", sb.ai_engine_url]
        return [
            "docker", "run", "-i", "--rm", "--name", self.name,
            "--label", ROLE_LABEL, "--label", f"scs.master={self.instance}", "--label", f"scs.master_pid={os.getpid()}",
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--pids-limit", str(sb.pids_limit), "--memory", sb.memory, "--memory-swap", sb.memory,
            "--cpus", str(sb.cpus), "--user", "10001:10001",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
            "-e", f"SCS_AI_MODE={sec.ai_mode}", "-e", "ARTIFACT_DIR=/artifacts", "-e", "PYTHONHASHSEED=0",
            "-v", f"{self.cfg.artifacts_dir}:/artifacts:ro",
            sb.image, "python", "-m", "master.inspector", "--serve",
        ]

    def start(self) -> None:
        self.state = "starting"
        self.started_at = time.time()
        env = {**os.environ, "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"}
        try:
            self._proc = subprocess.Popen(self.command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True, bufsize=1, cwd=PROJECT_ROOT,
                                          env=env, start_new_session=True)
        except OSError as exc:
            self.state = "dead"
            raise SandboxError(f"cannot start sandbox: {exc}") from exc
        threading.Thread(target=self._read_stdout, name=f"mn-sbx-io-{self.lane}.{self.seq}", daemon=True).start()
        threading.Thread(target=self._read_stderr, name=f"mn-sbx-err-{self.lane}.{self.seq}", daemon=True).start()
        msg = self._next_message(self.cfg.sandbox.start_timeout)
        if msg is None or msg.get("type") != "ready":
            self.kill()
            raise SandboxError(f"sandbox {self.name} did not become ready: {self.stderr_tail()}")
        self.ready = msg
        if self.cfg.security.ai_mode == "local" and not msg.get("ai", {}).get("loaded"):
            logger.warning("sandbox %s: AI models not loaded: %s", self.name, msg.get("ai", {}).get("error"))
        self.state = "idle"

    def _read_stdout(self) -> None:
        assert self._proc and self._proc.stdout
        for line in self._proc.stdout:
            self._lines.put(line)
        self._lines.put(None)  # EOF

    def _read_stderr(self) -> None:
        assert self._proc and self._proc.stderr
        for line in self._proc.stderr:
            self._stderr.append(line.rstrip())

    def stderr_tail(self, n: int = 6) -> str:
        return " | ".join(list(self._stderr)[-n:])[-800:] or "(no output)"

    def _next_message(self, timeout: float) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty:
                return None
            if line is None:
                return None
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                self._stderr.append(f"[non-JSON stdout] {line[:200]}")

    def alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None and self.state not in ("dead", "killed")

    def inspect(self, job_id: str, filename: str, source: str, options: dict[str, Any]) -> dict[str, Any]:
        """Send one file, wait for its result. Raises SandboxError on timeout/crash (the sandbox is then killed)."""
        if not self.alive():
            raise SandboxError(f"sandbox {self.name} is not running")
        self.state, self.current_job = "busy", job_id
        started = time.perf_counter()
        request = json.dumps({"op": "inspect", "id": job_id, "filename": filename, "source": source,
                              "options": options})
        try:
            with self._write_lock:
                assert self._proc and self._proc.stdin
                self._proc.stdin.write(request + "\n")
                self._proc.stdin.flush()
            deadline = time.monotonic() + self.cfg.sandbox.job_timeout
            while True:
                msg = self._next_message(max(0.0, deadline - time.monotonic()))
                if msg is None:
                    reason = "timed out" if self._proc.poll() is None else f"exited ({self._proc.returncode})"
                    self.kill()
                    raise SandboxError(f"sandbox {self.name} {reason} during inspection: {self.stderr_tail()}")
                if msg.get("type") == "result" and msg.get("id") == job_id:
                    break
        except (BrokenPipeError, OSError) as exc:
            self.kill()
            raise SandboxError(f"sandbox {self.name} pipe failure: {exc}") from exc
        finally:
            self.current_job = None
        self.jobs += 1
        self.last_ms = round((time.perf_counter() - started) * 1000, 1)
        self.state = "idle"
        return msg

    def kill(self) -> None:
        """Stop the sandbox now. Containers are force-removed by name."""
        if self.state in ("killed",):
            return
        self.state = "killed"
        proc = self._proc
        if self.cfg.sandbox.backend == "docker":
            subprocess.run(["docker", "rm", "-f", self.name], capture_output=True, timeout=30)
        if proc is not None and proc.poll() is None:
            try:
                if proc.stdin:
                    proc.stdin.close()
            except OSError:
                pass
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def status(self) -> dict[str, Any]:
        return {"name": self.name, "lane": self.lane, "state": self.state, "jobs": self.jobs,
                "current_job": self.current_job, "last_ms": self.last_ms,
                "inner_pid": self.ready.get("pid"), "client_pid": self._proc.pid if self._proc else None,
                "uptime_s": round(time.time() - self.started_at, 1) if self.started_at else None,
                "load_ms": self.ready.get("load_ms")}


class SandboxPool:
    """Runs up to ``pool_size`` inspections at once, each in its own sandbox."""

    def __init__(self, cfg: Config, on_event: Callable[[str, dict[str, Any]], None] | None = None) -> None:
        self.cfg = cfg
        self.instance = secrets.token_hex(3)
        self.on_event = on_event or (lambda *_: None)
        self.size = cfg.sandbox.pool_size
        self._idle: queue.Queue[Sandbox] = queue.Queue()
        self._lanes: dict[int, Sandbox | None] = {i: None for i in range(1, self.size + 1)}
        self._slots = threading.BoundedSemaphore(self.size)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self.started = 0
        self.replaced = 0
        self.last_error: str | None = None
        self.info: dict[str, Any] = {}
        self._supervisor: threading.Thread | None = None

    @property
    def warm(self) -> bool:
        return self.cfg.sandbox.mode == "warm"

    def start(self) -> None:
        if self.cfg.sandbox.backend == "docker":
            ok, detail = docker_available()
            if not ok:
                raise SandboxError(f"Docker is required for sandbox.backend = 'docker': {detail}")
            self.info["docker"] = detail
            removed = remove_stale_containers()
            if removed:
                logger.info("removed %d stale inspector container(s)", removed)
            current = image_hash(self.cfg.sandbox.image)
            if current != source_hash():  # missing, or built from older inspector / AST / AI code
                logger.info("sandbox image %s is %s; building", self.cfg.sandbox.image,
                            "missing" if current is None else "out of date")
                build_image(self.cfg.sandbox.image, logger.info)
            self.info["image_hash"] = source_hash()
        if self.cfg.sandbox.backend != "services" and self.cfg.security.ai_mode == "local" \
                and not self.cfg.artifacts_dir.joinpath("manifest.json").exists():
            raise SandboxError(f"no trained models in {self.cfg.artifacts_dir} (security.ai_mode = 'local')")
        if self.warm:
            threads = [threading.Thread(target=self._fill_lane, args=(lane,), daemon=True) for lane in self._lanes]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            if not any(self._lanes.values()):
                raise SandboxError(f"no sandbox could be started: {self.last_error}")
            self._supervisor = threading.Thread(target=self._supervise, name="mn-sandbox-supervisor", daemon=True)
            self._supervisor.start()
        else:
            probe = Sandbox(self.cfg, self.instance, 0)  # verify the image/models once
            probe.start()
            self.info["probe"] = probe.ready
            probe.kill()

    def _fill_lane(self, lane: int) -> None:
        sb = Sandbox(self.cfg, self.instance, lane)
        try:
            sb.start()
        except SandboxError as exc:
            self.last_error = str(exc)
            logger.error("lane %d: %s", lane, exc)
            self.on_event("sandbox.failed", {"lane": lane, "error": str(exc)[:300]})
            return
        with self._lock:
            self._lanes[lane] = sb
            self.started += 1
        self.info.setdefault("ready", sb.ready)
        self._idle.put(sb)
        self.on_event("sandbox.ready", {"lane": lane, "name": sb.name, "load_ms": sb.ready.get("load_ms")})

    def _supervise(self) -> None:
        """Replace dead or recycled sandboxes in the background."""
        while not self._stop.is_set():
            self._wake.wait(1.0)
            self._wake.clear()
            if self._stop.is_set():
                break
            for lane, sb in list(self._lanes.items()):
                if sb is None or sb.state in ("dead", "killed"):
                    with self._lock:
                        self._lanes[lane] = None
                    self.replaced += 1
                    self._fill_lane(lane)

    def run(self, job_id: str, filename: str, source: str, options: dict[str, Any],
            timeout: float | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
        """Inspect one file in a free sandbox. Returns (result message, sandbox status)."""
        wait = timeout or (self.cfg.sandbox.start_timeout + self.cfg.sandbox.job_timeout)
        queued_at = time.perf_counter()
        if not self._slots.acquire(timeout=wait):
            raise SandboxError("no sandbox became free in time")
        try:
            if self.warm:
                try:
                    sb = self._idle.get(timeout=wait)
                except queue.Empty as exc:
                    raise SandboxError(f"no healthy sandbox available ({self.last_error})") from exc
            else:
                sb = Sandbox(self.cfg, self.instance, 0)
                sb.start()
            wait_ms = round((time.perf_counter() - queued_at) * 1000, 1)
            try:
                result = sb.inspect(job_id, filename, source, options)
                return result, {**sb.status(), "wait_ms": wait_ms}
            finally:
                if not self.warm:
                    sb.kill()
                elif sb.alive() and sb.jobs < self.cfg.sandbox.max_jobs_per_sandbox:
                    self._idle.put(sb)
                else:
                    sb.kill()  # crashed, timed out or due for recycling: the supervisor replaces it
                    self._wake.set()
        finally:
            self._slots.release()

    def status(self) -> dict[str, Any]:
        with self._lock:
            lanes = [sb.status() if sb else {"lane": lane, "state": "starting"} for lane, sb in self._lanes.items()]
        busy = sum(1 for lane in lanes if lane.get("state") == "busy")
        return {"backend": self.cfg.sandbox.backend, "mode": self.cfg.sandbox.mode, "image": self.cfg.sandbox.image,
                "isolated": self.cfg.sandbox.backend in ("docker", "services"), "size": self.size, "busy": busy,
                "lanes": lanes if self.warm else [], "started": self.started, "replaced": self.replaced,
                "last_error": self.last_error, "instance": self.instance,
                "limits": {"memory": self.cfg.sandbox.memory, "cpus": self.cfg.sandbox.cpus,
                           "pids": self.cfg.sandbox.pids_limit,
                           "network": "internal (AI + AST nodes)" if self.cfg.sandbox.backend == "services" else "none",
                           "job_timeout_s": self.cfg.sandbox.job_timeout},
                "ai": (self.info.get("ready") or self.info.get("probe") or {}).get("ai"),
                "astmaster": (self.info.get("ready") or self.info.get("probe") or {}).get("astmaster")}

    def close(self) -> None:
        self._stop.set()
        self._wake.set()
        with self._lock:
            sandboxes = [sb for sb in self._lanes.values() if sb]
        for sb in sandboxes:
            sb.kill()
        while not self._idle.empty():
            try:
                self._idle.get_nowait().kill()
            except queue.Empty:
                break
        if self.cfg.sandbox.backend == "docker":
            remove_stale_containers(self.instance)
