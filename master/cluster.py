"""Task Scheduler, Execution Monitor and Worker Node registry of the Master Server (SRS 3.4, 5.4, 5.5).

* Communication (OI-05): TCP sockets with JSON lines, one persistent connection per Worker Node,
  mutual HMAC authentication with the cluster token (NFR-2.5). JSON only, never pickle (FR-3.8).
* Scheduling (FR-4.1, OI-10): one centralized queue. A Worker Node asks for work whenever one of
  its slots is idle ("pull"); the scheduler answers each pull with the next ready task, so faster
  nodes automatically receive more tasks. Retried tasks go to the front of the queue.
* Watchdog (FR-4.6, 5.4.3): heartbeats every H s from a separate worker thread; a node is Suspect
  after 2 missed heartbeats and Dead after 3. A closed connection means the worker process died.
* Failure policy (Table 5.5.1): a Dead node's running tasks and timed-out tasks are re-queued on a
  different node, up to ``retry_limit`` retries per task; then the run is aborted. A program error
  is never retried: the region is aborted and the remaining tasks are cancelled (FR-5.4).
* Early termination (FR-4.5): for first-match regions, queued tasks above the best match index are
  cancelled and late results are ignored.
* At most one result per logical task (task id + attempt id, AF-5.5.5).

Threads: one acceptor, one reader per Worker Node connection, one watchdog. Sending to a worker is
done outside the scheduler lock, so a slow socket never blocks scheduling.
"""

from __future__ import annotations

import collections
import contextlib
import hashlib
import hmac
import itertools
import json
import logging
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger("master.cluster")

LogFn = Callable[..., None]


class ProgramError(Exception):
    """An exception raised by the submitted code (deterministic, never retried)."""

    def __init__(self, error: dict[str, Any], where: str = "") -> None:
        super().__init__(f"{error.get('type')}: {error.get('message')}")
        self.error = error
        self.where = where


class RunAborted(Exception):
    """Infrastructure failure beyond the retry policy, no Worker Node available, or cancelled by the user."""


@dataclass
class Task:
    id: str
    region: "RegionExec"
    index: int
    msg: dict[str, Any] | Callable[[], dict[str, Any]] | None  # built at dispatch, dropped when done
    attempt: int = 0
    retries: int = 0
    state: str = "queued"            # queued | running | done | cancelled
    worker: str | None = None
    sent_at: float = 0.0
    exclude: set[str] = field(default_factory=set)
    result: dict[str, Any] | None = None


@dataclass
class RegionExec:
    id: str
    label: str
    timeout: float
    first_match: bool = False
    tasks: list[Task] = field(default_factory=list)
    best: int | None = None
    error: BaseException | None = None
    t_first_dispatch: float | None = None
    t_done: float | None = None
    retries: int = 0
    no_worker_since: float | None = None
    workers_used: set[str] = field(default_factory=set)

    def complete(self) -> bool:
        if self.error is not None:
            return True
        upto = self.tasks if self.best is None else self.tasks[: self.best + 1]
        return all(t.state == "done" for t in upto)


class WorkerConn:
    def __init__(self, wid: str, sock: socket.socket, host: str, hello: dict[str, Any]) -> None:
        self.id = wid
        self.sock = sock
        self.host = host
        self.name = str(hello.get("name") or wid)[:40]
        self.slots = max(1, min(int(hello.get("slots") or 1), 256))
        self.info = {k: hello.get(k) for k in ("python", "platform", "cpus", "isolation", "pid")}
        self.state = "Online"
        self.last_hb = time.monotonic()
        self.connected_at = time.time()
        self.wants = 0
        self.inflight: dict[str, Task] = {}
        self.done = 0
        self.failed = 0
        self.known: set[str] = set()
        self.wlock = threading.Lock()

    def send(self, msg: dict[str, Any]) -> None:
        data = (json.dumps(msg) + "\n").encode()
        with self.wlock:
            self.sock.sendall(data)

    def view(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "host": self.host, "slots": self.slots,
                "state": "Busy" if self.state == "Online" and self.inflight else self.state,
                "running": len(self.inflight), "done": self.done, "failed": self.failed,
                "last_heartbeat_s": round(time.monotonic() - self.last_hb, 1), **self.info}


class Scheduler:
    def __init__(self, bind: str, port: int, token: str, heartbeat: float, retry_limit: int,
                 worker_wait_timeout: float, allowed_hosts: list[str] | None = None,
                 log: LogFn | None = None) -> None:
        self.bind, self.port = bind, port
        self.token = token.encode()
        self.heartbeat = heartbeat
        self.retry_limit = retry_limit
        self.worker_wait_timeout = worker_wait_timeout
        self.allowed_hosts = set(allowed_hosts or [])
        self.log: LogFn = log or (lambda level, msg, **kw: logger.info(msg))
        self.lock = threading.Lock()
        self.cond = threading.Condition(self.lock)
        self.workers: dict[str, WorkerConn] = {}
        self.dead: collections.deque[dict[str, Any]] = collections.deque(maxlen=20)
        self.queue: collections.deque[Task] = collections.deque()
        self.tasks: dict[str, Task] = {}
        self.regions: dict[str, RegionExec] = {}
        self.allowed: set[str] | None = None       # worker ids usable by the current run (speedup sweep)
        self.excluded_names: set[str] = set()      # nodes marked Dead during the current run
        self._ids = itertools.count(1)
        self._stop = threading.Event()
        self._server: socket.socket | None = None
        self.counters: collections.Counter[str] = collections.Counter()

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bind, self.port))
        srv.listen(64)
        self.port = srv.getsockname()[1]
        self._server = srv
        threading.Thread(target=self._accept_loop, name="mn-cluster-accept", daemon=True).start()
        threading.Thread(target=self._watchdog, name="mn-cluster-watchdog", daemon=True).start()
        logger.info("cluster scheduler listening on %s:%d", self.bind, self.port)

    def stop(self) -> None:
        self._stop.set()
        if self._server:
            with contextlib.suppress(OSError):
                self._server.close()
        with self.lock:
            workers = list(self.workers.values())
        for w in workers:
            with contextlib.suppress(OSError):
                w.send({"op": "bye"})
                w.sock.close()

    # ------------------------------------------------------------------ connections
    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                sock, (host, _) = self._server.accept()  # type: ignore[union-attr]
            except OSError:
                return
            threading.Thread(target=self._connection, args=(sock, host), name=f"mn-cluster-conn-{host}",
                             daemon=True).start()

    def _host_allowed(self, host: str) -> bool:
        return not self.allowed_hosts or host in self.allowed_hosts

    def _connection(self, sock: socket.socket, host: str) -> None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        reader = sock.makefile("r", encoding="utf-8", newline="\n")
        worker: WorkerConn | None = None
        try:
            nm = secrets.token_hex(16)
            sock.settimeout(10)
            sock.sendall((json.dumps({"op": "challenge", "nonce": nm}) + "\n").encode())
            hello = json.loads(reader.readline() or "{}")
            expect = hmac.new(self.token, (nm + str(hello.get("nonce", ""))).encode(), hashlib.sha256).hexdigest()
            if hello.get("op") != "hello" or not hmac.compare_digest(expect, str(hello.get("mac", ""))):
                sock.sendall(b'{"op": "reject", "reason": "invalid cluster token"}\n')
                self.log("detailed", f"rejected a Worker Node from {host}: invalid cluster token")
                return
            if not self._host_allowed(host):
                sock.sendall(b'{"op": "reject", "reason": "host not in cluster.workers"}\n')
                self.log("detailed", f"rejected a Worker Node from {host}: not in cluster.workers")
                return
            sock.settimeout(None)
            wid = f"w{next(self._ids)}"
            worker = WorkerConn(wid, sock, host, hello)
            mac = hmac.new(self.token, (str(hello["nonce"]) + nm).encode(), hashlib.sha256).hexdigest()
            worker.send({"op": "welcome", "worker_id": wid, "heartbeat": self.heartbeat, "mac": mac})
            with self.lock:
                self.workers[wid] = worker
            self.log("basic", f"Worker Node {worker.name} ({host}, {worker.slots} slot(s)) is Online", event="worker")
            for line in reader:
                msg = json.loads(line)
                op = msg.get("op")
                if op == "hb":
                    worker.last_hb = time.monotonic()
                    if worker.state == "Suspect":
                        worker.state = "Online"
                        self.log("detailed", f"{worker.name}: heartbeats resumed", event="worker")
                    self.log("debug", f"heartbeat {worker.name} busy={msg.get('busy')}")
                elif op == "pull":
                    worker.last_hb = time.monotonic()
                    with self.lock:
                        worker.wants = min(worker.slots, worker.wants + int(msg.get("n", 1)))
                    self.log("debug", f"pull {worker.name} (+{msg.get('n', 1)})")
                    self.dispatch()
                elif op == "result":
                    worker.last_hb = time.monotonic()
                    self._on_result(worker, msg)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            if worker is None:
                logger.debug("handshake with %s failed: %s", host, exc)
        finally:
            if worker is not None:
                self._mark_dead(worker, "connection closed (Worker process stopped or crashed)")
            with contextlib.suppress(OSError):
                sock.close()

    # ------------------------------------------------------------------ worker selection
    def _usable(self, w: WorkerConn) -> bool:
        return (w.state == "Online" and (self.allowed is None or w.id in self.allowed)
                and w.name not in self.excluded_names)

    def online(self) -> list[WorkerConn]:
        with self.lock:
            return sorted((w for w in self.workers.values() if w.state in ("Online", "Suspect")),
                          key=lambda w: int(w.id[1:]))

    def use_workers(self, count: int | None) -> list[WorkerConn]:
        """Restrict the next run to the first ``count`` online workers (None = all)."""
        workers = self.online()
        chosen = workers if count is None else workers[:count]
        with self.lock:
            self.allowed = {w.id for w in chosen}
            self.excluded_names = set()
        return chosen

    def active_slots(self) -> int:
        with self.lock:
            return sum(w.slots for w in self.workers.values() if self._usable(w))

    def wait_for_workers(self, count: int, timeout: float) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            n = len(self.online())
            if n >= count:
                return n
            time.sleep(0.1)
        return len(self.online())

    # ------------------------------------------------------------------ scheduling
    def dispatch(self) -> None:
        sends: list[tuple[WorkerConn, Task, dict[str, Any]]] = []
        with self.lock:
            if not self.queue:
                return
            candidates = [w for w in self.workers.values() if w.wants > 0 and self._usable(w)]
            if not candidates:
                return
            remaining: collections.deque[Task] = collections.deque()
            while self.queue:
                task = self.queue.popleft()
                if task.state != "queued":
                    continue
                pool = [w for w in candidates if w.wants > 0]
                if not pool:
                    remaining.append(task)
                    remaining.extend(self.queue)
                    self.queue.clear()
                    break
                choices = [w for w in pool if w.id not in task.exclude] or (
                    pool if not any(self._usable(w) and w.id not in task.exclude
                                    for w in self.workers.values()) else [])
                if not choices:
                    remaining.append(task)
                    continue
                w = max(choices, key=lambda x: (x.wants, -len(x.inflight)))
                w.wants -= 1
                task.state, task.worker, task.sent_at = "running", w.id, time.monotonic()
                w.inflight[task.id] = task
                region = task.region
                region.workers_used.add(w.name)
                if region.t_first_dispatch is None:
                    region.t_first_dispatch = time.perf_counter()
                base = task.msg() if callable(task.msg) else task.msg  # the chunk is sliced only now
                msg = {**base, "op": "task", "task": task.id, "attempt": task.attempt, "timeout": region.timeout}
                tid = msg.get("tid")
                if tid and tid in w.known:
                    msg.pop("src", None)
                elif tid:
                    w.known.add(tid)
                sends.append((w, task, msg))
            self.queue = remaining
        for w, task, msg in sends:
            try:
                w.send(msg)
                self.log("debug", f"dispatch {task.region.label} task {task.index} (attempt {task.attempt}) "
                                  f"→ {w.name}")
            except OSError:
                self._mark_dead(w, "send failed")

    def _on_result(self, worker: WorkerConn, msg: dict[str, Any]) -> None:
        retry_args = None
        abort = None
        with self.cond:
            task = self.tasks.get(str(msg.get("task")))
            worker.inflight.pop(str(msg.get("task")), None)
            if task is None or task.state != "running" or msg.get("attempt") != task.attempt or task.worker != worker.id:
                self.counters["ignored_results"] += 1
                self.log("debug", f"ignored a duplicate/late result for task {msg.get('task')} from {worker.name}")
                return
            region = task.region
            if msg.get("ok"):
                task.state, task.result = "done", msg
                task.msg = None  # free the task's input data as soon as its result is accepted
                worker.done += 1
                value = msg.get("value")
                if region.first_match and isinstance(value, dict) and value.get("__match__") is not None:
                    if region.best is None or task.index < region.best:
                        region.best = task.index
                        cancelled = [t for t in region.tasks if t.index > task.index and t.state == "queued"]
                        for t in cancelled:
                            t.state = "cancelled"
                        self.log("detailed", f"{region.label}: match in task {task.index}; "
                                             f"{len(cancelled)} queued task(s) above it cancelled (FR-4.5)")
                self.log("detailed", f"{region.label}: task {task.index} done on {worker.name} "
                                     f"({msg.get('ms', 0):.0f} ms)", event="task")
            elif msg.get("timeout") or msg.get("infra"):
                worker.failed += 1
                retry_args = (task, f"{msg.get('error', {}).get('message', 'infrastructure failure')} on {worker.name}",
                              worker.id)
            else:
                worker.failed += 1
                abort = ProgramError(msg.get("error") or {}, f"{region.label}, task {task.index}")
                task.state, task.result = "done", msg
            self.cond.notify_all()
        if retry_args:
            self._retry(*retry_args)
        if abort:
            self.abort_region(task.region, abort)

    def _retry(self, task: Task, reason: str, exclude: str | None = None) -> None:
        with self.cond:
            region = task.region
            if task.state not in ("running", "queued") or region.error is not None:
                return
            if task.worker and task.worker in self.workers:
                self.workers[task.worker].inflight.pop(task.id, None)
            task.retries += 1
            region.retries += 1
            self.counters["retries"] += 1
            if exclude:
                task.exclude.add(exclude)
            if task.retries > self.retry_limit:
                err = RunAborted(f"{region.label}: task {task.index} failed {task.retries} times "
                                 f"(retry limit {self.retry_limit}): {reason}")
            else:
                err = None
                task.state, task.worker = "queued", None
                task.attempt += 1
                self.queue.appendleft(task)
                self.log("detailed", f"{region.label}: task {task.index} re-queued (retry {task.retries}/"
                                     f"{self.retry_limit}): {reason}", event="retry")
            self.cond.notify_all()
        if err:
            self.abort_region(region, err)
        else:
            self.dispatch()

    def _mark_dead(self, worker: WorkerConn, why: str) -> None:
        with self.cond:
            if worker.state == "Dead":
                return
            worker.state = "Dead"
            self.workers.pop(worker.id, None)
            if self.allowed is not None and worker.id in self.allowed:
                self.excluded_names.add(worker.name)
            self.dead.append({**worker.view(), "state": "Dead", "reason": why, "at": time.time()})
            lost = list(worker.inflight.values())
            worker.inflight.clear()
            self.cond.notify_all()
        self.log("basic", f"Worker Node {worker.name} is Dead: {why}"
                          + (f"; {len(lost)} running task(s) returned to the queue" if lost else ""), event="worker")
        with contextlib.suppress(OSError):
            worker.sock.close()
        for task in lost:
            self._retry(task, f"node {worker.name} Dead")

    def _watchdog(self) -> None:
        while not self._stop.wait(0.25):
            now = time.monotonic()
            with self.lock:
                workers = list(self.workers.values())
                running = [t for t in self.tasks.values() if t.state == "running"]
                waiting = [r for r in self.regions.values() if r.error is None and any(
                    t.state == "queued" for t in r.tasks)]
            for w in workers:
                missed = (now - w.last_hb) / self.heartbeat
                if missed >= 3:
                    self._mark_dead(w, "3 missed heartbeats")
                elif missed >= 2 and w.state == "Online":
                    w.state = "Suspect"
                    self.log("detailed", f"Worker Node {w.name} is Suspect (2 missed heartbeats)", event="worker")
            for t in running:
                if now - t.sent_at > t.region.timeout and t.state == "running":
                    w = self.workers.get(t.worker or "")
                    if w is not None:
                        with contextlib.suppress(OSError):
                            w.send({"op": "cancel", "task": t.id})
                    self._retry(t, f"timeout after {t.region.timeout:.1f}s on {w.name if w else t.worker}",
                                t.worker)
            for r in waiting:
                if self.active_slots() == 0:
                    r.no_worker_since = r.no_worker_since or now
                    if now - r.no_worker_since > self.worker_wait_timeout:
                        self.abort_region(r, RunAborted(f"{r.label}: no Worker Node available for "
                                                        f"{self.worker_wait_timeout:.0f}s (AF-5.4.1)"))
                else:
                    r.no_worker_since = None
            self.dispatch()

    def abort_region(self, region: RegionExec, error: BaseException) -> None:
        cancels: list[tuple[WorkerConn, str]] = []
        with self.cond:
            if region.error is not None:
                return
            region.error = error
            for t in region.tasks:
                if t.state == "running" and t.worker in self.workers:
                    cancels.append((self.workers[t.worker], t.id))
                    self.workers[t.worker].inflight.pop(t.id, None)
                if t.state in ("queued", "running"):
                    t.state = "cancelled"
            self.cond.notify_all()
        for w, tid in cancels:
            with contextlib.suppress(OSError):
                w.send({"op": "cancel", "task": tid})  # the worker kills that task process and pulls again

    def cancel_all(self, reason: str) -> None:
        with self.lock:
            regions = [r for r in self.regions.values() if r.error is None]
        for r in regions:
            self.abort_region(r, RunAborted(reason))

    # ------------------------------------------------------------------ public: run tasks
    def run_tasks(self, label: str, msgs: list[dict[str, Any] | Callable[[], dict[str, Any]]], timeout: float,
                  first_match: bool = False,
                  cancelled: threading.Event | None = None) -> tuple[list[dict[str, Any] | None], RegionExec]:
        """Queue one region's tasks, wait for completion, return the accepted results in task order.

        Raises ProgramError (program error, no retry) or RunAborted (retry limit, no workers, cancel).
        For first-match regions, results above the match are None.
        """
        rid = f"r{next(self._ids)}"
        region = RegionExec(rid, label, timeout, first_match)
        for i, msg in enumerate(msgs):
            region.tasks.append(Task(f"{rid}.{i}", region, i, msg))
        with self.cond:
            self.regions[rid] = region
            for t in region.tasks:
                self.tasks[t.id] = t
                self.queue.append(t)
        self.log("detailed", f"{label}: {len(msgs)} task(s) queued (timeout {timeout:.1f}s each)", event="region")
        self.dispatch()
        try:
            with self.cond:
                while not region.complete():
                    if cancelled is not None and cancelled.is_set():
                        break
                    self.cond.wait(0.2)
            if cancelled is not None and cancelled.is_set() and region.error is None:
                self.abort_region(region, RunAborted("cancelled by the user"))
            if region.error is not None:
                raise region.error
            region.t_done = time.perf_counter()
            upto = len(region.tasks) if region.best is None else region.best + 1
            return [t.result if i < upto else None for i, t in enumerate(region.tasks)], region
        finally:
            with self.cond:
                self.regions.pop(rid, None)
                for t in region.tasks:
                    self.tasks.pop(t.id, None)
                    t.msg = None
                    if t.state == "queued":
                        t.state = "cancelled"
                self.queue = collections.deque(t for t in self.queue if t.region is not region)

    # ------------------------------------------------------------------ status
    def status(self) -> dict[str, Any]:
        with self.lock:
            workers = sorted((w.view() for w in self.workers.values()), key=lambda w: int(w["id"][1:]))
            return {"listen": f"{self.bind}:{self.port}", "workers": workers, "dead": list(self.dead)[-5:],
                    "queue": sum(1 for t in self.queue if t.state == "queued"),
                    "running": sum(1 for t in self.tasks.values() if t.state == "running"),
                    "allowed": sorted(self.allowed) if self.allowed is not None else None,
                    "counters": dict(self.counters)}
