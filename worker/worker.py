"""Worker Node agent of the Cluster Computing system (SRS FR-4.1, FR-4.3, FR-4.6, NFR-2.3, NFR-2.5).

One file, standard library only: copy it to a Raspberry Pi and run

    python3 worker.py --master 192.168.1.10:7070 --token <cluster token> --slots 4

* Pull model (FR-4.1): the agent asks the Master Server for a task whenever one of its slots is idle.
* Each task runs as a direct function call in a separate restricted process (FR-4.3): a warm
  "runner" child per slot, started with no network (Linux user + network namespace, as user
  ``nobody``), a memory limit, no core files, a file-size limit, the worker's output folder as
  working directory, and the task timeout. Runners are reused between tasks (compiled templates
  are cached), so a task costs a pipe round trip, not a Python start-up.
* Heartbeats are sent every H seconds from a separate thread (FR-4.6); the heartbeat thread and
  the slot threads never run submitted code.
* The agent only connects to the configured Master address and only accepts tasks after mutual
  HMAC authentication with the shared cluster token (NFR-2.5); the token is never sent.
* Task data is JSON only; pickle is never used (FR-3.8).

The same file is the runner (``--runner``), so a node needs nothing but this file and Python 3.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import hmac
import io
import json
import os
import platform
import queue
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

PROTOCOL = 1

# JSON has no tuple: tuples are tagged on the wire so they come back as tuples (SRS 2.5 lists tuple as task data).
_TAG = "__cc_tuple__"
_PLAIN = (str, int, float, bool, type(None))


def _enc(v):
    t = type(v)
    if t in _PLAIN:
        return v
    if isinstance(v, tuple):
        return {_TAG: [x if type(x) in _PLAIN else _enc(x) for x in v]}
    if isinstance(v, list):
        return [x if type(x) in _PLAIN else _enc(x) for x in v]
    if isinstance(v, dict):
        return {k: (x if type(x) in _PLAIN else _enc(x)) for k, x in v.items()}
    return v


def _dec(v):
    if isinstance(v, list):
        return [x if type(x) in _PLAIN else _dec(x) for x in v]
    if isinstance(v, dict):
        if len(v) == 1 and _TAG in v:
            return tuple(_dec(v[_TAG]))
        return {k: (x if type(x) in _PLAIN else _dec(x)) for k, x in v.items()}
    return v


# ====================================================================== runner (restricted child process)
#: The memory limit is enforced on real memory (RSS) by the parent, see rss_mb(). RLIMIT_AS (virtual memory)
#: is only a backstop: every thread reserves an 8 MB stack and glibc a malloc arena, so a program with 200
#: threads reserves gigabytes of address space while using little memory.
AS_BACKSTOP_FACTOR = 8


def rss_mb(pid: int) -> float | None:
    """Resident memory of a process in MB (Linux /proc), None where not available."""
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _limit_resources(memory_mb: int) -> None:
    try:
        import resource
    except ImportError:  # not Linux/Unix
        return
    for name, value in (("RLIMIT_AS", memory_mb * AS_BACKSTOP_FACTOR * 1024 * 1024), ("RLIMIT_CORE", 0),
                        ("RLIMIT_FSIZE", 64 * 1024 * 1024)):
        lim = getattr(resource, name, None)
        if lim is None or value <= 0:
            continue
        try:
            resource.setrlimit(lim, (value, value))
        except (ValueError, OSError):
            pass


def _error_info(exc: BaseException, source: str | None, filename: str) -> dict:
    line = None
    for frame in traceback.extract_tb(exc.__traceback__):
        if frame.filename == filename:
            line = frame.lineno
    if isinstance(exc, SyntaxError) and exc.filename == filename:
        line = exc.lineno
    text = None
    if line and source:
        lines = source.splitlines()
        if 0 < line <= len(lines):
            text = lines[line - 1].strip()
    return {"type": type(exc).__name__, "message": str(exc)[:500], "line": line, "text": text,
            "trace": traceback.format_exc()[-1500:]}


class _Marker:
    """Timing markers placed around the parallel regions of the reference run (FR-5.5)."""

    def __init__(self) -> None:
        self.starts: dict[str, float] = {}
        self.totals: dict[str, float] = {}

    def __call__(self, rid: str, phase: int) -> None:
        now = time.perf_counter()
        if phase == 0:
            self.starts[rid] = now
        elif rid in self.starts:
            self.totals[rid] = self.totals.get(rid, 0.0) + (now - self.starts.pop(rid))


def instrument(source: str, marks: list, filename: str = "<program>"):
    """Compile ``source`` with ``__cc_mark__(rid, 0/1)`` around each region; original line numbers are kept."""
    tree = ast.parse(source, filename)

    def bodies(node):
        for _, value in ast.iter_fields(node):
            if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
                yield value
        for child in ast.iter_child_nodes(node):
            yield from bodies(child)

    all_bodies = [tree.body, *bodies(tree)]
    for rid, line, end in marks:
        best = None
        for body in all_bodies:
            hit = [i for i, s in enumerate(body) if s.lineno <= end and (s.end_lineno or s.lineno) >= line]
            if not hit:
                continue
            lo, hi = hit[0], hit[-1]
            if body[lo].lineno <= line and (body[hi].end_lineno or body[hi].lineno) >= end:
                best = (body, lo, hi)  # deeper bodies come later: the last match is the innermost
        if best is None:
            continue
        body, lo, hi = best

        def mark(phase: int, ref: ast.stmt) -> ast.stmt:
            node = ast.Expr(ast.Call(ast.Name("__cc_mark__", ast.Load()),
                                     [ast.Constant(rid), ast.Constant(phase)], []))
            return ast.copy_location(node, ref)

        body.insert(hi + 1, mark(1, body[hi]))
        body.insert(lo, mark(0, body[lo]))
    ast.fix_missing_locations(tree)
    return compile(tree, filename, "exec")


def _run_template(msg: dict, cache: dict) -> dict:
    tid = msg["tid"]
    if msg.get("src") is not None:
        cache[tid] = (compile(msg["src"], "<task>", "exec"), msg["src"])
    if tid not in cache:
        return {"ok": False, "error": {"type": "MissingTemplate", "message": f"template {tid} unknown",
                                       "line": None, "text": None}, "infra": True}
    code, src = cache[tid]
    out = io.StringIO()
    started = time.perf_counter()
    try:
        ns = {"__name__": "__cc_task__"}
        with contextlib.redirect_stdout(out):
            exec(code, ns)  # noqa: S102 - screened task template, restricted process
            fn = ns[msg["entry"]]
            payload, consts = _dec(msg["payload"]), _dec(msg.get("consts"))
            if msg.get("call") == "args":
                value = fn(payload.get("args") or [], payload.get("kwargs") or {}, consts)
            else:
                value = fn(payload, consts)
        value = _enc(value)
        json.dumps(value)  # results must be JSON-serializable (R9)
    except BaseException as exc:  # noqa: BLE001 - every program error is reported, never retried
        if isinstance(exc, (KeyboardInterrupt,)):
            raise
        return {"ok": False, "error": _error_info(exc, src, "<task>"), "stdout": out.getvalue(),
                "ms": round((time.perf_counter() - started) * 1000, 3)}
    return {"ok": True, "value": value, "stdout": out.getvalue(), "ms": round((time.perf_counter() - started) * 1000, 3)}


def _run_program(msg: dict) -> dict:
    """Reference run (FR-5.2): the original program with its input files, timing markers around the regions."""
    src = msg["src"]
    work = tempfile.mkdtemp(prefix="ref-", dir=os.getcwd())
    old_cwd, old_path = os.getcwd(), list(sys.path)
    out = io.StringIO()
    marker = _Marker()
    started = time.perf_counter()
    try:
        for name, spec in (msg.get("files") or {}).items():
            target = os.path.normpath(os.path.join(work, name))
            if not target.startswith(work + os.sep):
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if "b64" in spec:
                import base64
                with open(target, "wb") as fh:
                    fh.write(base64.b64decode(spec["b64"]))
            else:
                with open(target, "w", encoding="utf-8") as fh:
                    fh.write(spec.get("text", ""))
        os.makedirs(os.path.join(work, "output"), exist_ok=True)
        os.chdir(work)
        sys.path.insert(0, work)
        code = instrument(src, msg.get("marks") or [], "<program>")
        ns = {"__name__": "__main__", "__cc_mark__": marker, "__builtins__": __builtins__}
        with contextlib.redirect_stdout(out):
            try:
                exec(code, ns)  # noqa: S102 - screened program, restricted process
            except SystemExit as exc:
                if exc.code not in (None, 0):
                    raise RuntimeError(f"program exited with status {exc.code}") from None
        ok, err = True, None
    except BaseException as exc:  # noqa: BLE001
        ok, err = False, _error_info(exc, src, "<program>")
    finally:
        os.chdir(old_cwd)
        sys.path[:] = old_path
        shutil.rmtree(work, ignore_errors=True)
    result = {"ok": ok, "stdout": out.getvalue(), "ms": round((time.perf_counter() - started) * 1000, 3),
              "value": {"marks": {k: round(v * 1000, 3) for k, v in marker.totals.items()}}}
    if err:
        result["error"] = err
    return result


def _write_files(work: str, files: dict) -> None:
    for name, spec in (files or {}).items():
        target = os.path.normpath(os.path.join(work, name))
        if not target.startswith(work + os.sep):
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if "b64" in spec:
            import base64
            with open(target, "wb") as fh:
                fh.write(base64.b64decode(spec["b64"]))
        else:
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(spec.get("text", ""))


def _run_tests(msg: dict) -> dict:
    """Run named unittest methods of a test module (test-suite extension).

    The module is loaded under its own name, not as __main__, so ``unittest.main()`` does not run; every
    listed test runs in a fresh TestCase instance. Modules imported from the task folder are dropped
    afterwards, so the next task of this (reused) process imports them fresh.
    """
    import types
    import unittest

    src, filename = msg["src"], msg.get("filename") or "test_module.py"
    work = tempfile.mkdtemp(prefix="tests-", dir=os.getcwd())
    old_cwd, old_path, before = os.getcwd(), list(sys.path), set(sys.modules)
    out = io.StringIO()
    results, started = [], time.perf_counter()
    try:
        _write_files(work, msg.get("files"))
        os.makedirs(os.path.join(work, "output"), exist_ok=True)
        os.chdir(work)
        sys.path.insert(0, work)
        module = types.ModuleType(os.path.splitext(os.path.basename(filename))[0])
        module.__file__ = os.path.join(work, os.path.basename(filename))
        with contextlib.redirect_stdout(out):
            try:
                exec(compile(src, "<program>", "exec"), module.__dict__)  # noqa: S102 - screened module
            except BaseException as exc:  # noqa: BLE001 - e.g. a missing local module
                return {"ok": False, "error": _error_info(exc, src, "<program>"), "stdout": out.getvalue(),
                        "ms": round((time.perf_counter() - started) * 1000, 3)}
            loader = unittest.TestLoader()
            for name in msg["names"]:
                t0 = time.perf_counter()
                result = unittest.TestResult()
                try:
                    loader.loadTestsFromName(name, module).run(result)
                except Exception as exc:  # noqa: BLE001 - a test that can't even be loaded
                    result.errors.append((name, f"{type(exc).__name__}: {exc}"))
                bad = result.failures or result.errors
                status = ("FAIL" if result.failures else "ERROR") if bad else "skipped" if result.skipped else "ok"
                detail = bad[0][1].strip().splitlines()[-1][:300] if bad else ""
                results.append([name, status, detail, round((time.perf_counter() - t0) * 1000, 3)])
    finally:
        os.chdir(old_cwd)
        sys.path[:] = old_path
        for mod in set(sys.modules) - before:
            if (getattr(sys.modules.get(mod), "__file__", None) or "").startswith(work):
                sys.modules.pop(mod, None)
        shutil.rmtree(work, ignore_errors=True)
    return {"ok": True, "value": {"tests": results}, "stdout": out.getvalue(),
            "ms": round((time.perf_counter() - started) * 1000, 3)}


def runner_main(memory_mb: int) -> int:
    """JSON lines on stdin -> JSON lines on the original stdout. Submitted code can't write to that stream."""
    _limit_resources(memory_mb)
    proto = os.fdopen(os.dup(1), "w", encoding="utf-8", buffering=1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    sys.setrecursionlimit(5000)
    cache: dict = {}
    proto.write(json.dumps({"ready": True, "pid": os.getpid(), "uid": os.getuid() if hasattr(os, "getuid") else None})
                + "\n")
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
            kind = msg.get("kind")
            result = (_run_program(msg) if kind == "program" else _run_tests(msg) if kind == "tests"
                      else _run_template(msg, cache))
        except MemoryError:
            result = {"ok": False, "error": {"type": "MemoryError", "message": "task exceeded the memory limit",
                                             "line": None, "text": None}}
        except Exception as exc:  # noqa: BLE001 - protocol problem
            result = {"ok": False, "infra": True, "error": {"type": type(exc).__name__, "message": str(exc)[:300],
                                                            "line": None, "text": None}}
        try:
            text = json.dumps(result)
        except (TypeError, ValueError) as exc:
            text = json.dumps({"ok": False, "error": {"type": "SerializationError",
                                                      "message": f"result is not JSON-serializable: {exc}",
                                                      "line": None, "text": None}})
        proto.write(text + "\n")
    return 0


# ====================================================================== runner handle (used by the agent and the Master)
_ISOLATION: list | None = None


def isolation_prefix(mode: str = "auto") -> list:
    """Command prefix that removes network access and admin rights (Linux namespaces), if available."""
    global _ISOLATION
    if mode == "none":
        return []
    if _ISOLATION is None:
        _ISOLATION = []
        if shutil.which("unshare"):
            try:
                ok = subprocess.run(["unshare", "-Un", "true"], capture_output=True, timeout=10).returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                ok = False
            if ok:
                _ISOLATION = ["unshare", "-Un"]  # new user + network namespace: uid nobody, no network
    if mode == "unshare" and not _ISOLATION:
        raise RuntimeError("isolation = 'unshare' but 'unshare -Un' is not available on this machine")
    return list(_ISOLATION)


class Runner:
    """A warm restricted child process that executes tasks one at a time."""

    def __init__(self, workdir: str, memory_mb: int = 512, isolation: str = "auto") -> None:
        self.workdir = workdir
        self.memory_mb = memory_mb
        self.isolation = isolation
        self.proc: subprocess.Popen | None = None
        self.known: set[str] = set()
        self.lock = threading.Lock()

    def start(self) -> None:
        os.makedirs(self.workdir, exist_ok=True)
        cmd = [*isolation_prefix(self.isolation), sys.executable, "-I", os.path.abspath(__file__),
               "--runner", "--memory-mb", str(self.memory_mb)]
        env = {"PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1", "MALLOC_ARENA_MAX": "2", "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "LANG": "C.UTF-8"}
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     cwd=self.workdir, env=env, text=True, bufsize=1, start_new_session=True)
        self.known = set()
        hello = self.proc.stdout.readline()
        if not hello:
            raise RuntimeError("runner process failed to start")

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def kill(self) -> None:
        proc, self.proc = self.proc, None
        if proc and proc.poll() is None:
            try:
                os.killpg(proc.pid, 9)
            except (OSError, AttributeError):
                proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def run(self, msg: dict, timeout: float) -> dict:
        """Execute one task. Returns the runner's result; ``{"timeout": True}`` if it was killed for overtime."""
        with self.lock:
            if not self.alive():
                self.start()
            if msg.get("kind") not in ("program", "tests"):
                if msg["tid"] in self.known:
                    msg = {**msg, "src": None}
                elif msg.get("src") is None:
                    return {"ok": False, "infra": True, "error": {"type": "MissingTemplate",
                                                                   "message": "template source missing"}}
            proc = self.proc
            timer = threading.Timer(timeout, self.kill)
            timer.daemon = True
            timer.start()
            done, over = threading.Event(), []

            def watch_memory() -> None:  # the memory limit, on real memory (RSS)
                while not done.wait(0.1):
                    used = rss_mb(proc.pid)
                    if used is not None and used > self.memory_mb:
                        over.append(used)
                        self.kill()
                        return

            threading.Thread(target=watch_memory, daemon=True).start()
            try:
                proc.stdin.write(json.dumps(msg) + "\n")
                proc.stdin.flush()
                line = proc.stdout.readline()
            except (BrokenPipeError, OSError, ValueError):
                line = ""
            finally:
                done.set()
                timer.cancel()
            if not line and over:
                self.kill()
                return {"ok": False, "error": {"type": "MemoryError", "line": None, "text": None,
                                               "message": f"task used {over[0]:.0f} MB, more than the "
                                                          f"{self.memory_mb} MB memory limit"}}
            if not line:
                timed_out = self.proc is None  # the timer killed it
                self.kill()
                if timed_out:
                    return {"ok": False, "timeout": True,
                            "error": {"type": "Timeout", "message": f"task exceeded its timeout ({timeout:.1f}s)"}}
                return {"ok": False, "infra": True, "error": {"type": "RunnerCrashed",
                                                              "message": "task process died (memory limit or crash)"}}
            if msg.get("kind") not in ("program", "tests"):
                self.known.add(msg["tid"])
            return json.loads(line)


# ====================================================================== worker agent
class Agent:
    def __init__(self, master: str, token: str, name: str, slots: int, workdir: str, memory_mb: int,
                 isolation: str, parent_pid: int = 0) -> None:
        self.parent_pid = parent_pid
        host, _, port = master.rpartition(":")
        self.addr = (host, int(port))
        self.token = token.encode()
        self.name = name
        self.slots = slots
        self.workdir = workdir
        self.memory_mb = memory_mb
        self.isolation = isolation
        self.sock: socket.socket | None = None
        self.wlock = threading.Lock()
        self.heartbeat = 2.0
        self.stop = threading.Event()
        self.busy = 0
        self.current: dict[int, str | None] = {}
        self.runners = [Runner(os.path.join(workdir, f"slot{i}"), memory_mb, isolation) for i in range(slots)]
        self.inbox: list[queue.Queue] = [queue.Queue() for _ in range(slots)]
        self.free: queue.Queue[int] = queue.Queue()
        self.templates: dict[str, str] = {}

    def send(self, msg: dict) -> None:
        data = (json.dumps(msg) + "\n").encode()
        with self.wlock:
            if self.sock is None:
                raise OSError("not connected")
            self.sock.sendall(data)

    def _handshake(self, reader) -> None:
        challenge = json.loads(reader.readline() or "{}")
        if challenge.get("op") != "challenge":
            raise OSError("unexpected greeting from the Master")
        nw = secrets.token_hex(16)
        mac = hmac.new(self.token, (challenge["nonce"] + nw).encode(), hashlib.sha256).hexdigest()
        self.send({"op": "hello", "protocol": PROTOCOL, "name": self.name, "slots": self.slots, "nonce": nw,
                   "mac": mac, "pid": os.getpid(), "python": platform.python_version(),
                   "platform": f"{platform.system()} {platform.machine()}", "cpus": os.cpu_count(),
                   "isolation": "namespaces" if isolation_prefix(self.isolation) else "rlimits only"})
        reply = json.loads(reader.readline() or "{}")
        if reply.get("op") != "welcome":
            raise PermissionError(reply.get("reason") or "rejected by the Master")
        expect = hmac.new(self.token, (nw + challenge["nonce"]).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, reply.get("mac", "")):
            raise PermissionError("the Master did not prove the cluster token (NFR-2.5)")
        self.heartbeat = float(reply.get("heartbeat", 2.0))

    def _orphaned(self) -> bool:
        """A local Worker Node started by the Master exits when the Master process is gone."""
        if not self.parent_pid:
            return False
        try:
            os.kill(self.parent_pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        return False

    def _heartbeats(self, conn_stop: threading.Event) -> None:
        while not conn_stop.wait(self.heartbeat):
            try:
                self.send({"op": "hb", "busy": self.busy})
            except OSError:
                return

    def _slot(self, i: int) -> None:
        while not self.stop.is_set():
            msg = self.inbox[i].get()
            if msg is None:
                return
            self.current[i] = msg["task"]
            self.busy += 1
            try:
                result = self.runners[i].run(msg, float(msg.get("timeout", 60)))
            except Exception as exc:  # noqa: BLE001 - infrastructure problem on this node
                result = {"ok": False, "infra": True, "error": {"type": type(exc).__name__, "message": str(exc)[:300]}}
            self.busy -= 1
            cancelled = self.current.get(i) is None
            self.current[i] = None
            try:
                if not cancelled:
                    self.send({"op": "result", "task": msg["task"], "attempt": msg["attempt"], **result})
                self.free.put(i)
                self.send({"op": "pull", "n": 1})
            except OSError:
                self.free.put(i)

    def _cancel(self, task: str) -> None:
        for i, current in list(self.current.items()):
            if current == task:
                self.current[i] = None
                self.runners[i].kill()

    def serve_once(self) -> None:
        sock = socket.create_connection(self.addr, timeout=10)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(None)
        with self.wlock:
            self.sock = sock
        reader = sock.makefile("r", encoding="utf-8", newline="\n")
        conn_stop = threading.Event()
        try:
            self._handshake(reader)
            print(f"[worker {self.name}] connected to {self.addr[0]}:{self.addr[1]} with {self.slots} slot(s)",
                  flush=True)
            threading.Thread(target=self._heartbeats, args=(conn_stop,), name="heartbeat", daemon=True).start()
            self.send({"op": "pull", "n": self.free.qsize()})
            for line in reader:
                msg = json.loads(line)
                op = msg.get("op")
                if op == "task":
                    tid = msg.get("tid")
                    if tid:  # the Master sends a template once per node; every slot's runner may need it
                        if msg.get("src") is not None:
                            self.templates[tid] = msg["src"]
                        else:
                            msg["src"] = self.templates.get(tid)
                    try:
                        i = self.free.get_nowait()
                    except queue.Empty:  # the Master never sends more than we pulled; refuse politely
                        self.send({"op": "result", "task": msg["task"], "attempt": msg["attempt"], "ok": False,
                                   "infra": True, "error": {"type": "NoSlot", "message": "no idle slot"}})
                        continue
                    self.inbox[i].put(msg)
                elif op == "cancel":
                    self._cancel(msg["task"])
                elif op == "bye":
                    self.stop.set()
                    break
        finally:
            conn_stop.set()
            with self.wlock:
                self.sock = None
            for i in range(self.slots):
                if self.current.get(i):
                    self._cancel(self.current[i])
            with contextlib.suppress(OSError):
                sock.close()

    def run(self) -> int:
        for i in range(self.slots):
            self.free.put(i)
            self.current[i] = None
            threading.Thread(target=self._slot, args=(i,), name=f"slot-{i}", daemon=True).start()
        for r in self.runners:  # warm the restricted processes before the first task
            with contextlib.suppress(Exception):
                r.start()
        delay = 0.5
        while not self.stop.is_set():
            try:
                self.serve_once()
                delay = 0.5
            except PermissionError as exc:
                print(f"[worker {self.name}] rejected: {exc}", file=sys.stderr, flush=True)
                return 2
            except (OSError, ValueError) as exc:
                if self.stop.is_set() or self._orphaned():
                    break
                print(f"[worker {self.name}] master unreachable ({exc}); retrying in {delay:.1f}s",
                      file=sys.stderr, flush=True)
                self.stop.wait(delay)
                delay = min(delay * 2, 5.0)
        for r in self.runners:
            r.kill()
        return 0


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description="Cluster Computing Worker Node agent")
    ap.add_argument("--master", help="Master Server host:port (cluster port)")
    ap.add_argument("--token", default=os.environ.get("CLUSTER_TOKEN", ""), help="shared cluster token")
    ap.add_argument("--name", default=platform.node())
    ap.add_argument("--slots", type=int, default=os.cpu_count() or 1, help="tasks executed at once")
    ap.add_argument("--workdir", default=os.path.join(tempfile.gettempdir(), "cc-worker"))
    ap.add_argument("--memory-mb", type=int, default=512, help="memory limit of each task process")
    ap.add_argument("--isolation", choices=["auto", "unshare", "none"], default="auto")
    ap.add_argument("--parent-pid", type=int, default=0, help="exit when this process is gone (local workers)")
    ap.add_argument("--runner", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    if args.runner:
        return runner_main(args.memory_mb)
    if not args.master or not args.token:
        ap.error("--master and --token (or $CLUSTER_TOKEN) are required")
    workdir = os.path.join(args.workdir, f"{args.name}-{os.getpid()}")
    os.makedirs(workdir, mode=0o700, exist_ok=True)
    try:
        return Agent(args.master, args.token, args.name, max(1, args.slots), workdir, args.memory_mb,
                     args.isolation, args.parent_pid).run()
    except KeyboardInterrupt:
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
