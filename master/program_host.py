"""Runs the transformed program on the Master Server, in a restricted process (SRS NFR-2.6).

Started by :mod:`master.runs` as ``python -I -c <this file> <rfd> <wfd> <memory_mb>`` (no network
and user ``nobody`` when Linux namespaces are available, memory limit, run folder as working
directory). Standard library only, nothing from the project is importable here.

It provides ``__mediator__`` (SRS 5.3.1, "Mediator"): at each GO region the transformed program
calls the Mediator, which hands the region's data to the Master's scheduler over a private pipe
(JSON lines), waits for the aggregated result and returns it so the program assigns it back to its
variables. NO-GO regions run here sequentially, exactly as written (FR-3.9).
"""

import builtins
import heapq
import json
import os
import sys
import time
import traceback


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


class ClusterError(RuntimeError):
    """A distributed region failed (program error in a task, or the run was aborted)."""


class _Mediator:
    def __init__(self, rfd, wfd, regions):
        self._r = os.fdopen(rfd, "r", encoding="utf-8")
        self._w = os.fdopen(wfd, "w", encoding="utf-8", buffering=1)
        self.g = {}
        self.regions = {r["task"]: r for r in regions}
        self.by_target = {}
        for r in regions:
            kind = {"thread-group": "thread", "executor-map": "map", "executor-submit": "submit"}.get(r["kind"])
            if kind and r.get("target"):
                self.by_target[(kind, r["target"])] = r["task"]
        self._pending = {}  # thread task -> [stand-in Thread, ...] in creation order

    # ---------------------------------------------------------------- transport
    def _call(self, msg):
        sys.stdout.flush()
        self._w.write(json.dumps(_enc(msg)) + "\n")
        line = self._r.readline()
        if not line:
            raise ClusterError("the Master Server closed the Mediator channel")
        reply = _dec(json.loads(line))
        if not reply.get("ok"):
            err = reply.get("error") or {}
            raise ClusterError(f"{err.get('type', 'Error')}: {err.get('message', 'distributed region failed')}")
        out = reply.get("stdout")
        if out:
            sys.stdout.write(out)
        return reply

    def note(self, **data):
        self._w.write(json.dumps({"op": "note", **data}) + "\n")

    # ---------------------------------------------------------------- loops (Table 5.3.2 splitting is done by the Master)
    def run_region(self, task, iterable, split, acc, consts):
        if split == "range":
            data = {"range": [iterable.start, iterable.stop, iterable.step]}
        elif split == "files":
            files = []
            for name in iterable:
                with open(name, encoding="utf-8", errors="replace") as fh:
                    files.append([name, fh.read()])
            data = {"files": files}
        elif split == "items":
            data = {"items": [list(kv) for kv in iterable]}
        else:  # list / tuple / lines of a file
            data = {"items": list(iterable)}
        return self._call({"op": "region", "task": task, "data": data, "consts": consts})["result"]

    def run_sort(self, task, data, key=None, reverse=False):
        chunks = self._call({"op": "region", "task": task, "data": {"items": list(data)}, "consts": {}})["chunks"]
        started = time.perf_counter()
        if key is None:  # Phase 2 on the Master (FR-4.4); merging in chunk order keeps the sort stable
            merged = list(heapq.merge(*chunks, reverse=reverse))
        else:  # chunks hold [key, item] pairs: no key is recomputed here
            merged = [p[1] for p in heapq.merge(*chunks, key=lambda p: p[0], reverse=reverse)]
        self.note(task=task, merge_ms=(time.perf_counter() - started) * 1000)
        return merged

    # ---------------------------------------------------------------- thread groups (SRS 5.3.2)
    def _apply(self, task, result):
        for name, kind in (self.regions[task].get("acc") or {}).items():
            value = result.get(name)
            if value is None or name not in self.g:
                continue
            live = self.g[name]
            if kind == "list":
                live.extend(value)
            elif kind == "set":
                live.update(value)
            elif kind == "sum":
                self.g[name] = live + value
            elif kind == "counter":
                for k, v in value:
                    live[k] = live.get(k, 0) + v
            elif kind == "dict":
                for k, v in value:
                    live[k] = v

    def _flush(self, task):
        group = self._pending.pop(task, [])
        if not group:
            return
        calls = [{"args": list(t._args), "kwargs": dict(t._kwargs)} for t in group]
        reply = self._call({"op": "calls", "task": task, "calls": calls})
        self._apply(task, reply["result"])
        for t, value in zip(group, reply["result"].get("__return__", [])):
            t._value, t._done = value, True

    def Thread(self, group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None):  # noqa: N802
        task = self.by_target.get(("thread", getattr(target, "__name__", None)))
        if task is None:  # not a GO thread group: a real thread, as written
            import threading
            return threading.Thread(group, target, name, args, kwargs, daemon=daemon)
        return _TaskThread(self, task, target, name, args, kwargs or {})

    def Executor(self, *args, **kwargs):  # noqa: N802
        return _TaskExecutor(self, args, kwargs)


class _TaskThread:
    """Stands in for a Thread of a GO thread group: no thread is created (SRS 2.2)."""

    def __init__(self, med, task, target, name, args, kwargs):
        self._med, self._task, self._target = med, task, target
        self.name = name or f"task-{task}"
        self._args, self._kwargs = tuple(args), kwargs
        self._started = self._done = False
        self._value = None
        self.daemon = False

    def start(self):
        if not self._started:
            self._started = True
            self._med._pending.setdefault(self._task, []).append(self)

    def join(self, timeout=None):
        if self._started and not self._done:
            self._med._flush(self._task)  # the join point: one task per started thread

    def is_alive(self):
        return self._started and not self._done


class _TaskFuture:
    def __init__(self, med, task, owner):
        self._med, self._task, self._owner = med, task, owner
        self._value, self._done = None, False

    def result(self, timeout=None):
        if not self._done:
            self._med._flush(self._task)
        return self._value

    def done(self):
        return self._done


class _TaskExecutor:
    """Stands in for ThreadPoolExecutor: map() and submit() of GO targets become tasks (Patterns B, C)."""

    def __init__(self, med, args, kwargs):
        self._med, self._args, self._kwargs = med, args, kwargs
        self._real = None

    def _fallback(self):
        if self._real is None:
            from concurrent.futures import ThreadPoolExecutor
            self._real = ThreadPoolExecutor(*self._args, **self._kwargs)
        return self._real

    def map(self, fn, *iterables, timeout=None, chunksize=1):
        task = self._med.by_target.get(("map", getattr(fn, "__name__", None)))
        if task is None or len(iterables) != 1:
            return self._fallback().map(fn, *iterables)
        result = self._med._call({"op": "region", "task": task, "data": {"items": list(iterables[0])},
                                  "consts": {}})["result"]
        self._med._apply(task, result)
        return iter(result.get("__return__", []))

    def submit(self, fn, *args, **kwargs):
        task = self._med.by_target.get(("submit", getattr(fn, "__name__", None)))
        if task is None:
            return self._fallback().submit(fn, *args, **kwargs)
        future = _TaskFuture(self._med, task, self)
        future._args, future._kwargs = args, kwargs
        self._med._pending.setdefault(task, []).append(future)
        return future

    def shutdown(self, wait=True, cancel_futures=False):
        for task in list(self._med._pending):
            if self._med.regions.get(task, {}).get("kind") == "executor-submit":
                self._med._flush(task)
        if self._real is not None:
            self._real.shutdown(wait=wait)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.shutdown()
        return False


def _limit(memory_mb):
    try:
        import resource
        # virtual-memory backstop only; the Master enforces run_memory_mb on real memory (RSS)
        for name, value in (("RLIMIT_AS", memory_mb * 8 * 1024 * 1024), ("RLIMIT_CORE", 0),
                            ("RLIMIT_FSIZE", 64 * 1024 * 1024)):
            lim = getattr(resource, name, None)
            if lim is not None and value > 0:
                resource.setrlimit(lim, (value, value))
    except (ImportError, ValueError, OSError):
        pass


def main():
    rfd, wfd, memory_mb = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    _limit(memory_mb)
    sys.setrecursionlimit(5000)
    med = _Mediator(rfd, wfd, [])
    spec = json.loads(med._r.readline())
    med.regions = {r["task"]: r for r in spec["regions"]}
    for r in spec["regions"]:
        kind = {"thread-group": "thread", "executor-map": "map", "executor-submit": "submit"}.get(r["kind"])
        if kind and r.get("target"):
            med.by_target[(kind, r["target"])] = r["task"]
    sys.path.insert(0, os.getcwd())
    g = {"__name__": "__main__", "__builtins__": builtins, "__mediator__": med}
    med.g = g
    started = time.perf_counter()
    try:
        code = compile(spec["source"], "<transformed>", "exec")
        try:
            exec(code, g)  # noqa: S102 - screened program, restricted process
        except SystemExit as exc:
            if exc.code not in (None, 0):
                raise RuntimeError(f"program exited with status {exc.code}") from None
        sys.stdout.flush()
        med._w.write(json.dumps({"op": "exit", "ok": True, "ms": (time.perf_counter() - started) * 1000}) + "\n")
    except BaseException as exc:  # noqa: BLE001 - reported to the Master
        sys.stdout.flush()
        line = None
        for frame in traceback.extract_tb(exc.__traceback__):
            if frame.filename == "<transformed>":
                line = frame.lineno
        text = None
        if line:
            lines = spec["source"].splitlines()
            text = lines[line - 1].strip() if 0 < line <= len(lines) else None
        med._w.write(json.dumps({"op": "exit", "ok": False, "ms": (time.perf_counter() - started) * 1000,
                                 "cluster": isinstance(exc, ClusterError),
                                 "error": {"type": type(exc).__name__, "message": str(exc)[:500], "line": line,
                                           "text": text, "trace": traceback.format_exc()[-1500:]}}) + "\n")
    med._w.flush()


if __name__ == "__main__":
    main()
