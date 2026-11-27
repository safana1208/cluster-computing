"""Stage 1 (SRS 5.1): input validation, run in the Master's ProcessPoolExecutor.

Parsing untrusted source is CPU-bound and can exhaust the stack or memory on a hostile
file, so it runs in a separate worker process, never in the Master's own process. The
function is top-level and returns plain data so it pickles cheaply. Standard library only.
"""

from __future__ import annotations

import ast
import hashlib
import os
import time
from typing import Any

_THREAD_HINTS = ("threading", "Thread", "ThreadPoolExecutor")
_PROCESS_HINTS = ("multiprocessing", "ProcessPoolExecutor", "asyncio", "subprocess", "os.fork")


def precheck(job_id: str, filename: str, data: bytes) -> dict[str, Any]:
    """Validate one submission: UTF-8, no NUL bytes, valid Python syntax. Returns a census for the dashboard."""
    started = time.perf_counter()
    out: dict[str, Any] = {"job_id": job_id, "ok": False, "pid": os.getpid(), "error": None, "line": None,
                           "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        out["error"] = f"not UTF-8 text (byte {exc.start})"
        return _done(out, started)
    if "\x00" in text:
        out["error"] = "file contains NUL bytes"
        return _done(out, started)
    try:
        tree = ast.parse(data, filename)
    except SyntaxError as exc:
        out["error"], out["line"] = f"invalid Python syntax: {exc.msg}", exc.lineno
        return _done(out, started)
    except (ValueError, RecursionError, MemoryError) as exc:
        out["error"] = f"cannot parse: {type(exc).__name__}"
        return _done(out, started)
    census = {"lines": text.count("\n") + 1, "functions": 0, "classes": 0, "for_loops": 0, "while_loops": 0,
              "imports": [], "thread_hints": 0, "process_hints": 0}
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            census["functions"] += 1
        elif isinstance(node, ast.ClassDef):
            census["classes"] += 1
        elif isinstance(node, ast.For):
            census["for_loops"] += 1
        elif isinstance(node, ast.While):
            census["while_loops"] += 1
        elif isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    census["imports"] = sorted(imports)
    census["thread_hints"] = sum(text.count(h) for h in _THREAD_HINTS)
    census["process_hints"] = sum(text.count(h) for h in _PROCESS_HINTS)
    out.update(ok=True, census=census)
    return _done(out, started)


def warm_up() -> int:
    """No-op used to start the pool's worker processes ahead of the first job."""
    return os.getpid()


def _done(out: dict[str, Any], started: float) -> dict[str, Any]:
    out["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return out
