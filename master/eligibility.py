"""Cluster eligibility: can this program run in parallel on the Worker Nodes?

Implements the conservative Go/No-Go analysis of the SRS:

* program checks P1 (concurrency constructs) and P2 (candidate regions),
* region checks R1-R10 applied in order, stopping at the first failure (Table 3.3.1),
* the check-and-reconstruction templates of Table 5.3.1 (list collect, sum / counter, keyed
  dictionary, set collect, first match, print output, sort, thread group),
* the input-splitting rules of Table 5.3.2,
* thread patterns A (``threading.Thread``), B (``ThreadPoolExecutor.map``) and
  C (``ThreadPoolExecutor.submit`` + ``result()``) of Section 5.3.2,
* T1: a task template and a rewritten program are generated for every GO region and compiled.

The analysis is static: the program is parsed, never executed. It runs inside the inspection
sandbox, and only after the security screening has passed (FR-2.4). Standard library only.
"""

from __future__ import annotations

import ast
import builtins
import copy
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

ELIGIBILITY_VERSION = 1

#: SRS 2.5: standard-library modules allowed inside parallel regions (Control Parameter File default).
DEFAULT_ALLOWLIST: tuple[str, ...] = (
    "math", "hashlib", "re", "string", "itertools", "collections", "json", "datetime",
    "os.path", "os.listdir", "os.walk", "glob",
)
#: Builtins a task may call. ``open``/``input``/``print`` are handled by R8; dynamic-name builtins by R3.
SAFE_BUILTINS = frozenset({
    "abs", "all", "any", "ascii", "bin", "bool", "bytes", "chr", "dict", "divmod", "enumerate", "filter",
    "float", "format", "frozenset", "hash", "hex", "int", "isinstance", "issubclass", "iter", "len", "list",
    "map", "max", "min", "next", "oct", "ord", "pow", "print", "range", "repr", "reversed", "round", "set",
    "slice", "sorted", "str", "sum", "tuple", "type", "zip", "open", "bytearray", "complex", "callable",
    "input", "hasattr", "getattr", "id",
    "ValueError", "KeyError", "IndexError", "TypeError", "ZeroDivisionError", "Exception", "StopIteration",
    "ArithmeticError", "LookupError", "RuntimeError", "AssertionError", "NotImplementedError",
})
_DYNAMIC_NAMES = frozenset({"globals", "locals", "vars", "setattr", "delattr", "eval", "exec", "__import__", "compile"})
_MUTATORS = frozenset({
    "append", "extend", "insert", "remove", "pop", "clear", "sort", "reverse", "update", "setdefault", "popitem",
    "add", "discard", "difference_update", "intersection_update", "symmetric_difference_update", "write",
    "writelines", "__setitem__", "__delitem__", "put", "send",
})
_JSON_CTORS = frozenset({"list", "dict", "set", "int", "float", "str", "tuple", "frozenset",
                         "collections.Counter", "collections.defaultdict", "collections.OrderedDict"})
_ITERATOR_CALLS = frozenset({"enumerate", "zip", "map", "filter", "reversed", "iter", "itertools.chain",
                             "itertools.product", "itertools.permutations", "itertools.combinations",
                             "glob.iglob", "os.walk", "os.scandir"})

TEMPLATES: dict[str, tuple[str, str]] = {
    "list": ("List collect", "Concatenate in task order"),
    "sum": ("Sum / counter", "Sum"),
    "dict": ("Keyed dictionary", "Merge (sum the values for counters)"),
    "set": ("Set collect", "Union"),
    "first": ("First match", "Lowest index; early termination (FR-4.5)"),
    "print": ("Print output", "Printed in task order"),
    "sort": ("Sort", "Merge of sorted chunks (FR-4.4)"),
    "thread": ("Thread group", "Accumulators in thread-creation order; return values in submission order"),
}
SPLITS: dict[str, str] = {
    "range": "Sub-ranges of consecutive indices (start, stop, step); no data is copied",
    "list": "Slices of consecutive elements + index of the first element",
    "items": "Slices of [key, value] pairs, in insertion order",
    "lines": "Blocks of whole lines (UTF-8) + number of the first line",
    "files": "Groups of whole files (names + text content); a file is never split",
    "map": "Slices of the items; the task calls f for each item",
    "threads": "One task per thread (that thread's arguments)",
    "sort": "Slices sorted on Worker Nodes (Phase 1), merged on the Master (Phase 2)",
}
_CHECK_NAMES = {
    "P1": "Concurrency constructs", "P2": "Candidate regions",
    "R1": "Region form", "R2": "Libraries", "R3": "Variable classification", "R4": "Writes",
    "R5": "Carried dependency", "R6": "Global reads", "R7": "Called functions", "R8": "Input / output",
    "R9": "Serializability", "R10": "Template match", "T1": "Compile",
}


# --------------------------------------------------------------------------- results
@dataclass(slots=True)
class Check:
    id: str
    status: str            # pass | fail | skip | note
    detail: str = ""

    @property
    def name(self) -> str:
        return _CHECK_NAMES.get(self.id, self.id)

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name, "status": self.status, "detail": self.detail}


@dataclass(slots=True)
class Accumulator:
    name: str
    kind: str              # list | sum | dict | counter | set | first
    line: int
    init: str | None = None

    def to_dict(self) -> dict[str, Any]:
        key = "dict" if self.kind == "counter" else self.kind
        title, reconstruction = TEMPLATES[key]
        return {"name": self.name, "kind": self.kind, "template": title, "reconstruction": reconstruction,
                "line": self.line, "init": self.init}


@dataclass(slots=True)
class ConcurrencyItem:
    construct: str
    line: int
    kind: str              # thread | executor | lock | process | async | sync
    supported: bool
    note: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Region:
    index: int
    kind: str              # for-loop | while-loop | sort | thread-group | executor-map | executor-submit
    line: int
    end_line: int
    scope: str
    header: str
    decision: str = "NO-GO"
    failed_check: str | None = None
    reason: str = ""
    checks: list[Check] = field(default_factory=list)
    accumulators: list[Accumulator] = field(default_factory=list)
    patterns: list[str] = field(default_factory=list)
    split: str | None = None
    constants: list[str] = field(default_factory=list)
    called_functions: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    iterations: int | None = None
    planned_tasks: int | None = None
    thread_pattern: str | None = None
    task_name: str | None = None
    task_template: str | None = None
    rewrite: str | None = None

    @property
    def id(self) -> str:
        return f"#{self.index}"

    def to_dict(self) -> dict[str, Any]:
        templates = [TEMPLATES[p][0] for p in self.patterns]
        return {
            "id": self.id, "index": self.index, "kind": self.kind, "line": self.line, "end_line": self.end_line,
            "scope": self.scope, "header": self.header, "decision": self.decision,
            "failed_check": self.failed_check,
            "failed_check_name": _CHECK_NAMES.get(self.failed_check or "", None), "reason": self.reason,
            "checks": [c.to_dict() for c in self.checks],
            "template": " + ".join(templates) if templates else None,
            "reconstruction": [TEMPLATES[p][1] for p in self.patterns],
            "accumulators": [a.to_dict() for a in self.accumulators],
            "split": self.split, "split_rule": SPLITS.get(self.split or ""), "constants": self.constants,
            "called_functions": self.called_functions, "modules": self.modules, "iterations": self.iterations,
            "planned_tasks": self.planned_tasks, "thread_pattern": self.thread_pattern, "task_name": self.task_name,
            "task_template": self.task_template, "rewrite": self.rewrite,
            "target": getattr(self, "_target", None),
        }


class _RegionFail(Exception):
    def __init__(self, check: str, reason: str) -> None:
        super().__init__(reason)
        self.check = check
        self.reason = reason


# --------------------------------------------------------------------------- AST helpers
def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _loads(node: ast.AST | list[ast.stmt]) -> list[ast.Name]:
    """Name loads in evaluation scope (comprehension / lambda variables and nested defs excluded)."""
    out: list[ast.Name] = []

    def walk(n: ast.AST, bound: frozenset[str]) -> None:
        if isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            inner = set(bound)
            for g in n.generators:
                walk(g.iter, frozenset(inner))
                inner |= {x.id for x in ast.walk(g.target) if isinstance(x, ast.Name)}
                for cond in g.ifs:
                    walk(cond, frozenset(inner))
            for e in ([n.key, n.value] if isinstance(n, ast.DictComp) else [n.elt]):
                walk(e, frozenset(inner))
            return
        if isinstance(n, ast.Lambda):
            walk(n.body, bound | {a.arg for a in ast.walk(n.args) if isinstance(a, ast.arg)})
            return
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for d in n.decorator_list:
                walk(d, bound)
            return
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in bound:
            out.append(n)
        for child in ast.iter_child_nodes(n):
            walk(child, bound)

    for item in (node if isinstance(node, list) else [node]):
        walk(item, frozenset())
    return out


def _stored_names(node: ast.AST | list[ast.stmt]) -> set[str]:
    """Names bound by assignment / for / with / import / def, excluding nested scopes."""
    out: set[str] = set()

    def walk(n: ast.AST) -> None:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
            return
        if isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp, ast.Lambda)):
            return
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            out.add(n.id)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                out.add(a.asname or a.name.split(".")[0])
        elif isinstance(n, ast.ExceptHandler) and n.name:
            out.add(n.name)
        for child in ast.iter_child_nodes(n):
            walk(child)

    for item in (node if isinstance(node, list) else [node]):
        walk(item)
    return out


def _walk_no_defs(node: ast.AST | list[ast.stmt]) -> Iterable[ast.AST]:
    """``ast.walk`` that does not descend into nested function / class / lambda bodies."""
    pending = list(node) if isinstance(node, list) else [node]
    while pending:
        n = pending.pop()
        yield n
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        pending.extend(ast.iter_child_nodes(n))


def _target_base(node: ast.AST) -> ast.Name | None:
    while isinstance(node, (ast.Subscript, ast.Attribute)):
        node = node.value
    return node if isinstance(node, ast.Name) else None


def _const_int(node: ast.AST) -> int | None:
    try:
        value = ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return None
    return value if type(value) is int else None


def _is_literal(node: ast.AST) -> bool:
    try:
        ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return False
    return True


def _first_use(stmts: list[ast.stmt], name: str, cond: bool = False) -> str | None:
    """How ``name`` is first used in ``stmts``: ``load``, ``store`` (unconditional) or ``store-cond``."""
    for s in stmts:
        r = _first_use_stmt(s, name, cond)
        if r:
            return r
    return None


def _first_use_stmt(s: ast.stmt, name: str, cond: bool) -> str | None:
    store = "store-cond" if cond else "store"

    def loads_in(*nodes: ast.AST | None) -> bool:
        return any(n is not None and any(x.id == name for x in _loads(n)) for n in nodes)

    if isinstance(s, ast.Assign):
        if loads_in(s.value) or any(loads_in(t) for t in s.targets if not isinstance(t, ast.Name)):
            return "load"
        if any(name in _stored_names(t) for t in s.targets):
            return store
        return None
    if isinstance(s, ast.AugAssign):
        if (isinstance(s.target, ast.Name) and s.target.id == name) or loads_in(s.value, s.target):
            return "load"
        return None
    if isinstance(s, ast.AnnAssign):
        if loads_in(s.value):
            return "load"
        return store if s.value is not None and name in _stored_names(s.target) else None
    if isinstance(s, (ast.If, ast.While)):
        if loads_in(s.test):
            return "load"
        return _first_use(s.body, name, True) or _first_use(s.orelse, name, True)
    if isinstance(s, (ast.For, ast.AsyncFor)):
        if loads_in(s.iter):
            return "load"
        if name in _stored_names(s.target):
            return "store-cond"
        return _first_use(s.body, name, True) or _first_use(s.orelse, name, True)
    if isinstance(s, (ast.With, ast.AsyncWith)):
        for item in s.items:
            if loads_in(item.context_expr):
                return "load"
            if item.optional_vars is not None and name in _stored_names(item.optional_vars):
                return store
        return _first_use(s.body, name, cond)
    if isinstance(s, ast.Try):
        for block in (s.body, *[h.body for h in s.handlers], s.orelse):
            r = _first_use(block, name, True)
            if r:
                return r
        return _first_use(s.finalbody, name, cond)
    if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return store if s.name == name else None
    if loads_in(s):
        return "load"
    return store if name in _stored_names(s) else None


# --------------------------------------------------------------------------- analyzer
class EligibilityAnalyzer:
    """Static Go/No-Go analysis of one program.

    Args:
        source: Program text.
        filename: Name used in reports.
        allowlist: Standard-library modules allowed inside regions.
        chunk_factor: Chunks per active Worker Node (SRS 5.3.4, default 4).
        worker_nodes: Number of configured Worker Nodes (used to plan the task count).
    """

    def __init__(self, source: str, filename: str = "<input>", allowlist: Iterable[str] = DEFAULT_ALLOWLIST,
                 chunk_factor: int = 4, worker_nodes: int = 1) -> None:
        self.source = source
        self.filename = filename
        self.allowlist = tuple(allowlist)
        self.chunk_factor = max(1, int(chunk_factor))
        self.worker_nodes = max(1, int(worker_nodes))
        self.lines = source.splitlines()
        self.tree = ast.parse(source, filename)
        self.aliases: dict[str, str] = {}
        self.import_nodes: dict[str, ast.stmt] = {}
        self.functions: dict[str, ast.FunctionDef] = {}
        self.duplicate_functions: set[str] = set()
        self.classes: set[str] = set()
        self.module_stores: dict[str, list[ast.stmt]] = {}
        self.global_writers: dict[str, set[str]] = {}
        self.generators: set[str] = set()
        self.concurrency: list[ConcurrencyItem] = []
        self.thread_targets: set[str] = set()
        self.lock_names: set[str] = set()
        self.executor_names: set[str] = set()
        self._fn_cache: dict[str, tuple[set[str], list[str], str | None]] = {}
        self._prepare()

    # ------------------------------------------------------------------ prep
    def _prepare(self) -> None:
        for stmt in self.tree.body:
            if isinstance(stmt, ast.Import):
                for a in stmt.names:
                    local = a.asname or a.name.split(".")[0]
                    self.aliases[local] = a.name if a.asname else a.name.split(".")[0]
                    self.import_nodes[local] = ast.Import(names=[a])
            elif isinstance(stmt, ast.ImportFrom) and stmt.module and not stmt.level:
                for a in stmt.names:
                    if a.name != "*":
                        self.aliases[a.asname or a.name] = f"{stmt.module}.{a.name}"
                        self.import_nodes[a.asname or a.name] = ast.ImportFrom(module=stmt.module, names=[a], level=0)
            elif isinstance(stmt, ast.FunctionDef):
                if stmt.name in self.functions:
                    self.duplicate_functions.add(stmt.name)
                self.functions[stmt.name] = stmt
            elif isinstance(stmt, ast.ClassDef):
                self.classes.add(stmt.name)
            for name in _stored_names(stmt):
                self.module_stores.setdefault(name, []).append(stmt)
        for fn in self.functions.values():
            declared = {n for g in _walk_no_defs(fn.body) if isinstance(g, ast.Global) for n in g.names}
            for name in declared & _stored_names(fn.body):
                self.global_writers.setdefault(name, set()).add(fn.name)
            if any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in _walk_no_defs(fn.body)):
                self.generators.add(fn.name)

    def resolve(self, node: ast.AST) -> str | None:
        dotted = _dotted(node)
        if dotted is None:
            return None
        head, _, rest = dotted.partition(".")
        base = self.aliases.get(head)
        if base is None:
            return dotted
        return f"{base}.{rest}" if rest else base

    def snippet(self, line: int) -> str:
        return self.lines[line - 1].strip()[:140] if 0 < line <= len(self.lines) else ""

    # ------------------------------------------------------------------ P1
    def scan_concurrency(self) -> list[str]:
        """Record every thread / process / async construct. Returns the unsupported ones (P1 reasons)."""
        bad: list[str] = []

        def add(construct: str, line: int, kind: str, supported: bool, note: str) -> None:
            self.concurrency.append(ConcurrencyItem(construct, line, kind, supported, note))
            if not supported:
                bad.append(f"{construct} (line {line}): {note}")

        for node in ast.walk(self.tree):  # pre-pass: names bound to locks and thread pools
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                ctor = self.resolve(node.value.func)
                for t in node.targets:
                    if isinstance(t, ast.Name) and ctor in ("threading.Lock", "threading.RLock"):
                        self.lock_names.add(t.id)
                    elif isinstance(t, ast.Name) and ctor == "concurrent.futures.ThreadPoolExecutor":
                        self.executor_names.add(t.id)
            elif isinstance(node, ast.With):
                for item in node.items:
                    if isinstance(item.context_expr, ast.Call) and isinstance(item.optional_vars, ast.Name) and \
                            self.resolve(item.context_expr.func) == "concurrent.futures.ThreadPoolExecutor":
                        self.executor_names.add(item.optional_vars.id)
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                for m in mods:
                    root = m.split(".")[0]
                    if root == "multiprocessing":
                        add(m, node.lineno, "process", False, "process-based concurrency is not converted (SRS 2.5)")
                    elif root == "asyncio":
                        add(m, node.lineno, "async", False, "asynchronous concurrency is not converted (SRS 2.5)")
                    elif root in ("_thread", "queue"):
                        add(m, node.lineno, "sync", False, "threads that communicate while running are not supported")
            elif isinstance(node, (ast.AsyncFunctionDef, ast.Await, ast.AsyncFor, ast.AsyncWith)):
                add(type(node).__name__, node.lineno, "async", False, "async code is not converted (SRS 2.5)")
            elif isinstance(node, ast.ClassDef):
                for b in node.bases:
                    if self.resolve(b) == "threading.Thread":
                        add(f"class {node.name}(Thread)", node.lineno, "thread", False,
                            "Thread subclasses are not supported (SRS 5.3.2)")
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Attribute) and t.attr == "daemon":
                        add(f"{ast.unparse(t)} = ...", node.lineno, "thread", False, "daemon threads are not supported")
            if not isinstance(node, ast.Call):
                continue
            name = self.resolve(node.func) or ""
            attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if name == "threading.Thread":
                daemon = next((k for k in node.keywords if k.arg == "daemon"), None)
                if daemon is not None and not (isinstance(daemon.value, ast.Constant) and daemon.value.value is False):
                    add("Thread(daemon=...)", node.lineno, "thread", False, "daemon threads are not supported")
                else:
                    add("threading.Thread", node.lineno, "thread", True,
                        "Pattern A: each thread becomes one task, run as a direct function call")
                target = self._thread_target(node)
                if isinstance(target, ast.Name):
                    self.thread_targets.add(target.id)
            elif name == "threading.Timer":
                add("threading.Timer", node.lineno, "thread", False, "Timer threads are not supported")
            elif name in ("threading.Event", "threading.Condition", "threading.Semaphore", "threading.Barrier",
                          "threading.BoundedSemaphore", "threading.local") or name.startswith("queue."):
                add(name, node.lineno, "sync", False,
                    "threads that communicate while running are not supported (SRS 5.3.2)")
            elif name in ("threading.Lock", "threading.RLock"):
                add(name, node.lineno, "lock", True, "allowed only around a single accumulator update")
            elif name == "concurrent.futures.ThreadPoolExecutor":
                add("ThreadPoolExecutor", node.lineno, "executor", True,
                    "Patterns B/C: items become tasks; parallelism is set by the Worker Nodes, not max_workers")
            elif name == "concurrent.futures.ProcessPoolExecutor" or name.startswith("multiprocessing."):
                add(name.rsplit(".", 1)[-1], node.lineno, "process", False,
                    "process-based concurrency is not converted (SRS 2.5)")
            elif name in ("concurrent.futures.as_completed", "concurrent.futures.wait") or attr == "add_done_callback":
                add(name or attr, node.lineno, "executor", False,
                    "as_completed / callbacks depend on timing (SRS 5.3.2)")
            elif attr == "setDaemon":
                add("setDaemon()", node.lineno, "thread", False, "daemon threads are not supported")
            elif attr in ("acquire", "release") and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id in self.lock_names:
                add(f"{node.func.value.id}.{attr}()", node.lineno, "lock", False,
                    "locks must be used as 'with lock:' around one accumulator update")
            elif name.startswith("asyncio."):
                add(name, node.lineno, "async", False, "asynchronous concurrency is not converted (SRS 2.5)")
            if attr in ("map", "submit") and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id in self.executor_names and node.args and isinstance(node.args[0], ast.Name):
                self.thread_targets.add(node.args[0].id)

        uses_threads = any(i.construct == "threading.Thread" for i in self.concurrency)
        if uses_threads and not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                                    and n.func.attr == "join" and not n.args
                                    and not isinstance(n.func.value, ast.Constant) for n in ast.walk(self.tree)):
            add("Thread without join()", next(i.line for i in self.concurrency if i.construct == "threading.Thread"),
                "thread", False, "every thread must be joined before its results are used")
        # with lock: blocks may only protect one recognized accumulator update.
        for node in ast.walk(self.tree):
            if isinstance(node, ast.With) and any(isinstance(i.context_expr, ast.Name)
                                                  and i.context_expr.id in self.lock_names for i in node.items):
                if not (len(node.body) == 1 and self._is_accumulator_stmt(node.body[0])):
                    add("with lock:", node.lineno, "lock", False,
                        "a lock may only protect a single accumulator update (SRS 5.3.2)")
        return bad

    @staticmethod
    def _is_accumulator_stmt(s: ast.stmt) -> bool:
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) and isinstance(s.value.func, ast.Attribute):
            return s.value.func.attr in ("append", "extend", "add") and isinstance(s.value.func.value, ast.Name)
        if isinstance(s, ast.AugAssign):
            return isinstance(s.op, (ast.Add, ast.Sub)) and isinstance(_target_base(s.target), ast.Name)
        if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Subscript):
            return isinstance(s.targets[0].value, ast.Name)
        return False

    @staticmethod
    def _thread_target(call: ast.Call) -> ast.expr | None:
        for k in call.keywords:
            if k.arg == "target":
                return k.value
        return call.args[1] if len(call.args) > 1 else None

    @staticmethod
    def _thread_args(call: ast.Call) -> list[ast.expr]:
        out: list[ast.expr] = []
        for k in call.keywords:
            if k.arg in ("args", "kwargs"):
                out.append(k.value)
        if len(call.args) > 3:
            out.extend(call.args[3:5])
        return out

    # ------------------------------------------------------------------ regions
    def collect_regions(self) -> list[Region]:
        regions: list[Region] = []
        scopes: list[tuple[str, list[ast.stmt], ast.FunctionDef | None]] = [("<module>", self.tree.body, None)]
        scopes += [(name, fn.body, fn) for name, fn in self.functions.items() if name not in self.thread_targets]
        for scope_name, body, fn in scopes:
            for node in self._outer_statements(body):
                if isinstance(node, ast.For):
                    if self._is_thread_orchestration(node):
                        continue
                    regions.append(Region(0, "for-loop", node.lineno, node.end_lineno or node.lineno, scope_name,
                                          self.snippet(node.lineno)))
                    regions[-1]._node = node  # type: ignore[attr-defined]
                    regions[-1]._fn = fn  # type: ignore[attr-defined]
                elif isinstance(node, ast.While):
                    r = Region(0, "while-loop", node.lineno, node.end_lineno or node.lineno, scope_name,
                               self.snippet(node.lineno))
                    r.checks = [Check("R1", "fail", "while loops are not parallelized (SRS 2.5)")]
                    r.failed_check, r.reason = "R1", "while loops are not parallelized; the region runs sequentially"
                    regions.append(r)
                else:
                    sort_call = self._sort_call(node)
                    if sort_call is not None:
                        r = Region(0, "sort", node.lineno, node.end_lineno or node.lineno, scope_name,
                                   self.snippet(node.lineno))
                        r._node, r._call, r._fn = node, sort_call, fn  # type: ignore[attr-defined]
                        regions.append(r)
        regions += self._thread_regions()
        regions.sort(key=lambda r: (r.line, r.kind))
        for i, r in enumerate(regions, 1):
            r.index = i
        return regions

    def _outer_statements(self, body: list[ast.stmt]) -> Iterable[ast.stmt]:
        """Statements of a scope that may start a region: descend into if/with/try, not into loops or defs."""
        for s in body:
            yield s
            if isinstance(s, ast.If):
                yield from self._outer_statements(s.body)
                yield from self._outer_statements(s.orelse)
            elif isinstance(s, ast.With):
                yield from self._outer_statements(s.body)
            elif isinstance(s, ast.Try):
                for block in (s.body, s.orelse, s.finalbody, *[h.body for h in s.handlers]):
                    yield from self._outer_statements(block)

    def _is_thread_orchestration(self, loop: ast.For) -> bool:
        for n in _walk_no_defs(loop):
            if isinstance(n, ast.Call):
                name = self.resolve(n.func) or ""
                attr = n.func.attr if isinstance(n.func, ast.Attribute) else ""
                if name in ("threading.Thread", "concurrent.futures.ThreadPoolExecutor") or (
                        attr in ("start", "join") and not n.args and not isinstance(n.func.value, ast.Constant)) or (
                        attr in ("submit", "map", "result") and isinstance(n.func.value, ast.Name)
                        and (n.func.value.id in self.executor_names or attr == "result")):
                    return True
        return False

    def _sort_call(self, stmt: ast.stmt) -> ast.Call | None:
        value = stmt.value if isinstance(stmt, (ast.Expr, ast.Assign)) else None
        if not isinstance(value, ast.Call):
            return None
        if isinstance(value.func, ast.Name) and value.func.id == "sorted" and "sorted" not in self.functions \
                and value.args and isinstance(value.args[0], ast.Name):
            return value  # sorted(<expression>) builds a new list from an iterator: not a sort region
        if isinstance(stmt, ast.Expr) and isinstance(value.func, ast.Attribute) and value.func.attr == "sort" \
                and isinstance(value.func.value, ast.Name) and not value.args:
            return value
        return None

    # ------------------------------------------------------------------ scope helpers
    def _outer_bound(self, loop: ast.AST, fn: ast.FunctionDef | None) -> set[str]:
        inside = {id(n) for n in ast.walk(loop)}
        if fn is None:
            names: set[str] = set()
            for stmt in self.tree.body:
                for n in _walk_no_defs(stmt):
                    if id(n) in inside:
                        continue
                    if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                        names.add(n.id)
                    elif isinstance(n, (ast.FunctionDef, ast.ClassDef)):
                        names.add(n.name)
            return names | set(self.aliases)
        args = fn.args
        params = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
        params |= {a.arg for a in (args.vararg, args.kwarg) if a}
        local = {n.id for n in _walk_no_defs(fn.body) if id(n) not in inside and isinstance(n, ast.Name)
                 and isinstance(n.ctx, (ast.Store, ast.Del))}
        return params | local | set(self.module_stores) | set(self.aliases)

    def _function_locals(self, fn: ast.FunctionDef | None) -> set[str]:
        if fn is None:
            return set()
        declared = {n for g in _walk_no_defs(fn.body) if isinstance(g, (ast.Global, ast.Nonlocal)) for n in g.names}
        args = fn.args
        params = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
        return (params | _stored_names(fn.body)) - declared

    def _reads_after(self, loop: ast.AST, fn: ast.FunctionDef | None) -> set[str]:
        end = getattr(loop, "end_lineno", 0) or 0
        inside = {id(n) for n in ast.walk(loop)}
        body = fn.body if fn else self.tree.body
        names = {n.id for n in _loads(body) if id(n) not in inside and n.lineno > end}
        if fn is None:  # functions may run after the loop and read module globals
            for f in self.functions.values():
                names |= {n.id for n in _loads(f.body)}
        return names

    def _binding_value(self, name: str, before_line: int, fn: ast.FunctionDef | None) -> ast.AST | None:
        """The expression last bound to ``name`` before ``before_line`` in the scope (or module)."""
        best: tuple[int, ast.AST] | None = None
        bodies = [fn.body] if fn else []
        bodies.append(self.tree.body)
        for body in bodies:
            for n in _walk_no_defs(body):
                line = getattr(n, "lineno", 0)
                if line >= before_line:
                    continue
                value: ast.AST | None = None
                if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
                    value = n.value
                elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id == name:
                    value = n.value
                elif isinstance(n, ast.withitem) and isinstance(n.optional_vars, ast.Name) \
                        and n.optional_vars.id == name:
                    value = n.context_expr
                if value is not None and (best is None or line >= best[0]):
                    best = (line, value)
            if best is not None:
                return best[1]
        if fn is not None:
            args = fn.args
            if name in {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}:
                return ast.Name("__param__", ast.Load())
        return None

    # ------------------------------------------------------------------ R1: iterables
    def _classify_iterable(self, node: ast.AST, line: int, fn: ast.FunctionDef | None,
                           depth: int = 0) -> tuple[str, str | None]:
        """Return (split kind, NO-GO reason or None)."""
        if depth > 4:
            return "list", None
        if isinstance(node, (ast.List, ast.Tuple, ast.ListComp, ast.Subscript, ast.BinOp)) or (
                isinstance(node, ast.Constant) and isinstance(node.value, str)):
            if isinstance(node, ast.ListComp) and len(node.generators) == 1:
                kind, _ = self._classify_iterable(node.generators[0].iter, line, fn, depth + 1)
                if kind == "files":
                    return "files", None
            return "list", None
        if isinstance(node, (ast.GeneratorExp, ast.SetComp, ast.Set)):
            return "list", "generator / set iteration is not in the split rules (Table 5.3.2)"
        if isinstance(node, (ast.Dict, ast.DictComp)):
            return "items", "iterate d.items() to split a dictionary"
        if isinstance(node, ast.Call):
            name = self.resolve(node.func) or ""
            attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if name == "range":
                return "range", None
            if name in ("open", "io.open"):
                mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords
                                                                     if k.arg == "mode"), None)
                if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and "b" in mode.value:
                    return "lines", "binary files (\"rb\") are not split (SRS 5.3.4)"
                return "lines", None
            if attr == "items" and not node.args:
                return "items", None
            if attr in ("keys", "values") and not node.args:
                return "list", "iterate d.items() to split a dictionary"
            if attr == "readlines":
                return "lines", None
            if attr in ("split", "splitlines"):
                return "list", None
            if name in ("os.listdir", "glob.glob"):
                return "files", None
            if name in _ITERATOR_CALLS:
                return "list", f"{name}() is an iterator; only range, lists, tuples, dict.items(), file lines " \
                               "and file lists are split (Table 5.3.2)"
            if name in ("sorted", "list", "tuple") and node.args:
                inner = node.args[0]
                if isinstance(inner, (ast.GeneratorExp, ast.ListComp)) and len(inner.generators) == 1:
                    inner = inner.generators[0].iter  # materialized by sorted()/list(): only the source matters
                kind, _ = self._classify_iterable(inner, line, fn, depth + 1)
                return ("files" if kind == "files" else "list"), None
            if isinstance(node.func, ast.Name) and node.func.id in self.generators:
                return "list", f"'{node.func.id}' is a generator: iterators with side effects are NO-GO"
            if isinstance(node.func, ast.Name) and node.func.id in self.classes:
                return "list", f"iterating an instance of class '{node.func.id}' (not serializable)"
            return "list", None
        if isinstance(node, ast.Name):
            value = self._binding_value(node.id, line, fn)
            if value is None or (isinstance(value, ast.Name) and value.id == "__param__"):
                return "list", None
            return self._classify_iterable(value, line, fn, depth + 1)
        if isinstance(node, ast.Attribute):
            return "list", None
        return "list", f"unsupported iterable '{ast.unparse(node)[:60]}'"

    # ------------------------------------------------------------------ function analysis (R2/R3/R7/R8)
    def _module_refs(self, nodes: Iterable[ast.AST]) -> set[str]:
        refs: set[str] = set()
        for n in nodes:
            for sub in ast.walk(n):
                if isinstance(sub, (ast.Name, ast.Attribute)) and isinstance(getattr(sub, "ctx", None), ast.Load):
                    dotted = _dotted(sub)
                    if dotted and dotted.split(".")[0] in self.aliases:
                        refs.add(self.resolve(sub) or dotted)
        # keep only the longest chain per prefix (os.path.join beats os.path / os)
        return {r for r in refs if not any(o != r and o.startswith(r + ".") for o in refs)}

    def _allowed_module(self, ref: str) -> bool:
        return any(ref == a or ref.startswith(a + ".") for a in self.allowlist)

    def _called_user_functions(self, nodes: Iterable[ast.AST]) -> list[str]:
        out: list[str] = []
        for n in nodes:
            for sub in _walk_no_defs(n):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id in self.functions \
                        and sub.func.id not in out:
                    out.append(sub.func.id)
        return out

    def _function_closure(self, names: list[str]) -> list[str]:
        """User functions reachable from ``names`` (recursion allowed: it stays inside one task)."""
        seen: list[str] = []
        pending = list(names)
        while pending:
            name = pending.pop(0)
            if name in seen or name not in self.functions:
                continue
            seen.append(name)
            pending.extend(self._called_user_functions(self.functions[name].body))
        return seen

    def _check_function(self, name: str) -> str | None:
        """Why user function ``name`` may not run inside a task (R7), or None."""
        fn = self.functions[name]
        if name in self.duplicate_functions:
            return f"function '{name}' is defined more than once"
        if fn.decorator_list:
            return f"function '{name}' is decorated"
        declared = {n for g in _walk_no_defs(fn.body) if isinstance(g, (ast.Global, ast.Nonlocal)) for n in g.names}
        written = declared & _stored_names(fn.body)
        if written:
            return f"function '{name}' modifies global(s) {', '.join(sorted(written))}"
        local = self._function_locals(fn)
        for n in _walk_no_defs(fn.body):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _MUTATORS:
                base = _target_base(n.func.value)
                if base is not None and base.id not in local and base.id in self.module_stores:
                    return f"function '{name}' modifies the module-level object '{base.id}'"
            if isinstance(n, (ast.Assign, ast.AugAssign, ast.Delete)):
                targets = n.targets if isinstance(n, (ast.Assign, ast.Delete)) else [n.target]
                for t in targets:
                    base = _target_base(t)
                    if not isinstance(t, ast.Name) and base is not None and base.id not in local \
                            and base.id in self.module_stores:
                        return f"function '{name}' writes into the module-level object '{base.id}'"
        return None

    def _io_problem(self, nodes: list[ast.AST], split: str | None, loop_vars: set[str],
                    allow_open: bool) -> str | None:
        derived = set(loop_vars)
        for n in nodes:
            for sub in _walk_no_defs(n):
                if isinstance(sub, ast.Assign) and any(x.id in derived for x in _loads(sub.value)):
                    derived |= _stored_names(sub.targets)
        for n in nodes:
            for sub in _walk_no_defs(n):
                if not isinstance(sub, ast.Call):
                    continue
                name = self.resolve(sub.func) or ""
                attr = sub.func.attr if isinstance(sub.func, ast.Attribute) else ""
                if name == "input":
                    return f"input() on line {sub.lineno}: interactive input can't be split"
                if attr in ("write", "writelines"):
                    return f".{attr}() on line {sub.lineno}: tasks may not write files"
                if attr in ("seek", "tell"):
                    return f".{attr}() on line {sub.lineno}: random-access file reads can't be split"
                if name == "print" and any(k.arg == "file" for k in sub.keywords):
                    return f"print(file=...) on line {sub.lineno}: tasks may not write files"
                if name in ("open", "io.open", "codecs.open"):
                    mode = sub.args[1] if len(sub.args) > 1 else next((k.value for k in sub.keywords
                                                                       if k.arg == "mode"), None)
                    mode_s = mode.value if isinstance(mode, ast.Constant) and isinstance(mode.value, str) else "r"
                    if any(c in mode_s for c in "wax+"):
                        return f"open(..., '{mode_s}') on line {sub.lineno}: tasks may not write files"
                    if "b" in mode_s:
                        return f"binary open() on line {sub.lineno}: binary input is not split"
                    arg_names = {x.id for x in _loads(sub.args[0])} if sub.args else set()
                    if not (allow_open and split == "files" and arg_names & derived):
                        return (f"open() on line {sub.lineno}: files opened inside a region must come from a file "
                                "list iterated by the loop (SRS 5.3.4)")
        return None

    # ------------------------------------------------------------------ body analysis (R3-R6, R9, R10)
    def _analyze_body(self, region: Region, body: list[ast.stmt], loop_vars: set[str], fn: ast.FunctionDef | None,
                      loop: ast.AST, mode: str) -> dict[str, Any]:
        """Classify the names a region uses. ``mode`` is ``loop`` or ``thread`` (target function body)."""
        if mode == "thread":
            assert fn is not None
            locals_ = self._function_locals(fn)
            declared_global = {n for g in _walk_no_defs(fn.body) if isinstance(g, ast.Global) for n in g.names}
            outer = (set(self.module_stores) | set(self.aliases)) - locals_
            after: set[str] = set()
        else:
            outer = self._outer_bound(loop, fn)
            declared_global = set()
            if fn is not None:
                declared_global = {n for g in _walk_no_defs(fn.body) if isinstance(g, ast.Global) for n in g.names}
            after = self._reads_after(loop, fn)
            locals_ = set()

        # R3: dynamic name access
        for n in _walk_no_defs(body):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in _DYNAMIC_NAMES \
                    and n.func.id not in self.functions:
                raise _RegionFail("R3", f"{n.func.id}() on line {n.lineno} prevents classifying every name")
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "getattr" \
                    and len(n.args) >= 2 and not isinstance(n.args[1], ast.Constant):
                raise _RegionFail("R3", f"getattr() with a computed name on line {n.lineno}")
            if isinstance(n, ast.Nonlocal):
                raise _RegionFail("R4", f"nonlocal {', '.join(n.names)} on line {n.lineno}")
            if isinstance(n, (ast.Yield, ast.YieldFrom)):
                raise _RegionFail("R1", f"yield inside the region (line {n.lineno})")

        stored = _stored_names(body)
        accs: dict[str, Accumulator] = {}
        acc_stmts: dict[str, set[int]] = {}   # accumulator -> ids of statements allowed to read it
        first_match_vars: set[str] = set()
        has_break = False
        prints = False

        def is_outer(name: str) -> bool:
            if name in loop_vars:
                return False
            if mode == "thread":
                return name in outer and (name not in locals_ or name in declared_global)
            if name not in outer:
                return False
            if _first_use(body, name) == "store" and name not in after:
                return False  # rebound unconditionally each iteration and unused afterwards
            return True

        def derives(expr: ast.AST) -> bool:
            names = {x.id for x in _loads(expr)}
            return bool(names & (loop_vars | (stored - {a for a in accs})))

        def add_acc(name: str, kind: str, stmt: ast.stmt) -> None:
            prev = accs.get(name)
            if prev and prev.kind != kind and {prev.kind, kind} != {"dict", "counter"}:
                raise _RegionFail("R10", f"'{name}' is updated in two different ways ({prev.kind}, {kind})")
            if not prev or kind == "counter":
                accs[name] = Accumulator(name, kind, stmt.lineno)
            acc_stmts.setdefault(name, set()).add(id(stmt))

        def first_match_block(block: list[ast.stmt]) -> bool:
            return bool(block) and isinstance(block[-1], ast.Break) and all(
                isinstance(s, ast.Assign) and all(isinstance(t, ast.Name) for t in s.targets) for s in block[:-1])

        def visit(stmts: list[ast.stmt], in_first: bool = False, inner: bool = False) -> None:
            nonlocal has_break, prints
            for s in stmts:
                if isinstance(s, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                    raise _RegionFail("R10", f"definition of '{s.name}' inside the region (line {s.lineno})")
                if isinstance(s, ast.Return):
                    if mode == "loop":
                        raise _RegionFail("R10", f"return inside the loop (line {s.lineno}) matches no template")
                    continue
                if isinstance(s, (ast.Break, ast.Continue)) and inner:
                    continue  # leaves only the inner loop
                if isinstance(s, ast.Break):
                    if not in_first:
                        raise _RegionFail("R10", f"break on line {s.lineno} is not part of a first-match pattern "
                                                 "(if cond: result = x; break)")
                    has_break = True
                    continue
                if isinstance(s, ast.If):
                    top = mode == "loop" and not inner
                    visit(s.body, in_first=top and first_match_block(s.body), inner=inner)
                    visit(s.orelse, in_first=top and first_match_block(s.orelse), inner=inner)
                    continue
                if isinstance(s, (ast.For, ast.While)):
                    if s.orelse:
                        raise _RegionFail("R1", f"for/while ... else on line {s.lineno}")
                    visit(s.body, inner=True)  # inner loops: their own break leaves only the inner loop
                    continue
                if isinstance(s, ast.With):
                    # A lock around one accumulator update (checked by P1) is transparent.
                    visit(s.body, inner=inner)
                    continue
                if isinstance(s, ast.Try):
                    for block in (s.body, s.orelse, s.finalbody, *[h.body for h in s.handlers]):
                        visit(block, inner=inner)
                    continue
                self._classify_stmt(s, is_outer, derives, add_acc, first_match_vars, in_first, mode, declared_global)
                if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) and \
                        isinstance(s.value.func, ast.Name) and s.value.func.id == "print":
                    prints = True

        visit(body)
        for name in first_match_vars:
            if name in accs:
                raise _RegionFail("R10", f"'{name}' is both a first-match result and another accumulator")
            accs[name] = Accumulator(name, "first", region.line)

        # Mutating method calls anywhere on outer objects (other than recognized accumulator statements).
        allowed_ids = {i for ids in acc_stmts.values() for i in ids}
        for s in _walk_no_defs(body):
            if isinstance(s, ast.Call) and isinstance(s.func, ast.Attribute) and s.func.attr in _MUTATORS:
                base = _target_base(s.func.value)
                if base is not None and is_outer(base.id) and base.id not in self.lock_names:
                    parent_ok = any(id(st) in allowed_ids and st.value is s for st in _walk_no_defs(body)
                                    if isinstance(st, ast.Expr))
                    if not parent_ok:
                        raise _RegionFail("R4", f"'{base.id}.{s.func.attr}()' on line {s.lineno} changes an outer "
                                                "object that is not a recognized accumulator")

        # R5: accumulators read outside their own update statements.
        for name, acc in accs.items():
            if acc.kind == "first":
                continue
            allowed = acc_stmts.get(name, set())
            for s in _walk_no_defs(body):
                if isinstance(s, ast.stmt) and id(s) not in allowed and not isinstance(
                        s, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                    if any(x.id == name for x in _loads(s)):
                        raise _RegionFail("R5", f"'{name}' is read inside the region on line {s.lineno} while it "
                                                "accumulates results (carried dependency)")
                if isinstance(s, (ast.If, ast.While)) and any(x.id == name for x in _loads(s.test)):
                    raise _RegionFail("R5", f"'{name}' is read inside the region on line {s.lineno} while it "
                                            "accumulates results (carried dependency)")
                if isinstance(s, ast.For) and s is not loop and any(x.id == name for x in _loads(s.iter)):
                    raise _RegionFail("R5", f"'{name}' is read inside the region on line {s.lineno} while it "
                                            "accumulates results (carried dependency)")

        reads = {n.id for n in _loads(body)} - loop_vars
        outer_reads = sorted(n for n in reads if is_outer(n) and n not in accs and n not in self.functions
                             and n not in self.aliases and n not in self.lock_names
                             and n not in self.classes and n not in dir(builtins))
        if mode == "thread":
            outer_reads = [n for n in outer_reads if n in self.module_stores]
        return {"accs": accs, "outer_reads": outer_reads, "prints": prints, "has_break": has_break,
                "first_match_vars": first_match_vars}

    def _classify_stmt(self, s: ast.stmt, is_outer, derives, add_acc, first_vars: set[str], in_first: bool,
                       mode: str, declared_global: set[str]) -> None:
        line = s.lineno
        if isinstance(s, ast.Assign):
            for t in s.targets:
                if isinstance(t, (ast.Tuple, ast.List)):
                    for elt in t.elts:
                        if isinstance(elt, ast.Name) and is_outer(elt.id):
                            raise _RegionFail("R4", f"assignment to outer variable '{elt.id}' on line {line}")
                        if not isinstance(elt, ast.Name):
                            raise _RegionFail("R4", f"unpacking into '{ast.unparse(elt)}' on line {line}")
                elif isinstance(t, ast.Name):
                    if not is_outer(t.id):
                        continue
                    if mode == "thread" and t.id not in declared_global:
                        continue
                    if in_first:
                        first_vars.add(t.id)
                        continue
                    if isinstance(s.value, ast.BinOp) and isinstance(s.value.op, ast.Add) and \
                            isinstance(s.value.left, ast.Name) and s.value.left.id == t.id and \
                            t.id not in {x.id for x in _loads(s.value.right)}:
                        add_acc(t.id, "sum", s)
                        continue
                    if t.id in {x.id for x in _loads(s.value)}:
                        raise _RegionFail("R5", f"'{t.id}' is computed from its value in the previous iteration on "
                                                f"line {line} (carried dependency)")
                    raise _RegionFail("R4", f"assignment to outer variable '{t.id}' on line {line}")
                elif isinstance(t, ast.Attribute):
                    base = _target_base(t)
                    raise _RegionFail("R4", f"changes object attribute '{ast.unparse(t)}' on line {line}"
                                      if base is None or is_outer(base.id) else
                                      f"object attribute assignment on line {line} (class instances are NO-GO)")
                elif isinstance(t, ast.Subscript):
                    base = _target_base(t)
                    if base is None or not is_outer(base.id):
                        continue
                    if not isinstance(t.value, ast.Name):
                        raise _RegionFail("R4", f"nested item assignment into outer '{base.id}' on line {line}")
                    if not derives(t.slice):
                        raise _RegionFail("R4", f"'{base.id}[...]' on line {line} is not keyed by the loop variable")
                    reads_self = [x for x in _loads(s.value) if x.id == base.id]
                    if reads_self and not self._is_get_same_key(s.value, base.id, t.slice):
                        raise _RegionFail("R5", f"'{base.id}' is read while it is written on line {line} "
                                                "(carried dependency)")
                    add_acc(base.id, "counter" if reads_self else "dict", s)
        elif isinstance(s, ast.AugAssign):
            t = s.target
            base = _target_base(t)
            if base is None:
                raise _RegionFail("R4", f"unsupported augmented assignment on line {line}")
            if isinstance(t, ast.Attribute):
                raise _RegionFail("R4", f"changes object attribute '{ast.unparse(t)}' on line {line}")
            if not is_outer(base.id):
                return
            if mode == "thread" and isinstance(t, ast.Name) and base.id not in declared_global:
                return
            if base.id in {x.id for x in _loads(s.value)}:
                raise _RegionFail("R5", f"'{base.id}' is read while it is updated on line {line}")
            if isinstance(t, ast.Name):
                if not isinstance(s.op, (ast.Add, ast.Sub)):
                    raise _RegionFail("R5", f"'{base.id} {type(s.op).__name__}=' on line {line} depends on the "
                                            "previous iteration (only += / -= are reconstructed)")
                add_acc(base.id, "sum", s)
            else:
                if not isinstance(t.value, ast.Name) or not derives(t.slice):
                    raise _RegionFail("R4", f"'{ast.unparse(t)}' on line {line} is not keyed by the loop variable")
                if not isinstance(s.op, (ast.Add, ast.Sub)):
                    raise _RegionFail("R5", f"'{ast.unparse(t)}' updated with a non-additive operator")
                add_acc(base.id, "counter", s)
        elif isinstance(s, ast.AnnAssign):
            if isinstance(s.target, ast.Name) and is_outer(s.target.id):
                raise _RegionFail("R4", f"assignment to outer variable '{s.target.id}' on line {line}")
        elif isinstance(s, ast.Delete):
            for t in s.targets:
                base = _target_base(t)
                if base is not None and is_outer(base.id):
                    raise _RegionFail("R4", f"del of outer '{base.id}' on line {line}")
        elif isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) and isinstance(s.value.func, ast.Attribute):
            func = s.value.func
            if isinstance(func.value, ast.Name) and is_outer(func.value.id):
                name = func.value.id
                if func.attr in ("append", "extend"):
                    if any(x.id == name for a in s.value.args for x in _loads(a)):
                        raise _RegionFail("R5", f"'{name}' is read while it accumulates on line {line}")
                    add_acc(name, "list", s)
                elif func.attr == "add":
                    add_acc(name, "set", s)
        elif isinstance(s, ast.Global):
            return

    @staticmethod
    def _is_get_same_key(value: ast.AST, name: str, key: ast.AST) -> bool:
        """``d.get(k, 0) + expr`` or ``d[k] + expr`` with the same key k (a keyed counter)."""
        if not (isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add)):
            return False
        left = value.left
        same = ast.dump(key)
        if isinstance(left, ast.Call) and isinstance(left.func, ast.Attribute) and left.func.attr == "get" \
                and isinstance(left.func.value, ast.Name) and left.func.value.id == name and left.args:
            return ast.dump(left.args[0]) == same and name not in {x.id for x in _loads(value.right)}
        if isinstance(left, ast.Subscript) and isinstance(left.value, ast.Name) and left.value.id == name:
            return ast.dump(left.slice) == same and name not in {x.id for x in _loads(value.right)}
        return False

    # ------------------------------------------------------------------ region checks
    def check_loop(self, region: Region) -> None:
        loop: ast.For = region._node  # type: ignore[attr-defined]
        fn: ast.FunctionDef | None = region._fn  # type: ignore[attr-defined]
        loop_vars = _stored_names(loop.target)
        checks = region.checks

        # R1 region form
        if loop.orelse:
            raise _RegionFail("R1", "for ... else is not parallelized (SRS 2.5)")
        if not all(isinstance(n, (ast.Name, ast.Tuple, ast.List)) for n in ast.walk(loop.target)
                   if not isinstance(n, (ast.Store, ast.Load))):
            raise _RegionFail("R1", f"loop target '{ast.unparse(loop.target)}' must be plain names")
        split, why = self._classify_iterable(loop.iter, loop.lineno, fn)
        if why:
            raise _RegionFail("R1", why)
        region.split = split
        if split == "range":
            args = [_const_int(a) for a in loop.iter.args] if isinstance(loop.iter, ast.Call) else []
            if args and all(a is not None for a in args):
                region.iterations = len(range(*args))  # type: ignore[arg-type]
        checks.append(Check("R1", "pass", f"for over {ast.unparse(loop.iter)[:60]} → split: {split}"))

        # R2 libraries (region + called functions)
        called = self._function_closure(self._called_user_functions(loop.body))
        region.called_functions = called
        scope_nodes: list[ast.AST] = [*loop.body, *(self.functions[c] for c in called)]
        refs = self._module_refs(scope_nodes)
        region.modules = sorted(refs)
        bad = sorted(r for r in refs if not self._allowed_module(r))
        if bad:
            raise _RegionFail("R2", f"uses {', '.join(bad)} (not in the library allowlist: "
                                    f"{', '.join(self.allowlist)})")
        checks.append(Check("R2", "pass", f"modules: {', '.join(sorted(refs)) or 'none'}"))

        # R3-R5 classification, writes, carried dependencies
        info = self._analyze_body(region, loop.body, loop_vars, fn, loop, "loop")
        checks.append(Check("R3", "pass", "every name classified; no dynamic name access"))
        accs: dict[str, Accumulator] = info["accs"]
        checks.append(Check("R4", "pass", "writes: iteration-local variables" +
                            (f" + accumulators {', '.join(accs)}" if accs else "")))
        checks.append(Check("R5", "pass", "no iteration reads a value written by an earlier one"))

        # R6 global reads
        modified = sorted(n for n in info["outer_reads"] if self.global_writers.get(n, set()) & set(called))
        if modified:
            raise _RegionFail("R6", f"global(s) {', '.join(modified)} are modified by called functions")
        region.constants = info["outer_reads"]
        checks.append(Check("R6", "pass", f"read-only values copied as constants: "
                                          f"{', '.join(region.constants) or 'none'}"))

        # R7 called functions
        self._check_called(region, loop.body, called, fn)
        checks.append(Check("R7", "pass", f"functions: {', '.join(called) or 'none'}"))

        # R8 input / output
        problem = self._io_problem([*loop.body], split, loop_vars, allow_open=True) or \
            self._io_problem([self.functions[c] for c in called], split, set(), allow_open=False)
        if problem:
            raise _RegionFail("R8", problem)
        checks.append(Check("R8", "pass", "input can be split; no file writes or input()"))

        # R9 serializability
        self._check_serializable(accs, fn, loop.lineno)
        for acc in accs.values():
            if acc.kind == "sum" and acc.init is not None:
                if acc.init.startswith(("[", "list(")):
                    acc.kind = "list"  # x += [...] concatenates in iteration order
                elif acc.init.startswith(("'", '"', "str(")):
                    raise _RegionFail("R10", f"string concatenation into '{acc.name}' matches no template")
        checks.append(Check("R9", "pass", "chunks and results are JSON-serializable"))

        # R10 template match
        patterns = sorted({("dict" if a.kind == "counter" else a.kind) for a in accs.values()},
                          key=list(TEMPLATES).index)
        if info["prints"]:
            patterns.append("print")
        if not patterns:
            raise _RegionFail("R10", "no recognized accumulator or printed output: the tasks would return nothing")
        if "first" in patterns and len([p for p in patterns if p != "print"]) > 1:
            raise _RegionFail("R10", "a first-match loop may not also build other accumulators")
        region.patterns = patterns
        region.accumulators = list(accs.values())
        checks.append(Check("R10", "pass", " + ".join(TEMPLATES[p][0] for p in patterns)))

    def _check_called(self, region: Region, body: list[ast.stmt], called: list[str],
                      fn: ast.FunctionDef | None) -> None:
        for name in called:
            why = self._check_function(name)
            if why:
                raise _RegionFail("R7", why)
        local_names = _stored_names(body) | self._function_locals(fn) | set(self.module_stores)
        for node in [*body, *(self.functions[c] for c in called)]:
            for n in _walk_no_defs(node):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                    callee = n.func.id
                    if callee in self.classes:
                        raise _RegionFail("R9", f"creates an instance of class '{callee}' on line {n.lineno} "
                                                "(class instances are not serializable)")
                    if callee in self.functions or callee in self.aliases or callee in SAFE_BUILTINS:
                        continue
                    if callee in dir(builtins):
                        raise _RegionFail("R7", f"builtin {callee}() on line {n.lineno} is not allowed in a task")
                    if callee not in local_names:
                        raise _RegionFail("R7", f"call to unknown function '{callee}' on line {n.lineno}")

    def _check_serializable(self, accs: dict[str, Accumulator], fn: ast.FunctionDef | None, line: int) -> None:
        for acc in accs.values():
            value = self._binding_value(acc.name, line, fn)
            if value is None or (isinstance(value, ast.Name) and value.id == "__param__"):
                if acc.kind != "first":
                    raise _RegionFail("R9", f"accumulator '{acc.name}' has no visible initial value before the loop")
                continue
            acc.init = ast.unparse(value)[:80]
            if acc.kind == "first" or _is_literal(value) or isinstance(value, (ast.List, ast.Dict, ast.Set,
                                                                              ast.ListComp, ast.DictComp)):
                continue
            if isinstance(value, ast.Call) and (self.resolve(value.func) or "") in _JSON_CTORS:
                continue
            raise _RegionFail("R9", f"accumulator '{acc.name}' starts as '{acc.init}', which is not a "
                                    "JSON-serializable value (int, float, str, list, dict, set)")

    def check_sort(self, region: Region) -> None:
        call: ast.Call = region._call  # type: ignore[attr-defined]
        fn = region._fn  # type: ignore[attr-defined]
        target = call.args[0] if isinstance(call.func, ast.Name) else call.func.value  # type: ignore[union-attr]
        if not isinstance(target, ast.Name):
            raise _RegionFail("R1", "only sorted(name) / name.sort() on a list variable is distributed")
        kind, why = self._classify_iterable(target, region.line, fn)
        if why or kind not in ("list", "lines", "files"):
            raise _RegionFail("R1", why or f"'{target.id}' is not a list")
        region.split = "sort"
        region.checks.append(Check("R1", "pass", f"two-phase sort of '{target.id}' (FR-4.4)"))
        for k in call.keywords:
            if k.arg == "key":
                if isinstance(k.value, ast.Lambda):
                    raise _RegionFail("R9", "key=lambda can't be sent to Worker Nodes; use a function defined in "
                                            "the file or a builtin")
                if isinstance(k.value, ast.Name) and k.value.id in self.functions:
                    why_fn = self._check_function(k.value.id)
                    if why_fn:
                        raise _RegionFail("R7", why_fn)
                    region.called_functions = self._function_closure([k.value.id])
                elif not (isinstance(k.value, ast.Name) and k.value.id in SAFE_BUILTINS) and \
                        not (self.resolve(k.value) or "").startswith(tuple(self.allowlist)):
                    raise _RegionFail("R7", f"sort key '{ast.unparse(k.value)}' must be a builtin or a function "
                                            "defined in the file")
            elif k.arg != "reverse":
                raise _RegionFail("R1", f"unsupported sort argument '{k.arg}'")
        if region.called_functions:  # read-only globals of the key function are copied into the template
            reads = {x.id for c in region.called_functions for x in _loads(self.functions[c].body)}
            glob = sorted(n for n in reads if n in self.module_stores and n not in self.functions
                          and n not in self.import_nodes)
            bad = [n for n in glob if not self._static_const(n)]
            if bad:
                raise _RegionFail("R9", f"the sort key reads {', '.join(bad)}, computed at run time; only constants "
                                        "can be copied to Worker Nodes")
            region.constants = glob
        for cid in ("R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"):
            region.checks.append(Check(cid, "pass", "built-in sort of plain data"))
        region.patterns = ["sort"]
        region.checks.append(Check("R10", "pass", "Sort (two-phase: chunk sort + merge on the Master)"))

    # ------------------------------------------------------------------ thread groups
    def _thread_regions(self) -> list[Region]:
        regions: list[Region] = []
        creations: dict[str, list[ast.Call]] = {}
        unresolved: list[ast.Call] = []
        maps: list[ast.Call] = []
        submits: dict[str, list[ast.Call]] = {}
        for n in ast.walk(self.tree):
            if not isinstance(n, ast.Call):
                continue
            if self.resolve(n.func) == "threading.Thread":
                target = self._thread_target(n)
                if isinstance(target, ast.Name):
                    creations.setdefault(target.id, []).append(n)
                else:
                    unresolved.append(n)
            elif isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) \
                    and n.func.value.id in self.executor_names:
                if n.func.attr == "map":
                    maps.append(n)
                elif n.func.attr == "submit" and n.args and isinstance(n.args[0], ast.Name):
                    submits.setdefault(n.args[0].id, []).append(n)
        joins = [n.lineno for n in ast.walk(self.tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr in ("join", "result") and not n.args]
        # SRS 5.3.2: the join point of Patterns B and C is the end of the executor's with block (or the last
        # result()); the region - and so the T_seq timing markers of FR-5.5 - must reach it.
        with_ends = [(w.lineno, w.end_lineno or w.lineno) for w in ast.walk(self.tree) if isinstance(w, ast.With)
                     and any(isinstance(i.context_expr, ast.Call)
                             and (self.resolve(i.context_expr.func) or "").endswith("ThreadPoolExecutor")
                             for i in w.items)]

        def join_point(first: int, last: int) -> int:
            end = max([last] + [j for j in joins if j >= first])
            enclosing = [e for b, e in with_ends if b <= first <= e]
            return max([end] + enclosing)
        for target, calls in creations.items():
            line = min(c.lineno for c in calls)
            end = max([c.end_lineno or c.lineno for c in calls] + [j for j in joins if j >= line] or [line])
            r = Region(0, "thread-group", line, end, "<program>", self.snippet(line), thread_pattern="A")
            r._target, r._calls = target, calls  # type: ignore[attr-defined]
            regions.append(r)
        for call in unresolved:
            r = Region(0, "thread-group", call.lineno, call.end_lineno or call.lineno, "<program>",
                       self.snippet(call.lineno), thread_pattern="A")
            r.checks = [Check("R1", "fail", "thread target must be a function defined in this file")]
            r.failed_check, r.reason = "R1", "thread target must be a function defined in this file"
            regions.append(r)
        for call in maps:
            target = call.args[0] if call.args else None
            r = Region(0, "executor-map", call.lineno, join_point(call.lineno, call.end_lineno or call.lineno), "<program>",
                       self.snippet(call.lineno), thread_pattern="B")
            r._target = target.id if isinstance(target, ast.Name) else None  # type: ignore[attr-defined]
            r._calls = [call]  # type: ignore[attr-defined]
            regions.append(r)
        for target, calls in submits.items():
            line = min(c.lineno for c in calls)
            r = Region(0, "executor-submit", line, join_point(line, max(c.end_lineno or c.lineno for c in calls)),
                       "<program>",
                       self.snippet(line), thread_pattern="C")
            r._target, r._calls = target, calls  # type: ignore[attr-defined]
            regions.append(r)
        return regions

    def check_thread_group(self, region: Region) -> None:
        target = region._target  # type: ignore[attr-defined]
        calls: list[ast.Call] = region._calls  # type: ignore[attr-defined]
        if target is None or target not in self.functions:
            raise _RegionFail("R1", f"thread target '{target}' must be a function defined in this file "
                                    "(lambdas, methods and imports can't be shipped)")
        fn = self.functions[target]
        if fn.args.vararg or fn.args.kwarg:
            pass
        region.split = "map" if region.kind == "executor-map" else "threads"
        pattern_txt = {"A": "Thread(target=f, args=...) started and joined", "B": "ThreadPoolExecutor.map(f, items)",
                       "C": "ThreadPoolExecutor.submit(f, x) + result() in submission order"}
        region.checks.append(Check("R1", "pass", f"Pattern {region.thread_pattern}: "
                                                 f"{pattern_txt[region.thread_pattern or 'A']}; target '{target}'"))
        called = self._function_closure([target])
        region.called_functions = called
        refs = self._module_refs([self.functions[c] for c in called])
        refs = {r for r in refs if not r.startswith(("threading.", "concurrent."))}
        region.modules = sorted(refs)
        bad = sorted(r for r in refs if not self._allowed_module(r))
        if bad:
            raise _RegionFail("R2", f"target uses {', '.join(bad)} (not in the library allowlist)")
        region.checks.append(Check("R2", "pass", f"modules: {', '.join(sorted(refs)) or 'none'}"))
        args = fn.args
        params = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
        info = self._analyze_body(region, fn.body, params, fn, fn, "thread")
        accs: dict[str, Accumulator] = info["accs"]
        region.checks.append(Check("R3", "pass", "every name classified; no dynamic name access"))
        region.checks.append(Check("R4", "pass", "target writes only its locals" +
                                   (f" and accumulators {', '.join(accs)}" if accs else "")))
        region.checks.append(Check("R5", "pass", "threads do not read each other's results while running"))
        modified = sorted(n for n in info["outer_reads"] if self.global_writers.get(n, set()) & set(called))
        if modified:
            raise _RegionFail("R6", f"global(s) {', '.join(modified)} are modified by the thread functions")
        region.constants = info["outer_reads"]
        region.checks.append(Check("R6", "pass", f"read-only values copied as constants: "
                                                 f"{', '.join(region.constants) or 'none'}"))
        for name in called:
            if name == target:
                continue
            why = self._check_function(name)
            if why:
                raise _RegionFail("R7", why)
        self._check_called(region, fn.body, [c for c in called if c != target], fn)
        region.checks.append(Check("R7", "pass", f"functions: {', '.join(called)}"))
        problem = self._io_problem([self.functions[c] for c in called], None, set(), allow_open=False)
        if problem:
            raise _RegionFail("R8", problem)
        region.checks.append(Check("R8", "pass", "no file writes or input() in the thread functions"))
        for call in calls:
            arg_nodes = self._thread_args(call) if region.thread_pattern == "A" else call.args[1:]
            for a in arg_nodes:
                for sub in ast.walk(a):
                    if isinstance(sub, ast.Lambda):
                        raise _RegionFail("R9", f"lambda passed to a thread on line {call.lineno}")
                    if isinstance(sub, ast.Name) and (sub.id in self.lock_names or sub.id in self.executor_names):
                        raise _RegionFail("R9", f"'{sub.id}' (a lock/executor) can't be sent to a Worker Node")
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id in self.classes:
                        raise _RegionFail("R9", f"class instance passed to a thread on line {call.lineno}")
                    if isinstance(sub, ast.Name):
                        bound = self._binding_value(sub.id, call.lineno, None)
                        if isinstance(bound, ast.Call) and (self.resolve(bound.func) or "") in ("open", "io.open"):
                            raise _RegionFail("R9", f"file handle '{sub.id}' passed to a thread")
        self._check_serializable({k: v for k, v in accs.items()}, None, region.line)
        region.checks.append(Check("R9", "pass", "thread arguments and results are JSON-serializable"))
        region.patterns = ["thread"] + sorted({("dict" if a.kind == "counter" else a.kind) for a in accs.values()},
                                              key=list(TEMPLATES).index)
        if info["prints"]:
            region.patterns.append("print")
        region.accumulators = list(accs.values())
        region.checks.append(Check("R10", "pass", " + ".join(TEMPLATES[p][0] for p in region.patterns)))

    # ------------------------------------------------------------------ T1: templates + rewrite
    def _packaging(self, region: Region, nodes: list[ast.AST]) -> list[str]:
        out: list[str] = []
        needed = {x.id for n in nodes for x in _loads(n)} | {
            x.id for c in region.called_functions for x in _loads(self.functions[c].body)}
        for acc in region.accumulators:  # e.g. Counter() / defaultdict(int) initialisers
            if acc.init:
                try:
                    needed |= {x.id for x in _loads(ast.parse(acc.init, mode="eval"))}
                except SyntaxError:
                    pass
        for name, imp in self.import_nodes.items():
            if name in needed and not self.resolve(ast.Name(name, ast.Load())).startswith(("threading", "concurrent")):
                out.append(ast.unparse(imp))
        for name in region.constants:
            if self._static_const(name):  # read-only global copied into the template (FR-3.8)
                stmt = self.module_stores[name][0]
                for x in _loads(stmt.value):  # e.g. the "re" of re.compile(...)
                    if x.id in self.import_nodes and ast.unparse(self.import_nodes[x.id]) not in out:
                        out.insert(1, ast.unparse(self.import_nodes[x.id]))
                out.append(ast.unparse(stmt))
        for name in region.called_functions:
            fn = copy.deepcopy(self.functions[name])
            out.append(ast.unparse(_StripLocks(self.lock_names).visit(fn)))
        return out

    def _static_value(self, node: ast.AST) -> bool:
        """A value the task template can rebuild itself: a literal, or an allowlisted call with literal args."""
        if _is_literal(node):
            return True
        if isinstance(node, ast.Call):
            ref = self.resolve(node.func) or ""
            return ("." in ref and self._allowed_module(ref) and all(_is_literal(a) for a in node.args)
                    and all(k.arg and _is_literal(k.value) for k in node.keywords))
        return False

    def _static_const(self, name: str) -> bool:
        stmts = self.module_stores.get(name, [])
        return (len(stmts) == 1 and isinstance(stmts[0], ast.Assign) and len(stmts[0].targets) == 1
                and isinstance(stmts[0].targets[0], ast.Name) and self._static_value(stmts[0].value))

    def _runtime_consts(self, region: Region) -> list[str]:
        return [n for n in region.constants if not self._static_const(n)]

    def build_loop_template(self, region: Region) -> None:
        loop: ast.For = copy.deepcopy(region._node)  # type: ignore[attr-defined]
        task = f"task_{region.index}"
        region.task_name = task
        lines = ["# task template (sent to Worker Nodes): plain data in, plain data out", *self._packaging(
            region, [region._node])]  # type: ignore[attr-defined]
        body: list[str] = []
        for name in self._runtime_consts(region):
            body.append(f"{name} = __consts__[{name!r}]")
        for acc in region.accumulators:
            init = {"list": "[]", "set": "set()", "sum": "0", "first": "None"}.get(acc.kind)
            if acc.kind in ("dict", "counter"):
                init = acc.init if acc.init and acc.init.split("(")[0].split(".")[-1] in (
                    "Counter", "defaultdict", "OrderedDict", "dict") else "{}"
            body.append(f"{acc.name} = {init}")
        first = any(a.kind == "first" for a in region.accumulators)
        if first:
            body.append("__match__ = None")
            _MarkFirstMatch().visit(loop)
        if region.split == "files":
            body += ["import io", "__files__ = dict(chunk['files'])",
                     "def __open_chunk_file__(name, *args, **kwargs):",
                     "    return io.StringIO(__files__[name])"]
            loop = _RedirectOpen().visit(loop)
        target = ast.unparse(loop.target)
        if region.split == "range":
            header = f"for __index__, {target} in enumerate(range(chunk['start'], chunk['stop'], chunk['step']), " \
                     "chunk['first_index']):"
        elif region.split == "files":
            header = f"for __index__, {target} in enumerate([name for name, _ in chunk['files']], chunk['start']):"
        else:
            header = f"for __index__, {target} in enumerate(chunk['items'], chunk['start']):"
        body.append(header)
        loop_body = ast.unparse(ast.Module(body=loop.body, type_ignores=[]))
        body += ["    " + ln for ln in loop_body.splitlines()]
        ret = []
        for acc in region.accumulators:
            if acc.kind == "set":
                ret.append(f"{acc.name!r}: sorted({acc.name}, key=repr)")
            elif acc.kind in ("dict", "counter"):
                ret.append(f"{acc.name!r}: [[k, v] for k, v in {acc.name}.items()]")
            elif acc.kind != "first":
                ret.append(f"{acc.name!r}: {acc.name}")
        if first:
            names = ", ".join(f"{a.name!r}: {a.name}" for a in region.accumulators if a.kind == "first")
            ret.append(f"'__match__': None if __match__ is None else {{'index': __match__, 'values': {{{names}}}}}")
        body.append("return {" + ", ".join(ret) + "}")
        lines.append(f"def {task}(chunk, __consts__=None):")
        lines += ["    " + b for b in body]
        region.task_template = "\n".join(lines) + "\n"
        region.rewrite = self._loop_rewrite(region)

    def _loop_rewrite(self, region: Region) -> str:
        loop: ast.For = region._node  # type: ignore[attr-defined]
        res = f"__r{region.index}__"
        acc = ", ".join(f"{a.name!r}: {a.kind!r}" for a in region.accumulators)
        consts = ", ".join(f"{n!r}: {n}" for n in self._runtime_consts(region))
        out = [f"{res} = __mediator__.run_region({region.task_name!r}, {ast.unparse(loop.iter)}, "
               f"split={region.split!r}, acc={{{acc}}}, consts={{{consts}}})"]
        for a in region.accumulators:
            if a.kind == "list":
                out.append(f"{a.name}.extend({res}[{a.name!r}])")
            elif a.kind == "sum":
                out.append(f"{a.name} += {res}[{a.name!r}]")
            elif a.kind == "set":
                out.append(f"{a.name}.update({res}[{a.name!r}])")
            elif a.kind == "counter":
                out.append(f"for __k__, __v__ in {res}[{a.name!r}]:\n    {a.name}[__k__] = "
                           f"{a.name}.get(__k__, 0) + __v__")
            elif a.kind == "dict":
                out.append(f"for __k__, __v__ in {res}[{a.name!r}]:\n    {a.name}[__k__] = __v__")
        firsts = [a for a in region.accumulators if a.kind == "first"]
        if firsts:
            assigns = "\n".join(f"    {a.name} = {res}['__match__']['values'][{a.name!r}]" for a in firsts)
            out.append(f"if {res}['__match__'] is not None:\n{assigns}")
        return "\n".join(out)

    def build_sort_template(self, region: Region) -> None:
        call: ast.Call = region._call  # type: ignore[attr-defined]
        node = region._node  # type: ignore[attr-defined]
        task = f"task_{region.index}"
        region.task_name = task
        kw = ", ".join(ast.unparse(k) for k in call.keywords)
        helpers = [ast.unparse(self.functions[c]) for c in region.called_functions]
        key = next((k.value for k in call.keywords if k.arg == "key"), None)
        rev = next((ast.unparse(k.value) for k in call.keywords if k.arg == "reverse"), "False")
        if key is None:
            body = [f"    return sorted(chunk['items']{', ' + kw if kw else ''})"]
        else:  # each key is computed once, on the Worker Node; the Master merges on the returned keys
            body = [f"    __key__ = {ast.unparse(key)}",
                    "    __pairs__ = [[__key__(x), x] for x in chunk['items']]",
                    f"    __pairs__.sort(key=lambda p: p[0], reverse={rev})",
                    "    return __pairs__"]
        region.task_template = "\n".join([
            "# task template (Phase 1 on Worker Nodes): sort one chunk", *self._packaging(region, [call]),
            f"def {task}(chunk, __consts__=None):", *body, ""]) if key is not None else "\n".join([
            "# task template (Phase 1 on Worker Nodes): sort one chunk", *helpers,
            f"def {task}(chunk, __consts__=None):", *body, ""])
        target = call.args[0] if isinstance(call.func, ast.Name) else call.func.value  # type: ignore[union-attr]
        merged = f"__mediator__.run_sort({task!r}, {ast.unparse(target)}{', ' + kw if kw else ''})"
        if isinstance(node, ast.Assign):
            region.rewrite = f"{', '.join(ast.unparse(t) for t in node.targets)} = {merged}"
        else:
            region.rewrite = f"{ast.unparse(target)}[:] = {merged}"

    def build_thread_template(self, region: Region) -> None:
        target = region._target  # type: ignore[attr-defined]
        task = f"task_{region.index}"
        region.task_name = task
        lines = ["# task template (sent to Worker Nodes): no thread is created; the target runs as a direct call",
                 *[x for x in self._packaging(region, [self.functions[target]])]]
        for acc in region.accumulators:
            init = {"list": "[]", "set": "set()", "sum": "0"}.get(acc.kind, "{}")
            lines.append(f"{acc.name} = {init}")
        ret = ", ".join([f"{a.name!r}: " + (f"sorted({a.name}, key=repr)" if a.kind == "set" else
                                            f"[[k, v] for k, v in {a.name}.items()]" if a.kind in ("dict", "counter")
                                            else a.name) for a in region.accumulators])
        if region.thread_pattern == "B":
            lines += [f"def {task}(chunk, __consts__=None):",
                      f"    __returns__ = [{target}(item) for item in chunk['items']]",
                      f"    return {{'__return__': __returns__{', ' + ret if ret else ''}}}"]
        else:
            lines += [f"def {task}(args, kwargs=None, __consts__=None):",
                      f"    __return__ = {target}(*args, **(kwargs or {{}}))",
                      f"    return {{'__return__': __return__{', ' + ret if ret else ''}}}"]
        region.task_template = "\n".join(lines) + "\n"
        if region.thread_pattern == "B":
            call = region._calls[0]  # type: ignore[attr-defined]
            region.rewrite = f"{ast.unparse(call)}  →  __mediator__.run_map({task!r}, " \
                             f"{ast.unparse(call.args[1]) if len(call.args) > 1 else '[]'})"

    def compile_check(self, region: Region) -> None:
        for label, code in (("task template", region.task_template), ("rewrite", region.rewrite)):
            if not code or "→" in code:
                continue
            try:
                compile(code, f"<{region.task_name}:{label}>", "exec")
            except SyntaxError as exc:
                raise _RegionFail("T1", f"generated {label} does not compile: {exc.msg} (line {exc.lineno})")
        region.checks.append(Check("T1", "pass", "task template and rewritten region compile"))

    def transformed_program(self, regions: list[Region]) -> str | None:
        """The program with every GO loop / sort region replaced by its Mediator call (FR-1.7 view)."""
        targets = {(r.line, r.kind): r for r in regions if r.decision == "GO" and r.kind in ("for-loop", "sort")
                   and r.rewrite}
        threads = [r for r in regions if r.decision == "GO" and r.kind in ("thread-group", "executor-map",
                                                                             "executor-submit")]
        if not targets and not threads:
            return None
        tree = ast.parse(self.source, self.filename)

        class Rewriter(ast.NodeTransformer):
            def generic_visit(self, node: ast.AST) -> ast.AST:
                for fname, value in ast.iter_fields(node):
                    if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
                        new: list[ast.stmt] = []
                        for stmt in value:
                            kind = "for-loop" if isinstance(stmt, ast.For) else "sort"
                            region = targets.get((stmt.lineno, kind))
                            if region is not None:
                                marker = ast.Expr(ast.Constant(f"region {region.id}: {region.kind} → cluster "
                                                               f"({' + '.join(TEMPLATES[p][0] for p in region.patterns)})"))
                                new.append(marker)
                                new.extend(ast.parse(region.rewrite or "pass").body)
                            else:
                                new.append(self.visit(stmt))
                        setattr(node, fname, new)
                    elif isinstance(value, ast.AST):
                        self.visit(value)
                return node

        tree = Rewriter().visit(tree)
        if threads:
            # SRS 5.3.2 step 6: the Thread / executor objects are replaced by Mediator stand-ins. start() records
            # the call, join() / result() / the end of the with block send one task per thread (or per chunk)
            # at the join point and assign the aggregated accumulators back. Threads of other targets keep
            # running as written.
            resolve = self.resolve

            class ThreadSwap(ast.NodeTransformer):
                def visit_Call(self, node: ast.Call) -> ast.Call:
                    self.generic_visit(node)
                    name = {"threading.Thread": "Thread",
                            "concurrent.futures.ThreadPoolExecutor": "Executor"}.get(resolve(node.func) or "")
                    if name:
                        node.func = ast.Attribute(ast.Name("__mediator__", ast.Load()), name, ast.Load())
                    return node

            tree = ThreadSwap().visit(tree)
        ast.fix_missing_locations(tree)
        text = "# Transformed program (runs on the Master; GO regions call the Mediator)\n" + ast.unparse(tree) + "\n"
        compile(text, "<transformed>", "exec")
        return text

    # ------------------------------------------------------------------ test suites (extension)
    def unittest_cases(self) -> list[str]:
        """``Class.test_method`` ids of the unittest.TestCase classes defined in this module.

        Extension beyond the SRS v1 region patterns: unittest guarantees that test methods are independent
        (each gets a fresh TestCase instance), so a test module is distributed one test method per task.
        """
        cases: list[str] = []
        for cls in self.tree.body:
            if not isinstance(cls, ast.ClassDef):
                continue
            bases = {self.resolve(b) or "" for b in cls.bases}
            if not bases & {"unittest.TestCase", "unittest.case.TestCase"}:
                continue
            for fn in cls.body:
                if isinstance(fn, ast.FunctionDef) and fn.name.startswith("test"):
                    cases.append(f"{cls.name}.{fn.name}")
        return cases

    # ------------------------------------------------------------------ driver
    def analyze(self) -> dict[str, Any]:
        started = time.perf_counter()
        program_checks: list[Check] = []
        regions: list[Region] = []
        bad = self.scan_concurrency()
        if bad:
            program_checks.append(Check("P1", "fail", "; ".join(bad[:6])))
            program_checks.append(Check("P2", "skip", "not reached: the program is not eligible (P1)"))
        else:
            supported = [i for i in self.concurrency if i.supported]
            program_checks.append(Check("P1", "pass", "supported thread patterns only" if supported
                                        else "no thread or process constructs"))
            regions = self.collect_regions()
            candidates = [r for r in regions if r.kind != "while-loop"]
            if not candidates:
                program_checks.append(Check("P2", "fail", "no candidate region (for loop, sort call or thread group)"))
            else:
                program_checks.append(Check("P2", "pass", f"{len(candidates)} candidate region(s)"))
            for region in regions:
                if region.failed_check:
                    continue
                try:
                    if region.kind == "for-loop":
                        self.check_loop(region)
                        self.build_loop_template(region)
                    elif region.kind == "sort":
                        self.check_sort(region)
                        self.build_sort_template(region)
                    else:
                        self.check_thread_group(region)
                        self.build_thread_template(region)
                    self.compile_check(region)
                    region.decision = "GO"
                    region.reason = f"{' + '.join(TEMPLATES[p][0] for p in region.patterns)}; split: {region.split}"
                    region.planned_tasks = self.chunk_factor * self.worker_nodes
                    if region.iterations is not None:
                        region.planned_tasks = max(1, min(region.planned_tasks, region.iterations))
                    if region.kind == "thread-group":
                        region.planned_tasks = None  # one task per thread, known at run time
                except _RegionFail as fail:
                    region.decision, region.failed_check, region.reason = "NO-GO", fail.check, fail.reason
                    region.checks.append(Check(fail.check, "fail", fail.reason))
                    region.task_template = region.rewrite = None
                except (RecursionError, ValueError, TypeError, SyntaxError) as exc:
                    region.decision, region.failed_check = "NO-GO", "R3"
                    region.reason = f"analysis could not complete ({type(exc).__name__}); kept sequential"
                    region.checks.append(Check("R3", "fail", region.reason))
                    region.task_template = region.rewrite = None
        go = [r for r in regions if r.decision == "GO"]
        nogo = [r for r in regions if r.decision != "GO"]
        if any(c.status == "fail" for c in program_checks) or not go:
            verdict = "NOT_ELIGIBLE"
        elif nogo:
            verdict = "PARTIALLY_ELIGIBLE"
        else:
            verdict = "ELIGIBLE"
        transformed = None
        try:
            transformed = self.transformed_program(regions) if go else None
        except (SyntaxError, ValueError, RecursionError):
            transformed = None
        test_suite = None
        cases = self.unittest_cases()
        summary = self._summary(verdict, program_checks, go, nogo)
        if cases and not go:  # a test module: its unit of parallel work is the test method
            test_suite = {"framework": "unittest", "cases": cases}
            verdict = "TEST_SUITE"
            summary = (f"unittest suite: {len(cases)} test method(s) run as independent tasks on the Worker Nodes "
                       f"(test-suite extension; no loop or thread region could be distributed: "
                       f"{summary.split(': ', 1)[-1][:160]})")
        return {
            "version": ELIGIBILITY_VERSION,
            "verdict": verdict,
            "eligible": verdict != "NOT_ELIGIBLE",
            "summary": summary,
            "test_suite": test_suite,
            "program_checks": [c.to_dict() for c in program_checks],
            "regions": [r.to_dict() for r in regions],
            "go_regions": len(go),
            "nogo_regions": len(nogo),
            "concurrency": [i.to_dict() for i in self.concurrency],
            "uses_threads": any(i.kind in ("thread", "executor") for i in self.concurrency),
            "uses_processes": any(i.kind in ("process", "async") for i in self.concurrency),
            "transformed_program": transformed,
            "cluster_plan": {"worker_nodes": self.worker_nodes, "chunk_factor": self.chunk_factor,
                             "tasks_per_region": self.chunk_factor * self.worker_nodes,
                             "library_allowlist": list(self.allowlist)},
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }

    @staticmethod
    def _summary(verdict: str, program_checks: list[Check], go: list[Region], nogo: list[Region]) -> str:
        failed = next((c for c in program_checks if c.status == "fail"), None)
        if failed:
            return f"Not eligible ({failed.id} {failed.name}): {failed.detail}"
        if not go:
            reasons = "; ".join(f"{r.id} line {r.line}: {r.reason}" for r in nogo[:3])
            return f"Not eligible for parallelization: no GO region. {reasons}".strip()
        kinds = sorted({p for r in go for p in r.patterns}, key=list(TEMPLATES).index)
        text = f"{len(go)} of {len(go) + len(nogo)} region(s) run on the cluster " \
               f"({', '.join(TEMPLATES[k][0] for k in kinds)})"
        if nogo:
            text += f"; {len(nogo)} stay sequential on the Master"
        return text


class _StripLocks(ast.NodeTransformer):
    """Remove ``with lock:`` around accumulator updates (SRS 5.3.2 step 6): a task runs alone."""

    def __init__(self, lock_names: set[str]) -> None:
        self.lock_names = lock_names

    def visit_With(self, node: ast.With) -> Any:
        self.generic_visit(node)
        if any(isinstance(i.context_expr, ast.Name) and i.context_expr.id in self.lock_names for i in node.items):
            return node.body
        return node


class _MarkFirstMatch(ast.NodeTransformer):
    """Record the iteration index just before the first-match ``break``."""

    def __init__(self) -> None:
        self.depth = 0

    def visit_For(self, node: ast.For) -> ast.For:
        if self.depth:  # an inner loop's break leaves only that loop
            return node
        self.depth += 1
        node.body = [self.visit(s) for s in node.body]
        self.depth -= 1
        return node

    def visit_If(self, node: ast.If) -> ast.If:
        for block in ("body", "orelse"):
            stmts = getattr(node, block)
            if stmts and isinstance(stmts[-1], ast.Break):
                stmts.insert(len(stmts) - 1, ast.parse("__match__ = __index__").body[0])
            else:
                setattr(node, block, [self.visit(s) for s in stmts])
        return node

    def visit_While(self, node: ast.While) -> ast.While:
        return node


class _RedirectOpen(ast.NodeTransformer):
    """In a file-list task, ``open(path)`` reads the content shipped in the chunk instead of the disk."""

    def visit_Call(self, node: ast.Call) -> ast.Call:
        self.generic_visit(node)
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            node.func = ast.Name("__open_chunk_file__", ast.Load())
        return node


def analyze_eligibility(source: str, filename: str = "<input>", allowlist: Iterable[str] = DEFAULT_ALLOWLIST,
                        chunk_factor: int = 4, worker_nodes: int = 1) -> dict[str, Any]:
    """Go/No-Go report for one program (JSON-serialisable). Raises SyntaxError on invalid code."""
    return EligibilityAnalyzer(source, filename, allowlist, chunk_factor, worker_nodes).analyze()
