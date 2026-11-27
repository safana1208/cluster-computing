"""Mandatory rule-based SAST policy for programs submitted to the cluster (SRS Table 3.2.1).

The rest of this package (AST Master + the built-in extractor, fused with the ML models in
``ai_engine``) answers "does this look like a supply-chain attack?". It is tuned on packages
and deliberately tolerant of, for example, a helper that calls ``os.system`` at run time.
A program that will be shipped to Worker Nodes needs a stricter, deterministic gate: it may
not run commands, open sockets, modify files, escalate privileges, tamper with the
interpreter, or deserialize untrusted data. This module is that gate.

* Standard library only, never executes the analysed code.
* Import aliases are resolved before matching (``import os as o``, ``from subprocess import run``),
  as are ``__import__("os").system`` and ``getattr(__builtins__, "ex" + "ec")``.
* *References* are matched, not only calls, so ``f = os.system; f("...")`` is caught.
* Threads, processes and asyncio are **not** security violations (SRS 3.2): eligibility for
  parallel execution is decided separately.

Usage::

    report = screen_source(source, "job.py")
    report.blocked          # True when any finding has action "block"
    report.to_dict()        # JSON-serialisable: verdict, findings (rule, category, severity, line, ...)
"""

from __future__ import annotations

import ast
import re
import time
from dataclasses import asdict, dataclass, field

POLICY_VERSION = 2

#: category -> (title, default severity). Every category except obfuscation blocks.
CATEGORIES: dict[str, tuple[str, str]] = {
    "dynamic-exec": ("Dynamic code execution", "critical"),
    "os-command": ("OS command execution", "critical"),
    "network": ("Network access", "high"),
    "fs-modify": ("File system modification", "high"),
    "privilege": ("Privilege escalation", "critical"),
    "hooking": ("Hooking and interpreter tampering", "high"),
    "deserialization": ("Unsafe deserialization", "high"),
    "process-control": ("Low-level process control", "high"),
    "obfuscation": ("Obfuscation", "medium"),
}

# Modules whose import alone is a violation (matched on the dotted prefix).
_BLOCKED_MODULES: dict[str, str] = {
    **dict.fromkeys(("importlib", "runpy", "code", "codeop"), "dynamic-exec"),
    **dict.fromkeys(("subprocess", "pty", "commands"), "os-command"),
    **dict.fromkeys((
        "socket", "socketserver", "ssl", "urllib", "urllib2", "urllib3", "http", "requests", "httpx", "aiohttp",
        "ftplib", "smtplib", "telnetlib", "poplib", "imaplib", "nntplib", "xmlrpc", "websocket", "websockets",
        "paramiko", "webbrowser",
    ), "network"),
    **dict.fromkeys(("ctypes", "_ctypes", "cffi"), "hooking"),
    **dict.fromkeys(("marshal", "shelve", "dill", "cPickle", "_pickle", "jsonpickle"), "deserialization"),
    **dict.fromkeys(("signal",), "process-control"),
}

# Fully qualified names (after alias resolution) that are violations wherever they are referenced.
_BLOCKED_NAMES: dict[str, str] = {
    **dict.fromkeys((
        "eval", "exec", "compile", "__import__", "execfile",
        "builtins.eval", "builtins.exec", "builtins.compile", "builtins.__import__",
    ), "dynamic-exec"),
    **dict.fromkeys((
        "os.system", "os.popen", "os.posix_spawn", "os.posix_spawnp", "os.startfile", "platform.popen",
        "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
    ), "os-command"),
    **dict.fromkeys(("asyncio.open_connection", "asyncio.start_server", "asyncio.open_unix_connection"), "network"),
    **dict.fromkeys((
        "os.remove", "os.unlink", "os.rename", "os.renames", "os.replace", "os.rmdir", "os.removedirs",
        "os.chmod", "os.lchmod", "os.fchmod", "os.chown", "os.lchown", "os.fchown", "os.chflags", "os.truncate",
        "os.link", "os.symlink", "os.mkfifo", "os.mknod", "shutil.rmtree", "shutil.move", "shutil.copy",
        "shutil.copy2", "shutil.copyfile", "shutil.copytree", "shutil.chown",
    ), "fs-modify"),
    **dict.fromkeys((
        "os.setuid", "os.setgid", "os.seteuid", "os.setegid", "os.setreuid", "os.setregid", "os.setresuid",
        "os.setresgid", "os.setgroups", "os.initgroups",
    ), "privilege"),
    **dict.fromkeys((
        "sys.settrace", "sys.setprofile", "sys.addaudithook", "sys._getframe", "threading.settrace",
        "threading.setprofile", "threading.settrace_all_threads", "threading.setprofile_all_threads",
    ), "hooking"),
    **dict.fromkeys((
        "pickle.load", "pickle.loads", "pickle.Unpickler", "joblib.load", "yaml.load", "yaml.unsafe_load",
        "yaml.full_load",
    ), "deserialization"),
    **dict.fromkeys(("os.fork", "os.forkpty", "os.kill", "os.killpg"), "process-control"),
}
_BLOCKED_PREFIXES: tuple[tuple[str, str], ...] = (("os.exec", "os-command"), ("os.spawn", "os-command"))

# Attribute names that only interpreter-escape code needs.
_DUNDER_ESCAPES = frozenset({"__subclasses__", "__globals__", "__code__", "__builtins__", "f_globals", "f_builtins"})
# Path-like method calls that modify the file system. The first group only exists on paths; the second group
# is also common on other objects (pandas DataFrame.rename, …), so it blocks only on a receiver known to be a path.
_FS_METHODS = frozenset({"write_text", "write_bytes", "unlink", "rmdir", "symlink_to", "hardlink_to"})
_FS_METHODS_AMBIGUOUS = frozenset({"rename", "replace", "touch", "chmod", "lchmod", "mkdir"})
_PATH_CTORS = frozenset({"pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath"})
_PATH_ATTRS = frozenset({"parent", "with_name", "with_suffix", "with_stem", "resolve", "absolute", "expanduser",
                         "joinpath", "home", "cwd"})
# fs-modify functions whose arguments are all paths; with literal paths inside the output folder they are allowed.
_FS_COPY = frozenset({"shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree"})
_SYS_MODULES_MUTATORS = frozenset({"update", "pop", "popitem", "setdefault", "clear", "__setitem__", "__delitem__"})
_IMPORT_HOOKS = frozenset({"sys.meta_path", "sys.path_hooks", "sys.path_importer_cache"})
_DECODERS = frozenset({
    "base64.b64decode", "base64.b32decode", "base64.b16decode", "base64.a85decode", "base64.b85decode",
    "base64.urlsafe_b64decode", "base64.decodebytes", "base64.decodestring", "codecs.decode", "binascii.unhexlify",
    "binascii.a2b_base64", "binascii.a2b_hex", "bytes.fromhex", "zlib.decompress", "bz2.decompress",
    "lzma.decompress", "gzip.decompress",
})
_OPEN_FUNCS = frozenset({"open", "io.open", "codecs.open", "builtins.open", "os.fdopen"})
_WRITE_FLAGS = frozenset({"O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC"})

_SUDO = re.compile(r"(?:^|[\s;&|`$(\"'])sudo(?:\s|$)")
_SU = re.compile(r"(?:^|[;&|`$(]\s*)su(?:\s+-\w*|\s+root)?\s*(?:$|[;&|])|(?:^|[\s;&|`$(])su\s+-")
_PRIV_PATHS = re.compile(r"/etc/shadow|/etc/sudoers|/etc/gshadow|(?:^|[\s\"'=:;(])/root(?:/|$|[\s\"';)])")
# Credential stores a cluster task never needs: reading them is the first half of credential theft.
_CRED_PATHS = re.compile(r"\.ssh/(?:id_\w+|authorized_keys|known_hosts)|\.aws/(?:credentials|config)|\.netrc\b|"
                         r"\.git-credentials|\.docker/config\.json|\.kube/config|\.pgpass|\.gnupg/|/etc/passwd\b|"
                         r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b")


@dataclass(frozen=True, slots=True)
class PolicyFinding:
    """One rule violation (or warning) with its location."""

    rule: str
    category: str
    severity: str
    action: str          # "block" | "warn"
    line: int
    col: int
    message: str
    snippet: str = ""

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable representation."""
        return {**asdict(self), "category_title": CATEGORIES[self.category][0]}


@dataclass(slots=True)
class PolicyReport:
    """Outcome of screening one file."""

    filename: str
    findings: list[PolicyFinding] = field(default_factory=list)
    parse_error: str | None = None
    duration_ms: float = 0.0

    @property
    def blocked(self) -> bool:
        """True when the program must not be executed or distributed."""
        return any(f.action == "block" for f in self.findings)

    @property
    def verdict(self) -> str:
        """``ERROR`` (could not screen), ``BLOCK``, ``WARN`` or ``PASS``."""
        if self.parse_error:
            return "ERROR"
        if self.blocked:
            return "BLOCK"
        return "WARN" if self.findings else "PASS"

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable report (the security report of SRS 2.1.4)."""
        by_category: dict[str, int] = {}
        for f in self.findings:
            by_category[f.category] = by_category.get(f.category, 0) + 1
        return {
            "policy_version": POLICY_VERSION,
            "filename": self.filename,
            "verdict": self.verdict,
            "blocked": self.blocked,
            "parse_error": self.parse_error,
            "n_block": sum(f.action == "block" for f in self.findings),
            "n_warn": sum(f.action == "warn" for f in self.findings),
            "by_category": by_category,
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda f: (f.action != "block", f.line, f.col))],
            "duration_ms": self.duration_ms,
        }


def _fold_str(node: ast.AST) -> str | None:
    """Statically fold string constants joined with ``+`` (``"ex" + "ec"``)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold_str(node.left), _fold_str(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _module_category(dotted: str) -> str | None:
    parts = dotted.split(".")
    for i in range(len(parts), 0, -1):
        cat = _BLOCKED_MODULES.get(".".join(parts[:i]))
        if cat:
            return cat
    return None


def _name_category(dotted: str) -> str | None:
    cat = _BLOCKED_NAMES.get(dotted)
    if cat:
        return cat
    for prefix, pcat in _BLOCKED_PREFIXES:
        if dotted.startswith(prefix):
            return pcat
    return _module_category(dotted) if "." in dotted else None


class _PolicyVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, lines: list[str], output_dirs: tuple[str, ...]) -> None:
        self.filename = filename
        self.lines = lines
        self.output_dirs = output_dirs
        self.findings: dict[tuple[str, int, int], PolicyFinding] = {}
        self.aliases: dict[str, str] = {}
        self.module_aliases: set[str] = set()     # local names bound by `import x [as y]`
        self.shadowed: set[str] = set()           # builtins rebound by the program itself
        self.docstrings: set[int] = set()
        self.decoded_names: set[str] = set()      # variables assigned from a decoder call
        self.path_names: set[str] = set()         # variables that hold pathlib paths
        self.exempt: set[int] = set()             # fs-modify references proven to stay inside the output folder

    # ---------------------------------------------------------------- helpers
    def add(self, node: ast.AST, rule: str, category: str, message: str, action: str | None = None,
            severity: str | None = None) -> None:
        line = getattr(node, "lineno", 0) or 0
        col = getattr(node, "col_offset", 0) or 0
        action = action or ("warn" if category == "obfuscation" else "block")
        severity = severity or CATEGORIES[category][1]
        key = (rule, line, col)
        if key not in self.findings:
            snippet = self.lines[line - 1].strip()[:160] if 0 < line <= len(self.lines) else ""
            self.findings[key] = PolicyFinding(rule, category, severity, action, line, col, message, snippet)

    def resolve(self, node: ast.AST) -> str | None:
        """Fully qualified dotted name of a Name/Attribute chain, or of ``__import__("m").attr``."""
        dotted = _dotted(node)
        if dotted is None:
            return self._resolve_dynamic(node)
        head, _, rest = dotted.partition(".")
        if head == "__builtins__":
            head = "builtins"
        elif head in self.shadowed and head not in self.aliases:
            return None  # the program's own variable/function, not a module or builtin
        base = self.aliases.get(head, head)
        return f"{base}.{rest}" if rest else base

    def _resolve_dynamic(self, node: ast.AST) -> str | None:
        attrs: list[str] = []
        while isinstance(node, ast.Attribute):
            attrs.append(node.attr)
            node = node.value
        if not attrs or not isinstance(node, ast.Call) or not node.args:
            return None
        loader = _dotted(node.func)
        loader = self.aliases.get(loader, loader) if loader else None
        module = _fold_str(node.args[0])
        if loader in ("__import__", "importlib.import_module", "builtins.__import__") and module:
            return ".".join([module, *reversed(attrs)])
        return None

    # ---------------------------------------------------------------- pre-pass
    def prepare(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                body = node.body
                if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                        and isinstance(body[0].value.value, str):
                    self.docstrings.add(id(body[0].value))
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.aliases[a.asname] = a.name
                        self.module_aliases.add(a.asname)
                    else:
                        root = a.name.split(".")[0]
                        self.aliases[root] = root
                        self.module_aliases.add(root)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for a in node.names:
                    if a.name != "*":
                        self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.shadowed.add(node.name)
            elif isinstance(node, ast.arg):
                self.shadowed.add(node.arg)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                self.shadowed.add(node.id)
        # A name bound by an import is resolved through the alias table, not treated as shadowed.
        self.shadowed -= set(self.aliases)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and self._is_decoded(node.value):
                self.decoded_names.update(n.id for t in node.targets for n in ast.walk(t) if isinstance(n, ast.Name))
        for node in ast.walk(tree):  # parameters annotated as a Path
            if isinstance(node, ast.arg) and node.annotation is not None \
                    and "Path" in ast.unparse(node.annotation):
                self.path_names.add(node.arg)
        for _ in range(3):  # names assigned from a path expression (a few rounds for chains)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None \
                        and self._is_pathish(node.value):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    self.path_names.update(t.id for t in targets if isinstance(t, ast.Name))

    def _is_pathish(self, expr: ast.AST) -> bool:
        """Is ``expr`` (statically) a pathlib path? Path(...), a path variable, p.parent, p / "x", …"""
        if isinstance(expr, ast.Name):
            return expr.id in self.path_names
        if isinstance(expr, ast.Call):
            if (self.resolve(expr.func) or "") in _PATH_CTORS:
                return True
            return isinstance(expr.func, ast.Attribute) and expr.func.attr in _PATH_ATTRS \
                and self._is_pathish(expr.func.value)
        if isinstance(expr, ast.Attribute):
            return expr.attr in _PATH_ATTRS and self._is_pathish(expr.value)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
            return self._is_pathish(expr.left)
        return False

    def _literal_path(self, expr: ast.AST) -> str | None:
        """The literal path of a string or a Path("literal") / "literal" expression, if it is static."""
        text = _fold_str(expr)
        if text is not None:
            return text
        if isinstance(expr, ast.Call) and (self.resolve(expr.func) or "") in _PATH_CTORS and expr.args:
            parts = [_fold_str(a) for a in expr.args]
            return "/".join(parts) if all(x is not None for x in parts) else None
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
            left, right = self._literal_path(expr.left), _fold_str(expr.right)
            return f"{left}/{right}" if left is not None and right is not None else None
        return None

    def _relative_input(self, path: str) -> bool:
        norm = path.replace("\\", "/")
        return not norm.startswith("/") and ".." not in norm.split("/") and not norm.startswith("~")

    def _is_decoded(self, expr: ast.AST) -> bool:
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Call) and ((self.resolve(sub.func) or "") in _DECODERS
                                              or (isinstance(sub.func, ast.Attribute) and sub.func.attr == "fromhex")):
                return True
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load) and sub.id in self.decoded_names:
                return True
        return False

    # ---------------------------------------------------------------- imports
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            cat = _module_category(a.name)
            if cat:
                self.add(node, f"import-{a.name.split('.')[0]}", cat, f"import of '{a.name}' is not allowed")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level or not node.module:
            if node.level:
                self.add(node, "relative-import", "obfuscation", "relative import hides which module is loaded",
                         action="warn", severity="low")
            return
        cat = _module_category(node.module)
        if cat:
            self.add(node, f"import-{node.module.split('.')[0]}", cat, f"import from '{node.module}' is not allowed")
            return
        for a in node.names:
            if a.name == "*":
                self.add(node, "star-import", "obfuscation", f"'from {node.module} import *' hides imported names",
                         action="warn", severity="low")
                continue
            full = f"{node.module}.{a.name}"
            cat = _name_category(full)
            if cat:
                self.add(node, f"import-{full}", cat, f"import of '{full}' is not allowed")

    # ---------------------------------------------------------------- references
    def _check_reference(self, node: ast.AST, dotted: str | None) -> bool:
        if not dotted or id(node) in self.exempt:
            return False
        cat = _name_category(dotted)
        if cat is None and dotted in _BLOCKED_MODULES and dotted.split(".")[0] in self.aliases.values():
            cat = _BLOCKED_MODULES[dotted]
        if cat:
            self.add(node, dotted, cat, f"use of '{dotted}' is not allowed")
            return True
        return False

    def visit_Name(self, node: ast.Name) -> None:
        if not isinstance(node.ctx, ast.Load):
            return
        if node.id == "__builtins__":
            self.add(node, "builtins-access", "hooking", "direct access to __builtins__ (interpreter tampering)")
            return
        if node.id in self.shadowed and node.id not in self.aliases:
            return
        self._check_reference(node, self.resolve(node))

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _DUNDER_ESCAPES:
            self.add(node, f"dunder-{node.attr}", "hooking", f"access to '{node.attr}' (sandbox escape primitive)")
        dotted = self.resolve(node)
        if isinstance(node.ctx, ast.Load) and dotted:
            if dotted in _IMPORT_HOOKS:
                self.add(node, "import-hook", "hooking", f"access to '{dotted}' (import hooking)")
                return
            if self._check_reference(node, dotted):
                return  # don't report the shorter prefix again
        self.generic_visit(node)

    # ---------------------------------------------------------------- calls
    def visit_Call(self, node: ast.Call) -> None:
        name = self.resolve(node.func) or ""
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if _name_category(name) == "fs-modify" and node.args and not node.keywords:
            paths = [self._literal_path(a) for a in node.args[:2]]
            if all(p is not None for p in paths):
                *sources, target = paths
                ok = self._in_output_dir(target) and all(
                    self._relative_input(p) if name in _FS_COPY else self._in_output_dir(p) for p in sources)
                if ok:
                    self.exempt.add(id(node.func))
        # getattr(obj, "name") / getattr(module, computed)
        if name == "getattr" and len(node.args) >= 2:
            self._check_getattr(node)
        elif name == "setattr" and node.args:
            target = self.resolve(node.args[0])
            if target and (target == "builtins" or _dotted(node.args[0]) in self.module_aliases):
                self.add(node, "monkey-patch", "hooking", f"setattr() on module '{target}' (monkey-patching)")
        if name in _OPEN_FUNCS:
            self._check_open(node, name)
        elif name == "os.open":
            flags = {n.attr for a in node.args[1:2] for n in ast.walk(a) if isinstance(n, ast.Attribute)}
            if flags & _WRITE_FLAGS:
                self.add(node, "os.open-write", "fs-modify", "os.open() with write/create flags")
        if method in _FS_METHODS | _FS_METHODS_AMBIGUOUS and not isinstance(node.func.value, ast.Constant):
            receiver = node.func.value
            target = self._literal_path(receiver)
            if target is not None and self._in_output_dir(target):
                pass  # e.g. Path("output/result.txt").write_text(...)
            elif method in _FS_METHODS or self._is_pathish(receiver):
                self.add(node, f"method-{method}", "fs-modify", f".{method}() modifies the file system")
            elif method != "replace":  # str.replace is everywhere; an unknown receiver of rename/touch/… only warns
                self.add(node, f"method-{method}", "fs-modify",
                         f".{method}() may modify the file system (receiver type unknown)", action="warn",
                         severity="low")
        if isinstance(node.func, ast.Attribute) and method in _SYS_MODULES_MUTATORS \
                and self.resolve(node.func.value) == "sys.modules":
            self.add(node, "sys.modules-mutation", "hooking", f"sys.modules.{method}() (import hijacking)")
        if isinstance(node.func, ast.Attribute) and method in ("append", "insert", "extend", "remove") \
                and self.resolve(node.func.value) == "sys.path":
            self.add(node, "sys.path-mutation", "hooking", "changes sys.path (import search path)",
                     action="warn", severity="medium")
        self._check_decoded_args(node, name)
        self.generic_visit(node)

    def _check_getattr(self, node: ast.Call) -> None:
        target_node, attr_node = node.args[0], node.args[1]
        target = self.resolve(target_node)
        if isinstance(target_node, ast.Name) and target_node.id == "__builtins__":
            target = "builtins"
        attr = _fold_str(attr_node)
        is_module = target == "builtins" or (isinstance(target_node, ast.Name)
                                             and target_node.id in self.module_aliases)
        if attr is not None:
            full = attr if target == "builtins" else f"{target}.{attr}" if target else None
            if full and self._check_reference(node, full):
                return
        elif is_module:
            self.add(node, "getattr-computed", "obfuscation",
                     f"getattr() with a computed name on module '{target}'")

    def _check_open(self, node: ast.Call, name: str) -> None:
        mode_node: ast.expr | None = node.args[1] if len(node.args) > 1 else None
        for kw in node.keywords:
            if kw.arg == "mode":
                mode_node = kw.value
        if mode_node is None:
            return
        mode = mode_node.value if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str) else None
        if mode is None:
            self.add(node, "open-dynamic-mode", "fs-modify", f"{name}() with a mode computed at run time",
                     action="warn", severity="medium")
            return
        if not any(c in mode for c in "wax+"):
            return
        path = _fold_str(node.args[0]) if node.args else None
        if path is not None and self._in_output_dir(path):
            return
        self.add(node, "open-write", "fs-modify",
                 f"{name}() in '{mode}' mode outside the run output folder ({', '.join(self.output_dirs)})")

    def _in_output_dir(self, path: str) -> bool:
        norm = path.replace("\\", "/")
        while norm.startswith("./"):
            norm = norm[2:]
        if norm.startswith("/") or ".." in norm.split("/"):
            return False
        return any(norm == d or norm.startswith(d.rstrip("/") + "/") for d in self.output_dirs)

    def _check_decoded_args(self, node: ast.Call, name: str) -> None:
        if not any(self._is_decoded(arg) for arg in [*node.args, *(k.value for k in node.keywords)]):
            return
        if _name_category(name) or name in _OPEN_FUNCS:
            self.add(node, "decoded-to-blocked-call", "obfuscation",
                     f"decoded data passed to blocked call '{name}'", action="block", severity="critical")
        else:
            self.add(node, "decoded-argument", "obfuscation", f"decoded data passed to '{name or 'call'}'",
                     action="warn", severity="medium")

    # ---------------------------------------------------------------- writes
    def _check_store_target(self, target: ast.AST, stmt: ast.AST) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._check_store_target(elt, stmt)
            return
        if isinstance(target, ast.Attribute):
            base = target.value
            base_name = self.resolve(base)
            if base_name == "builtins" or (isinstance(base, ast.Name) and base.id == "__builtins__"):
                self.add(stmt, "builtins-assignment", "hooking", f"assignment to builtins.{target.attr}")
            elif isinstance(base, ast.Name) and base.id in self.module_aliases:
                self.add(stmt, "monkey-patch", "hooking",
                         f"assignment to module attribute '{base_name}.{target.attr}' (monkey-patching)")
            elif base_name in ("sys",) and target.attr in ("modules", "meta_path", "path_hooks", "excepthook",
                                                            "displayhook", "stdout", "stderr"):
                self.add(stmt, f"sys.{target.attr}-assignment", "hooking", f"replaces sys.{target.attr}")
        elif isinstance(target, ast.Subscript):
            base_name = self.resolve(target.value)
            if base_name == "sys.modules":
                self.add(stmt, "sys.modules-mutation", "hooking", "writes to sys.modules (import hijacking)")
            elif base_name == "builtins" or (isinstance(target.value, ast.Name)
                                             and target.value.id == "__builtins__"):
                self.add(stmt, "builtins-assignment", "hooking", "item assignment into __builtins__")
            elif base_name == "os.environ":
                self.add(stmt, "environ-write", "privilege", "modifies os.environ of the worker process",
                         action="warn", severity="medium")

    def visit_Assign(self, node: ast.Assign) -> None:
        for t in node.targets:
            self._check_store_target(t, node)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._check_store_target(node.target, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._check_store_target(node.target, node)
        self.generic_visit(node)

    def visit_Delete(self, node: ast.Delete) -> None:
        for t in node.targets:
            self._check_store_target(t, node)
        self.generic_visit(node)

    # ---------------------------------------------------------------- strings
    def visit_Constant(self, node: ast.Constant) -> None:
        value = node.value
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        if not isinstance(value, str) or id(node) in self.docstrings or len(value) > 4096:
            return
        if _SUDO.search(value) or _SU.search(value):
            self.add(node, "sudo-command", "privilege", "string contains a sudo/su command")
        if _PRIV_PATHS.search(value):
            self.add(node, "privileged-path", "privilege", "string references /etc/shadow, /etc/sudoers or /root")
        if _CRED_PATHS.search(value):
            self.add(node, "credential-path", "privilege",
                     "string references a credential store (SSH keys, cloud/Git/Docker credentials, /etc/passwd)")


def screen_source(source: str | bytes, filename: str = "<input>",
                  output_dirs: tuple[str, ...] = ("output",)) -> PolicyReport:
    """Screen one Python file against the cluster security policy. Never executes it."""
    started = time.perf_counter()
    report = PolicyReport(filename=filename)
    text = source.decode("utf-8", "replace") if isinstance(source, bytes) else source
    try:
        tree = ast.parse(source, filename)
    except SyntaxError as exc:
        report.parse_error = f"line {exc.lineno}: {exc.msg}"
    except (ValueError, RecursionError, MemoryError) as exc:
        report.parse_error = f"{type(exc).__name__}: {exc}"[:200]
    else:
        visitor = _PolicyVisitor(filename, text.splitlines(), tuple(d.strip("/") or "." for d in output_dirs))
        try:
            visitor.prepare(tree)
            visitor.visit(tree)
        except RecursionError:
            report.parse_error = "code is nested too deeply to screen"
        report.findings = list(visitor.findings.values())
    report.duration_ms = round((time.perf_counter() - started) * 1000, 2)
    return report


def rules_catalog() -> dict[str, object]:
    """The screening scope, for reports and the dashboard."""
    return {
        "policy_version": POLICY_VERSION,
        "categories": {k: {"title": t, "severity": s, "action": "warn" if k == "obfuscation" else "block"}
                       for k, (t, s) in CATEGORIES.items()},
        "blocked_modules": sorted(_BLOCKED_MODULES),
        "blocked_names": sorted(_BLOCKED_NAMES),
    }
