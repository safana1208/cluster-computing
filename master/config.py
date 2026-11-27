"""Control Parameter File (SRS FR-1.2, FR-1.8): loading and validation.

The file is TOML (``master/control_parameters.toml`` by default, or ``$MASTER_CONFIG`` /
``--config``). Every field has a safe default, so the file is optional. Validation runs at
start-up; an invalid file is rejected with the field and the reason. Relative paths are
resolved against the project root.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from master.eligibility import DEFAULT_ALLOWLIST

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "control_parameters.toml"
_WORKER = re.compile(r"^[A-Za-z0-9.\-:]+?(:\d{1,5})?$")
_MEMORY = re.compile(r"^\d+[kmg]$", re.I)


class ConfigError(ValueError):
    """Invalid Control Parameter File: names the field and the reason."""


@dataclass
class MasterSection:
    host: str = "127.0.0.1"
    port: int = 8080
    data_dir: str = "master_data"
    max_file_bytes: int = 1024 * 1024
    password: str = ""                    # protected field (Administrator); empty = no password
    import_poll_seconds: float = 2.0      # FR-1.11 import folder; 0 disables it
    reset_on_start: bool = True           # wipe the run history database and run files at every start
    debug_level: str = "basic"            # default debug level of a run (FR-1.9): basic | detailed | debug
    max_input_bytes: int = 32 * 1024 * 1024   # input files submitted with a program (total)


@dataclass
class PipelineSection:
    pipeline_threads: int = 4             # concurrent jobs (I/O-bound orchestration threads)
    precheck_processes: int = 2           # ProcessPoolExecutor workers for syntax validation
    precheck_timeout: float = 10.0
    sandbox_retries: int = 1              # retries on a fresh sandbox after an infrastructure failure


@dataclass
class SandboxSection:
    backend: str = "docker"               # docker | services (compose: AI + AST nodes) | process (dev only)
    ai_engine_url: str = "http://ai_engine:8100"   # AI node, used when backend = "services"
    mode: str = "warm"                    # warm (pool of long-lived sandboxes) | ephemeral (one per job)
    pool_size: int = 2
    image: str = "scs-inspector:latest"
    memory: str = "512m"
    cpus: float = 1.0
    pids_limit: int = 64
    job_timeout: float = 20.0
    start_timeout: float = 90.0
    max_jobs_per_sandbox: int = 200       # recycle a sandbox after this many inspections
    artifacts_dir: str = "shared/artifacts"      # trained models, mounted read-only


@dataclass
class SecuritySection:
    ai_mode: str = "local"                # protected: local (AST + AI) | off (static layers only)
    malicious_action: str = "delete"      # delete | quarantine
    block_on_suspicious: bool = False     # SRS: Low/Medium findings are warnings; set true to block them
    output_dirs: list[str] = field(default_factory=lambda: ["output"])


@dataclass
class ClusterSection:
    workers: list[str] = field(default_factory=list)   # allowed Worker Node hosts ("host" or "host:port"); [] = any
    bind: str = "127.0.0.1"               # cluster port address; "0.0.0.0" for Worker Nodes on the LAN
    port: int = 7070
    token: str = ""                       # protected: shared cluster token; "" = random per start (local only)
    local_workers: int = 4                # Worker Node agents started on this machine (0 on a real cluster)
    worker_slots: int = 1                 # tasks executed at once by each local Worker Node
    heartbeat_interval: float = 2.0       # FR-4.6: H seconds; Suspect after 2 missed, Dead after 3
    timeout_factor: float = 10.0          # FR-4.6: task timeout = smoke-test duration x factor ...
    task_timeout_min: float = 5.0         # ... with this minimum (seconds)
    retry_limit: int = 2                  # FR-5.3: retries per task after an infrastructure failure
    chunk_factor: int = 4                 # SRS 5.3.4: chunks = factor x active Worker Node slots ...
    chunk_size: int = 0                   # ... or a fixed number of items per chunk (0 = use the factor)
    worker_wait_timeout: float = 30.0     # AF-5.4.1: how long tasks wait for an available Worker Node
    run_timeout: float = 300.0            # time limit of one program run (reference run / transformed program)
    max_message_bytes: int = 16 * 1024 * 1024   # OI-18: larger chunks are split further
    task_memory_mb: int = 512             # memory limit of every task process (NFR-2.3, OI-07)
    run_memory_mb: int = 1024             # memory limit of the transformed program on the Master (NFR-2.6)
    isolation: str = "auto"               # auto | unshare (required) | none: no-network namespaces for task code
    library_allowlist: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWLIST))


@dataclass
class Config:
    master: MasterSection = field(default_factory=MasterSection)
    pipeline: PipelineSection = field(default_factory=PipelineSection)
    sandbox: SandboxSection = field(default_factory=SandboxSection)
    security: SecuritySection = field(default_factory=SecuritySection)
    cluster: ClusterSection = field(default_factory=ClusterSection)
    source: str | None = None

    # derived paths ------------------------------------------------------
    def path(self, value: str) -> Path:
        p = Path(value).expanduser()
        return p if p.is_absolute() else PROJECT_ROOT / p

    @property
    def data_dir(self) -> Path:
        return self.path(self.master.data_dir)

    @property
    def artifacts_dir(self) -> Path:
        return self.path(self.sandbox.artifacts_dir)

    def public(self) -> dict[str, Any]:
        """Settings for the dashboard (protected secrets redacted)."""
        out: dict[str, Any] = {}
        for sec in fields(self):
            if sec.name == "source":
                continue
            values = dict(vars(getattr(self, sec.name)))
            for secret in ("password", "token"):
                if secret in values:
                    values[secret] = "set" if values[secret] else ""
            out[sec.name] = values
        out["source"] = self.source
        return out

    def validate(self) -> None:
        m, p, s, sec, c = self.master, self.pipeline, self.sandbox, self.security, self.cluster

        def need(ok: bool, name: str, why: str) -> None:
            if not ok:
                raise ConfigError(f"{name}: {why}")

        need(1 <= m.port <= 65535, "master.port", "must be 1-65535")
        need(1024 <= m.max_file_bytes <= 16 * 1024 * 1024, "master.max_file_bytes", "must be 1 KB - 16 MB")
        need(m.import_poll_seconds == 0 or 0.2 <= m.import_poll_seconds <= 3600, "master.import_poll_seconds",
             "0 (off) or 0.2-3600")
        need(1 <= p.pipeline_threads <= 64, "pipeline.pipeline_threads", "must be 1-64")
        need(1 <= p.precheck_processes <= 32, "pipeline.precheck_processes", "must be 1-32")
        need(0.5 <= p.precheck_timeout <= 300, "pipeline.precheck_timeout", "must be 0.5-300 s")
        need(0 <= p.sandbox_retries <= 5, "pipeline.sandbox_retries", "must be 0-5")
        need(s.backend in ("docker", "services", "process"), "sandbox.backend", "docker, services or process")
        need(s.ai_engine_url.startswith(("http://", "https://")), "sandbox.ai_engine_url", "http(s) URL")
        need(s.mode in ("warm", "ephemeral"), "sandbox.mode", "warm or ephemeral")
        need(1 <= s.pool_size <= 32, "sandbox.pool_size", "must be 1-32")
        need(bool(_MEMORY.match(s.memory)), "sandbox.memory", "like 512m or 1g")
        need(0.1 <= s.cpus <= 64, "sandbox.cpus", "must be 0.1-64")
        need(16 <= s.pids_limit <= 4096, "sandbox.pids_limit", "must be 16-4096")
        need(1 <= s.job_timeout <= 600, "sandbox.job_timeout", "must be 1-600 s")
        need(5 <= s.start_timeout <= 900, "sandbox.start_timeout", "must be 5-900 s")
        need(1 <= s.max_jobs_per_sandbox <= 100000, "sandbox.max_jobs_per_sandbox", "must be >= 1")
        need(bool(re.match(r"^[\w.\-/:@]+$", s.image)), "sandbox.image", "invalid image reference")
        need(sec.ai_mode in ("local", "off"), "security.ai_mode", "local or off")
        need(sec.malicious_action in ("delete", "quarantine"), "security.malicious_action", "delete or quarantine")
        need(all(isinstance(d, str) and d and not d.startswith("/") and ".." not in d for d in sec.output_dirs),
             "security.output_dirs", "relative folder names without '..'")
        need(m.debug_level in ("basic", "detailed", "debug"), "master.debug_level", "basic, detailed or debug")
        need(1024 <= m.max_input_bytes <= 512 * 1024 * 1024, "master.max_input_bytes", "must be 1 KB - 512 MB")
        for w in c.workers:
            need(isinstance(w, str) and bool(_WORKER.match(w)), "cluster.workers", f"'{w}' is not host or host:port")
        need(bool(re.match(r"^[\w.:\-]+$", c.bind)), "cluster.bind", "an IP address or host name")
        need(0 <= c.port <= 65535, "cluster.port", "must be 0-65535")
        need(c.token == "" or len(c.token) >= 16, "cluster.token", "empty (local only) or at least 16 characters")
        need(c.token != "" or c.bind in ("127.0.0.1", "localhost", "::1"), "cluster.token",
             "required when Worker Nodes connect over the LAN (cluster.bind is not local)")
        need(0 <= c.local_workers <= 64, "cluster.local_workers", "must be 0-64")
        need(1 <= c.worker_slots <= 64, "cluster.worker_slots", "must be 1-64")
        need(0.2 <= c.heartbeat_interval <= 60, "cluster.heartbeat_interval", "must be 0.2-60 s")
        need(1 <= c.timeout_factor <= 1000, "cluster.timeout_factor", "must be 1-1000")
        need(0.5 <= c.task_timeout_min <= 3600, "cluster.task_timeout_min", "must be 0.5-3600 s")
        need(0 <= c.retry_limit <= 10, "cluster.retry_limit", "must be 0-10")
        need(1 <= c.chunk_factor <= 64, "cluster.chunk_factor", "must be 1-64")
        need(0 <= c.chunk_size <= 10_000_000, "cluster.chunk_size", "0 (use chunk_factor) or a positive size")
        need(1 <= c.worker_wait_timeout <= 3600, "cluster.worker_wait_timeout", "must be 1-3600 s")
        need(1 <= c.run_timeout <= 86400, "cluster.run_timeout", "must be 1-86400 s")
        need(64 * 1024 <= c.max_message_bytes <= 256 * 1024 * 1024, "cluster.max_message_bytes", "64 KB - 256 MB")
        need(64 <= c.task_memory_mb <= 65536, "cluster.task_memory_mb", "must be 64-65536")
        need(128 <= c.run_memory_mb <= 65536, "cluster.run_memory_mb", "must be 128-65536")
        need(c.isolation in ("auto", "unshare", "none"), "cluster.isolation", "auto, unshare or none")
        need(all(isinstance(x, str) and re.match(r"^[a-z_][\w.]*$", x) for x in c.library_allowlist),
             "cluster.library_allowlist", "module names only")


def _apply(section: Any, values: dict[str, Any], name: str) -> None:
    known = {f.name: f for f in fields(section)}
    for key, value in values.items():
        if key not in known:
            raise ConfigError(f"{name}.{key}: unknown field")
        default = getattr(section, key)
        if isinstance(default, bool):
            ok = isinstance(value, bool)
        elif isinstance(default, float):
            ok = isinstance(value, (int, float)) and not isinstance(value, bool)
            value = float(value) if ok else value
        elif isinstance(default, int):
            ok = isinstance(value, int) and not isinstance(value, bool)
        elif isinstance(default, list):
            ok = isinstance(value, list)
        else:
            ok = isinstance(value, str)
        if not ok:
            raise ConfigError(f"{name}.{key}: expected {type(default).__name__}, got {type(value).__name__}")
        setattr(section, key, value)


def load_config(path: str | Path | None = None, overrides: dict[str, dict[str, Any]] | None = None) -> Config:
    """Load and validate the Control Parameter File. Raises ConfigError on any invalid field."""
    cfg = Config()
    chosen = Path(path) if path else (Path(os.environ["MASTER_CONFIG"]) if os.environ.get("MASTER_CONFIG")
                                      else DEFAULT_CONFIG_PATH)
    data: dict[str, Any] = {}
    if chosen.exists():
        try:
            data = tomllib.loads(chosen.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{chosen}: {exc}") from exc
        cfg.source = str(chosen)
    elif path:
        raise ConfigError(f"{chosen}: file not found")
    env = {k: v for k, v in (("bind", os.environ.get("CLUSTER_BIND")), ("token", os.environ.get("CLUSTER_TOKEN")))
           if v}  # lets docker compose open the cluster port to Raspberry Pi Worker Nodes without editing the file
    layers = [*data.items(), *([("cluster", env)] if env else []), *(overrides or {}).items()]
    for name, values in layers:
        if name not in ("master", "pipeline", "sandbox", "security", "cluster") or not isinstance(values, dict):
            raise ConfigError(f"{name}: unknown section")
        _apply(getattr(cfg, name), values, name)
    cfg.validate()
    return cfg


#: Run parameters the dashboard may edit (SRS 7.8); AI mode, password and token stay Administrator-only.
EDITABLE: dict[str, tuple[str, ...]] = {
    "master": ("debug_level",),
    "cluster": ("workers", "heartbeat_interval", "timeout_factor", "task_timeout_min", "retry_limit",
                "chunk_factor", "chunk_size", "worker_wait_timeout", "run_timeout", "library_allowlist"),
}


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def update_run_params(cfg: Config, changes: dict[str, dict[str, Any]]) -> list[str]:
    """FR-1.8: validate edited run parameters, then apply them and save the file. Invalid -> ConfigError, nothing changes."""
    import copy

    trial = copy.deepcopy(cfg)
    applied: list[str] = []
    for section, values in changes.items():
        if section not in EDITABLE or not isinstance(values, dict):
            raise ConfigError(f"{section}: not editable from the dashboard")
        for key in values:
            if key not in EDITABLE[section]:
                raise ConfigError(f"{section}.{key}: protected or unknown field (set by the Administrator)")
        _apply(getattr(trial, section), values, section)
        applied += [f"{section}.{k}" for k in values]
    trial.validate()
    path = Path(cfg.source) if cfg.source else DEFAULT_CONFIG_PATH
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    for section, values in changes.items():
        for key, value in values.items():
            line = f"{key} = {_toml_value(getattr(getattr(trial, section), key))}"
            block = re.search(rf"(?ms)^\[{section}\]\s*$(.*?)(?=^\[|\Z)", text)
            if block is None:
                text += f"\n[{section}]\n{line}\n"
                continue
            body = block.group(1)
            pat = re.compile(rf"(?ms)^{key}\s*=\s*(\[.*?\]|[^\n#]*?)(?=\s*(#[^\n]*)?$)")
            new_body = pat.sub(lambda m: line, body, count=1) if pat.search(body) else body.rstrip("\n") + f"\n{line}\n\n"
            text = text[:block.start(1)] + new_body + text[block.end(1):]
    tomllib.loads(text)  # never write a file that doesn't parse
    path.write_text(text, encoding="utf-8")
    for section in changes:
        setattr(cfg, section, getattr(trial, section))
    return applied
