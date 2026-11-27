"""Web layer of the Master Node: dashboard + REST API + live WebSocket feed.

    GET  /                               dashboard (static/index.html)
    WS   /ws                             live events: jobs, runs, run log, Master status (1 Hz)
    GET  /api/health                     liveness / readiness
    GET  /api/status                     pools, sandboxes, Worker Nodes, current run
    GET  /api/config                     Control Parameter File (secrets redacted)
    POST /api/config                     edit run parameters (FR-1.8; only when no run is active)
    POST /api/jobs                       submit one file, a folder (several .py + input files) or an example
    GET  /api/jobs                       recent jobs
    GET  /api/jobs/{id}                  full report (security, eligibility, timeline, runs)
    GET  /api/jobs/{id}/files/{name}     generated files (program, transformed program, task templates)
    POST /api/jobs/{id}/run              {"mode": "standard"|"cluster"|"sweep", "debug": ..., "workers": n}
    GET  /api/runs                       runs (optionally ?job=<id>)
    GET  /api/runs/{id}                  one run (metrics, validation, log)
    POST /api/runs/{id}/cancel           cancel a pending or running run (OI-17)
    GET  /api/runs/{id}/files/{name}     run outputs (run.log, result.txt, performance.json, speedup.svg/png)
    GET  /api/examples                   SRS reference workloads and negative samples
    GET  /api/security/events            recent blocked files
    GET  /api/selftest, POST /api/selftest   system self-test: the project's own core-flow tests (trusted code)

Program text and findings are rendered with ``textContent`` in the browser (NFR-2.4: no XSS).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hmac
import json
import logging
import re
import secrets
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from master.config import Config, ConfigError, update_run_params
from master.core import MasterNode
from master.demo_programs import EXAMPLES, example_inputs
from master.sandbox import SandboxError
from master.selftest import SelfTest

logger = logging.getLogger("master.app")
STATIC = Path(__file__).resolve().parent / "static"
MAX_BATCH = 50
_RUN_FILE = re.compile(r"(run\.log|result\.txt|reference_output\.txt|performance\.json|speedup\.(svg|png))")


class FileIn(BaseModel):
    filename: str = Field(min_length=1, max_length=300)
    source: str | None = None          # .py files: text
    b64: str | None = None             # input files: base64 content


class SubmitIn(BaseModel):
    filename: str | None = Field(default=None, max_length=300)
    source: str | None = None
    files: list[FileIn] | None = None
    example: str | None = None
    resubmit_of: str | None = None     # FR-1.6: edited source, same input files


class RunIn(BaseModel):
    mode: str = "standard"
    debug: str | None = None
    workers: int | None = None


def create_app(cfg: Config, master: MasterNode | None = None, start: bool = True) -> FastAPI:
    node = master or MasterNode(cfg)

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        if start:
            def boot() -> None:
                try:
                    node.start()
                except (SandboxError, Exception) as exc:  # the dashboard stays up and shows why
                    node.startup_error = f"{type(exc).__name__}: {exc}"
                    logger.error("Master Node failed to start: %s", node.startup_error)
                    node.bus.publish("master.failed", error=node.startup_error)
            threading.Thread(target=boot, name="mn-boot", daemon=True).start()
        yield
        await asyncio.to_thread(node.stop)

    app = FastAPI(title="Cluster Computing — Master Node", version="1.1.0", lifespan=lifespan)
    app.state.master = node
    selftest = SelfTest(lambda kind, **data: node.bus.publish(kind, **data))

    @app.middleware("http")
    async def auth(request: Request, call_next):
        if cfg.master.password and not _authorized(request.headers.get("authorization"), cfg.master.password):
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="Master Node"'})
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Content-Security-Policy",
                                    "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                    "style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:")
        return response

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok" if node.ready else "starting" if not node.startup_error else "failed",
                "ready": node.ready, "error": node.startup_error}

    @app.get("/api/status")
    async def status() -> dict[str, Any]:
        return await asyncio.to_thread(node.status)

    @app.get("/api/config")
    async def config() -> dict[str, Any]:
        return cfg.public()

    @app.post("/api/config")
    async def edit_config(body: dict[str, dict[str, Any]]) -> dict[str, Any]:
        if node.runs.busy():
            raise HTTPException(409, "settings can be edited only when no run is active (FR-1.8)")
        try:
            applied = update_run_params(cfg, body)
        except ConfigError as exc:
            raise HTTPException(400, f"invalid value, previous settings kept: {exc}") from exc
        s, c = node.runs.sched, cfg.cluster
        s.heartbeat, s.retry_limit, s.worker_wait_timeout = c.heartbeat_interval, c.retry_limit, c.worker_wait_timeout
        hosts = [w.rsplit(":", 1)[0] for w in c.workers]
        s.allowed_hosts = set(hosts + (["127.0.0.1", "::1"] if hosts and c.local_workers else []))
        return {"applied": applied, "config": cfg.public()}

    @app.post("/api/jobs", status_code=202)
    async def submit(body: SubmitIn) -> dict[str, Any]:
        programs: list[tuple[str, str]] = []
        inputs: dict[str, bytes] = {}
        if body.example:
            ex = EXAMPLES.get(body.example)
            if ex is None:
                raise HTTPException(404, "unknown example")
            programs.append((body.example, body.source if body.source is not None else ex["source"]))
            inputs.update(await asyncio.to_thread(example_inputs, body.example))
        if body.resubmit_of:
            inputs.update(await asyncio.to_thread(_inputs_of, node, body.resubmit_of))
        for item in body.files or []:
            name = item.filename.replace("\\", "/").lstrip("/")
            if ".." in name.split("/"):
                raise HTTPException(400, f"invalid path: {item.filename}")
            if item.source is not None and name.lower().endswith(".py"):
                programs.append((name, item.source))
            elif item.b64 is not None:
                try:
                    inputs[name] = base64.b64decode(item.b64, validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise HTTPException(400, f"{name}: invalid base64") from exc
            elif item.source is not None:
                inputs[name] = item.source.encode("utf-8")
        if body.source is not None and not body.example:
            programs.append((body.filename or "program.py", body.source))
        if not programs:
            raise HTTPException(400, "no .py file submitted (only Python source files are analyzed)")
        if len(programs) > MAX_BATCH:
            raise HTTPException(413, f"at most {MAX_BATCH} .py files per folder")
        batch = secrets.token_hex(4) if len(programs) > 1 else None
        names = {n for n, _ in programs}
        accepted, rejected = [], []
        for name, source in programs:
            # the other .py files of the folder are input files too (local imports, read-only data)
            extra = {n: s.encode("utf-8") for n, s in programs if n != name}
            try:
                job = node.submit(name, source.encode("utf-8", "surrogatepass"), via="dashboard", batch=batch,
                                  inputs={**inputs, **extra})
                accepted.append(job.summary())
            except ValueError as exc:
                rejected.append({"filename": name, "reason": str(exc)})
            except RuntimeError as exc:
                raise HTTPException(503, str(exc)) from exc
        if not accepted:
            raise HTTPException(400, {"error": "no file accepted", "rejected": rejected})
        return {"accepted": accepted, "rejected": rejected, "batch": batch, "programs": sorted(names)}

    @app.get("/api/jobs")
    async def jobs(limit: int = 200) -> dict[str, Any]:
        return {"jobs": node.list_jobs(max(1, min(limit, 500)))}

    @app.get("/api/jobs/{job_id}")
    async def job(job_id: str) -> dict[str, Any]:
        report = await asyncio.to_thread(node.get_report, job_id)
        if report is None:
            raise HTTPException(404, "unknown job")
        live = node.jobs.get(job_id)
        if live is not None:
            report = {**report, "job": live.summary()}
        return {**report, "runs": node.runs.list_runs(job_id)}

    @app.get("/api/jobs/{job_id}/files/{name:path}")
    async def job_file(job_id: str, name: str) -> PlainTextResponse:
        if not re.fullmatch(r"[\w-]{1,64}", job_id) or not re.fullmatch(
                r"(program|transformed|astmaster_transformed|dispatch|report)\.(py|json)|tasks/task_\d+\.py", name):
            raise HTTPException(404, "not available")
        path = node.dirs["runs"] / job_id / name
        if not path.is_file():
            raise HTTPException(404, "not available (malicious files are not retained)")
        return PlainTextResponse(path.read_text(encoding="utf-8"),
                                 headers={"Content-Disposition": f'attachment; filename="{job_id}-{path.name}"'})

    @app.post("/api/jobs/{job_id}/run", status_code=202)
    async def run_job(job_id: str, body: RunIn) -> dict[str, Any]:
        try:
            return node.runs.request(job_id, body.mode, body.debug, body.workers).summary()
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/runs")
    async def runs(job: str | None = None) -> dict[str, Any]:
        return {"runs": node.runs.list_runs(job)}

    @app.get("/api/runs/{run_id}")
    async def run(run_id: str) -> dict[str, Any]:
        r = node.runs.runs.get(run_id)
        if r is None:
            raise HTTPException(404, "unknown run")
        return {**r.summary(), "logs": list(r.logs)}

    @app.post("/api/runs/{run_id}/cancel")
    async def cancel(run_id: str) -> dict[str, Any]:
        try:
            return node.runs.cancel(run_id).summary()
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/api/runs/{run_id}/files/{name}")
    async def run_file(run_id: str, name: str) -> Response:
        r = node.runs.runs.get(run_id)
        if r is None or r.out_dir is None or not _RUN_FILE.fullmatch(name):
            raise HTTPException(404, "not available")
        path = r.out_dir / name
        if not path.is_file():
            raise HTTPException(404, "not available")
        media = {"svg": "image/svg+xml", "png": "image/png", "json": "application/json"}.get(name.rsplit(".", 1)[1],
                                                                                              "text/plain")
        return FileResponse(path, media_type=media)

    @app.get("/api/examples")
    async def examples() -> dict[str, Any]:
        return {"examples": [{"filename": k, **v} for k, v in EXAMPLES.items()]}

    @app.get("/api/security/events")
    async def security_events(limit: int = 50) -> dict[str, Any]:
        path = node.dirs["logs"] / "security_events.jsonl"
        if not path.exists():
            return {"events": []}
        lines = path.read_text(encoding="utf-8").splitlines()[-max(1, min(limit, 500)):]
        return {"events": [json.loads(x) for x in reversed(lines) if x.strip()]}

    @app.get("/api/selftest")
    async def selftest_status() -> dict[str, Any]:
        return selftest.status()

    @app.post("/api/selftest", status_code=202)
    async def selftest_start() -> dict[str, Any]:
        try:
            return selftest.start()
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:
        if cfg.master.password and not _authorized(socket.headers.get("authorization"), cfg.master.password):
            await socket.close(code=1008)
            return
        await socket.accept()
        loop = asyncio.get_running_loop()
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1000)

        def push(event: dict[str, Any]) -> None:  # called from Master threads
            def put() -> None:
                if q.full():
                    with contextlib.suppress(asyncio.QueueEmpty):
                        q.get_nowait()
                q.put_nowait(event)
            loop.call_soon_threadsafe(put)

        node.bus.subscribe(push)
        try:
            await socket.send_json({"kind": "hello", "status": await asyncio.to_thread(node.status),
                                    "jobs": node.list_jobs(200), "runs": node.runs.list_runs(),
                                    "config": cfg.public()})
            while True:
                await socket.send_json(await q.get())
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            node.bus.unsubscribe(push)

    @app.exception_handler(json.JSONDecodeError)
    async def bad_json(_: Request, exc: json.JSONDecodeError) -> JSONResponse:
        return JSONResponse({"detail": f"invalid JSON: {exc.msg}"}, status_code=400)

    return app


def _inputs_of(node: MasterNode, job_id: str) -> dict[str, bytes]:
    if not re.fullmatch(r"[\w-]{1,64}", job_id):
        return {}
    root = node.dirs["runs"] / job_id / "inputs"
    if not root.is_dir():
        return {}
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def _authorized(header: str | None, password: str) -> bool:
    if not header or not header.lower().startswith("basic "):
        return False
    try:
        _, _, given = base64.b64decode(header[6:]).decode("utf-8").partition(":")
    except (ValueError, UnicodeDecodeError):
        return False
    return hmac.compare_digest(given, password)
