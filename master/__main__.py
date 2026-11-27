"""Command line of the Master Node.

    python -m master serve [--config FILE] [--host H] [--port P]   # dashboard + pipeline
    python -m master check FILE.py [FILE.py ...] [--json]          # headless: same pipeline, prints verdicts
    python -m master build-image                                   # build the inspection sandbox image
    python -m master poc [FILE.py] [--workers 2]                   # POC: split -> pull -> run -> aggregate -> compare

Exit code of ``check``: 0 = all files safe, 2 = at least one blocked (malicious or security violation),
3 = at least one could not be screened (fail-closed), 1 = usage/config error.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from master.config import ConfigError, load_config


def _overrides(args: argparse.Namespace) -> dict:
    out: dict = {}
    if getattr(args, "host", None):
        out.setdefault("master", {})["host"] = args.host
    if getattr(args, "port", None):
        out.setdefault("master", {})["port"] = args.port
    if getattr(args, "backend", None):
        out.setdefault("sandbox", {})["backend"] = args.backend
    if getattr(args, "mode", None):
        out.setdefault("sandbox", {})["mode"] = args.mode
    if getattr(args, "data_dir", None):
        out.setdefault("master", {})["data_dir"] = args.data_dir
    return out


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from master.app import create_app

    cfg = load_config(args.config, _overrides(args))
    if cfg.master.host not in ("127.0.0.1", "localhost", "::1") and not cfg.master.password:
        logging.warning("dashboard bound to %s without a password (set master.password)", cfg.master.host)
    uvicorn.run(create_app(cfg), host=cfg.master.host, port=cfg.master.port, log_level="info")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    from master.core import MasterNode

    overrides = _overrides(args)
    overrides.setdefault("master", {})["import_poll_seconds"] = 0
    cfg = load_config(args.config, overrides)
    from master.sandbox import SandboxError

    node = MasterNode(cfg)
    t0 = time.perf_counter()
    try:
        node.start(cluster=False)
    except SandboxError as exc:  # fail-closed: no screening, no verdicts
        node.stop()
        print(f"security screening unavailable, nothing was screened: {exc}", file=sys.stderr)
        return 3
    startup = time.perf_counter() - t0
    jobs, t1 = [], time.perf_counter()
    try:
        for f in args.files:
            p = Path(f)
            try:
                jobs.append(node.submit(p.name, p.read_bytes(), via="cli"))
            except (OSError, ValueError) as exc:
                print(f"{p.name}: rejected: {exc}", file=sys.stderr)
        while any(j.state in ("RECEIVED", "QUEUED", "VALIDATING", "SCREENING") for j in jobs):
            time.sleep(0.02)
        wall = time.perf_counter() - t1
    finally:
        node.stop()
    if args.json:
        print(json.dumps({"startup_s": round(startup, 2), "wall_s": round(wall, 3),
                          "jobs": [node.get_report(j.id) for j in jobs]}, indent=2, default=str))
    else:
        print(f"{'file':34} {'security':11} {'cluster eligibility':20} {'disposition':20} {'ms':>7}")
        for j in jobs:
            print(f"{j.filename[:34]:34} {j.security_verdict or '-':11} {j.eligibility_verdict or '-':20} "
                  f"{j.disposition or '-':20} {j.total_ms or 0:7.0f}")
            if j.error:
                print(f"    {j.error}")
        print(f"\n{len(jobs)} file(s) in {wall:.2f} s (startup {startup:.2f} s, "
              f"{cfg.sandbox.pool_size} {cfg.sandbox.backend} sandbox(es), mode {cfg.sandbox.mode})")
    if any(j.state == "ERROR" for j in jobs):
        return 3
    return 2 if any(j.state == "BLOCKED" or j.disposition == "SECURITY_VIOLATION" for j in jobs) else 0


def cmd_poc(args: argparse.Namespace) -> int:
    """POC (SRS milestone "upload -> SAST -> transform -> 2 Worker Nodes -> aggregate -> speedup").

    Proves, on one machine, that a Python program is split into tasks, that N Worker Nodes pull and
    execute them, that the Master aggregates the results, and that the output equals a standard run.
    Uses its own temporary data folder and a free cluster port, so it never touches a running Master.
    """
    import tempfile
    from collections import Counter

    from master.core import MasterNode
    from master.sandbox import SandboxError

    path = Path(args.file) if args.file else Path(__file__).resolve().parents[1] / "examples/poc_count_primes.py"
    overrides = _overrides(args)
    overrides.setdefault("master", {}).update(import_poll_seconds=0,
                                              data_dir=args.data_dir or tempfile.mkdtemp(prefix="cc-poc-"))
    overrides.setdefault("cluster", {}).update(port=0, local_workers=args.workers, bind="127.0.0.1")
    cfg = load_config(args.config, overrides)
    node = MasterNode(cfg)
    say = lambda text="": print(text, flush=True)  # noqa: E731

    def wait_run(run):
        while run.state in ("PENDING", "RUNNING"):
            time.sleep(0.1)
        return run

    try:
        say(f"POC: {path.name} with {args.workers} Worker Node(s)\n")
        try:
            node.start()
        except SandboxError as exc:
            print(f"security screening unavailable: {exc}", file=sys.stderr)
            return 3
        online = node.runs.sched.wait_for_workers(args.workers, 30)
        say(f"0. Master ready; {online} Worker Node agent(s) connected to the scheduler on "
            f"{node.runs.sched.bind}:{node.runs.sched.port} (pull model, heartbeats every "
            f"{cfg.cluster.heartbeat_interval:g} s)")
        job = node.submit(path.name, path.read_bytes(), via="poc")
        while job.state in ("RECEIVED", "QUEUED", "VALIDATING", "SCREENING"):
            time.sleep(0.05)
        say(f"1. Master received the program: security {job.security_verdict}, analysis {job.eligibility_verdict}")
        if job.state != "READY":
            say(f"   stopped: {job.error or (node.get_report(job.id) or {}).get('eligibility', {}).get('summary')}")
            return 2
        for r in node.get_report(job.id)["eligibility"]["regions"]:
            say(f"   AST region {r['id']} line {r['line']} ({r['kind']}): {r['decision']} - "
                + (f"{r['template']}, split by {r['split']} ({r['split_rule']})" if r["decision"] == "GO" else r["reason"]))
        std = wait_run(node.runs.request(job.id, "standard", "basic", None))
        if std.state != "COMPLETED":
            say(f"   standard run {std.state}: {std.error}")
            return 1
        ref = std.metrics["standard"]
        say(f"2. Standard run (original program, 1 process on {ref['node']}): T_seq {ref['t_seq_ms']:.0f} ms, "
            f"program {ref['wall_ms']:.0f} ms")
        before = Counter({w["name"]: w["done"] for w in node.runs.sched.status()["workers"]})
        cl = wait_run(node.runs.request(job.id, "cluster", "basic", args.workers))
        if cl.state != "COMPLETED":
            say(f"   cluster run {cl.state}: {cl.error}")
            return 1
        par = cl.metrics["cluster"]
        after = Counter({w["name"]: w["done"] for w in node.runs.sched.status()["workers"]})
        pulled = {k: v for k, v in (after - before).items() if v}
        say(f"3. Master split the input into {par['tasks']} task(s); the Worker Nodes pulled and ran them: "
            + ", ".join(f"{k}: {v} task(s)" for k, v in sorted(pulled.items())))
        say(f"4. Master aggregated the results: T_par {par['t_par_ms']:.0f} ms, program {par['wall_ms']:.0f} ms, "
            f"{par['retries']} retries (smoke test {par['smoke_ms']:.0f} ms, counted as preparation)")
        say(f"   output: {par['stdout_preview'].strip()[:200]}")
        say(f"5. Compared with the standard run: {cl.validation['status']} ({cl.validation['method']}); "
            f"speedup T_seq/T_par = {cl.metrics['speedup']}x, whole program = {cl.metrics['program_speedup']}x")
        return 0 if cl.validation["status"] == "PASSED" else 1
    finally:
        node.stop()


def cmd_build(args: argparse.Namespace) -> int:
    from master.sandbox import build_image

    cfg = load_config(args.config)
    build_image(cfg.sandbox.image)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m master", description="Cluster Computing Master Node")
    ap.add_argument("--config", help="Control Parameter File (TOML)")
    sub = ap.add_subparsers(dest="command", required=True)
    s = sub.add_parser("serve", help="run the Master Node with its dashboard")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    c = sub.add_parser("check", help="screen files headlessly and print the verdicts")
    c.add_argument("files", nargs="+")
    c.add_argument("--json", action="store_true")
    for p in (s, c):
        p.add_argument("--backend", choices=["docker", "process"])
        p.add_argument("--mode", choices=["warm", "ephemeral"])
        p.add_argument("--data-dir")
    sub.add_parser("build-image", help="build the inspection sandbox image")
    pc = sub.add_parser("poc", help="POC: split a program into tasks, run them on N Worker Nodes, compare")
    pc.add_argument("file", nargs="?", help="program (default: examples/poc_count_primes.py)")
    pc.add_argument("--workers", type=int, default=2)
    pc.add_argument("--backend", choices=["docker", "services", "process"])
    pc.add_argument("--mode", choices=["warm", "ephemeral"])
    pc.add_argument("--data-dir")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.command == "serve" else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        return {"serve": cmd_serve, "check": cmd_check, "build-image": cmd_build, "poc": cmd_poc}[args.command](args)
    except ConfigError as exc:
        print(f"invalid Control Parameter File: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
