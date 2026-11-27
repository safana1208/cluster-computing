"""Inspection worker: runs INSIDE the isolated sandbox (Docker container, ``--network none``).

Protocol: JSON lines on stdin/stdout, so the container needs no network at all.

    -> {"op": "inspect", "id": "...", "filename": "x.py", "source": "...", "options": {...}}
    <- {"type": "result", "id": "...", "ok": true, "security": {...}, "eligibility": {...} | null, ...}
    -> {"op": "ping", "id": "..."}            <- {"type": "pong", "id": "..."}

On start it loads the AST analyzers and the AI models once and prints
``{"type": "ready", ...}``, so a warm sandbox answers in milliseconds.

Order inside one inspection (SRS FR-2.4: security first):

1. Security screening (mandatory): SRS SAST policy (``analyzer.policy``), AST Master +
   built-in AST features (``ast_detection``), AI models (``ai_engine``: Random Forest +
   Isolation Forest + hybrid scorer). The verdicts are fused so that the AI can raise the
   verdict of the static layers but never lower it.
2. Cluster eligibility (``master.eligibility``), only when the program was not blocked.

The submitted code is parsed, never executed, here.

    python -m master.inspector --serve          # sandbox entry point
    python -m master.inspector file.py          # one-off, prints the JSON result
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
import traceback
from typing import Any

from analyzer.analyzer import PackageAnalyzer
from analyzer.parser import AstMasterParser
from analyzer.policy import POLICY_VERSION, screen_source
from master.eligibility import DEFAULT_ALLOWLIST, analyze_eligibility

MAX_SOURCE_CHARS = 2 * 1024 * 1024
#: SAST categories that indicate an attack, not just a capability the cluster doesn't allow (SRS Table 3.2.1).
ATTACK_CATEGORIES = frozenset({"dynamic-exec", "os-command", "privilege", "hooking", "obfuscation"})
COMPILE_ONLY_RULES = frozenset({"compile", "builtins.compile"})


class InProcessASTClient:
    """Stands in for ``analyzer.ai_engine.ast_client.ASTServiceClient`` without HTTP: the sandbox has no network.

    Every result still goes through the client's schema / identity / feature-digest verification.
    """

    def __init__(self, analyzer: PackageAnalyzer) -> None:
        self.analyzer = analyzer

    def analyze_batch(self, packages: list[dict[str, Any]], chunk_size: int = 100) -> list[dict[str, Any]]:
        from analyzer.ai_engine.ast_client import ASTServiceClient

        return [ASTServiceClient.verify(self.analyzer.analyze(p["name"], p["files"]), expected_name=p["name"])
                for p in packages]

    def health(self) -> dict[str, Any]:
        return {"backend": self.analyzer.parser.backend_info()}


class RemoteRiskEngine:
    """The AI node (``ai_engine`` service) over HTTP; it calls the AST node (``ast_detection``) itself.

    Used by the docker-compose deployment: Master Node -> AI node -> AST node. Same report format
    as the in-process :class:`analyzer.ai_engine.predict.RiskEngine`.
    """

    def __init__(self, url: str, timeout: float = 15.0, wait: float = 60.0) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout
        deadline = time.monotonic() + wait
        while True:  # the AI node may still be loading its models
            try:
                self.health = self._call("GET", "/health")
                if self.health.get("model", {}).get("loaded") and self.health.get("ast_service", {}).get("reachable"):
                    break
                error = f"AI node not ready: {self.health.get('model')} / {self.health.get('ast_service')}"
            except OSError as exc:
                error = f"AI node unreachable at {self.url}: {exc}"
            if time.monotonic() >= deadline:
                raise RuntimeError(error)
            time.sleep(1.0)

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        import urllib.error
        import urllib.request

        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (internal URL)
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            if path == "/health":  # 503 while degraded still carries the details
                return json.loads(exc.read() or b"{}")
            raise OSError(f"AI node {path} -> HTTP {exc.code}: {exc.read()[:300]!r}") from exc

    def assess(self, packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return self._call("POST", "/assess", {"packages": packages})["reports"]

    def info(self) -> dict[str, Any]:
        model = self.health.get("model", {})
        return {"trained_at": model.get("trained_at"), "decision_threshold": model.get("decision_threshold"),
                "models": ["RandomForest", "IsolationForest", "Hybrid scorer"], "node": self.url,
                "ast_node": self.health.get("ast_service", {}).get("backend")}


class Inspector:
    """Holds the loaded analyzers/models for the lifetime of the sandbox process."""

    def __init__(self, artifact_dir: str | None = None, ai_mode: str = "local", ai_url: str | None = None) -> None:
        started = time.perf_counter()
        self.analyzer = PackageAnalyzer(AstMasterParser())
        self.ai_mode = ai_mode
        self.engine = None
        self.ai_error: str | None = None
        self.model_info: dict[str, Any] = {}
        if ai_mode == "local" and ai_url:
            try:
                self.engine = RemoteRiskEngine(ai_url)
                self.model_info = self.engine.info()
            except Exception as exc:  # fail-closed later
                self.ai_error = f"{type(exc).__name__}: {exc}"[:300]
        elif ai_mode == "local":
            try:
                from analyzer.ai_engine.events import EventEmitter
                from analyzer.ai_engine.predict import RiskEngine

                self.engine = RiskEngine(artifact_dir or os.environ.get("ARTIFACT_DIR", "shared/artifacts"),
                                         InProcessASTClient(self.analyzer), EventEmitter("ai_engine", url=""))
                meta = self.engine.scorer.metadata
                self.model_info = {"trained_at": meta.get("created_at"),
                                   "decision_threshold": self.engine.scorer.config.decision_threshold,
                                   "models": ["RandomForest", "IsolationForest", "Hybrid scorer"]}
            except Exception as exc:  # fail-closed later: inspections report the AI as unavailable
                self.ai_error = f"{type(exc).__name__}: {exc}"[:300]
        self.load_ms = round((time.perf_counter() - started) * 1000, 1)

    def ready_message(self) -> dict[str, Any]:
        return {"type": "ready", "pid": os.getpid(), "host": platform.node(), "python": platform.python_version(),
                "load_ms": self.load_ms, "policy_version": POLICY_VERSION,
                "astmaster": self.analyzer.parser.backend_info(),
                "ai": {"mode": self.ai_mode, "loaded": self.engine is not None, "error": self.ai_error,
                       **self.model_info}}

    # ------------------------------------------------------------------ security
    def security(self, filename: str, source: str, options: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        timings: dict[str, float] = {}
        t = time.perf_counter()
        policy = screen_source(source, filename, tuple(options.get("output_dirs") or ("output",)))
        timings["policy_ms"] = round((time.perf_counter() - t) * 1000, 2)
        if policy.parse_error:
            raise RuntimeError(f"security screening could not parse the file: {policy.parse_error}")

        name = os.path.splitext(os.path.basename(filename))[0] or "program"
        t = time.perf_counter()
        ai: dict[str, Any] = {"enabled": self.ai_mode == "local", "loaded": self.engine is not None}
        ast_result: dict[str, Any]
        if self.engine is not None:
            report = self.engine.assess([{"name": name, "files": {filename: source}}])[0]
            sup, ano, sta = report["layers"]["supervised"], report["layers"]["anomaly"], report["layers"]["ast_static"]
            ai.update(risk_score=report["risk_score"], severity=report["severity"], action=report["action"],
                      flagged=report["flagged"], threat_probability=sup["threat_probability"],
                      anomaly_percentile=ano["percentile"], predicted_attack_type=report["predicted_attack_type"],
                      closest_known_attack=report["closest_known_attack"],
                      detection_layers=report["detection_layers"], verification_passed=report["verification"]["passed"],
                      ast_influence=report["ast_influence"], top_factors=report["top_factors"][:5],
                      layers={"ast_static": sta["component"], "random_forest": sup["threat_probability"],
                              "isolation_forest": ano["component"]})
            ast_result = {"static_score": sta["score"], "verdict": sta["verdict"], "source": sta["source"],
                          "findings": report["findings"], "risky_nodes": report["ast_risky_nodes"]}
        else:
            if self.ai_mode == "local":
                raise RuntimeError(f"AI models unavailable ({self.ai_error}); screening incomplete (fail-closed)")
            res = self.analyzer.analyze(name, {filename: source})
            ast_result = {"static_score": res["static_risk"]["score"], "verdict": res["static_risk"]["verdict"],
                          "source": res["static_risk"]["source"], "findings": res["findings"][:10],
                          "risky_nodes": res["risky_nodes"][:25]}
        timings["ast_ai_ms"] = round((time.perf_counter() - t) * 1000, 2)
        ast_result["astmaster"] = (self.model_info.get("ast_node") if isinstance(self.engine, RemoteRiskEngine)
                                   else None) or self.analyzer.parser.backend_info()
        if isinstance(self.engine, RemoteRiskEngine):
            ai["node"], ast_result["node"] = self.engine.url, "ast_detection (via the AI node)"

        # Verdicts (SRS 3.2): a blocking SAST finding always rejects the program (FR-2.3). Whether it is also
        # MALICIOUS (supply-chain attack: deleted and purged) depends on WHAT was found:
        #   * attack indicators - code execution, shell commands, privilege/credential access, interpreter
        #     tampering, obfuscation - or AST Master / the AI independently reporting an attack -> MALICIOUS;
        #   * only restricted capabilities - file writes, network, deserialization, process control - in code
        #     that no other layer finds suspicious -> VIOLATION: rejected and never executed, but kept so the
        #     operator can fix and resubmit it (FR-1.6). Ordinary programs that write a report file are not attacks.
        reasons: list[str] = []
        level = 0  # 0 SAFE, 1 SUSPICIOUS, 2 VIOLATION, 3 MALICIOUS
        blocking = [f for f in policy.findings if f.action == "block"]

        def attack_indicator(f: Any) -> bool:
            # compile() only builds a code object; running it needs exec/eval/__import__/importlib, which stay
            # attack indicators. A lone compile() (e.g. a syntax check) is a restricted capability.
            return f.category in ATTACK_CATEGORIES and f.rule not in COMPILE_ONLY_RULES

        attack = sorted({f.category for f in blocking if attack_indicator(f)})
        restricted = sorted({f.category for f in blocking if not attack_indicator(f)} - set(attack))
        if attack:
            reasons.append(f"SRS SAST policy: {len(blocking)} blocking finding(s), attack indicator(s): "
                           f"{', '.join(attack)}")
            level = 3
        elif restricted:
            reasons.append(f"SRS SAST policy: {len(blocking)} blocking finding(s) ({', '.join(restricted)}): "
                           "not allowed in the cluster")
            level = 2
        elif policy.findings:
            reasons.append(f"SRS SAST policy: {len(policy.findings)} warning(s)")
            level = max(level, 1)
        if ast_result["verdict"] == "MALICIOUS":
            reasons.append("AST Master: MALICIOUS (critical supply-chain indicator)")
            level = 3
        elif ast_result["verdict"] == "SUSPICIOUS":
            reasons.append("AST Master: SUSPICIOUS")
            level = 3 if restricted else max(level, 1)  # a second, independent layer confirms the policy block
        if ai.get("action") == "BLOCK":
            reasons.append(f"AI models: {ai['severity']} risk {ai['risk_score']:.3f} → BLOCK "
                           f"({ai['predicted_attack_type']})")
            level = 3
        elif ai.get("action") == "QUARANTINE_REVIEW":
            reasons.append(f"AI models: {ai['severity']} risk {ai['risk_score']:.3f} → review")
            level = 3 if restricted else max(level, 1)
        if level == 1 and options.get("block_on_suspicious"):
            reasons.append("block_on_suspicious is set in the Control Parameter File")
            level = 2
        verdict = ("SAFE", "SUSPICIOUS", "VIOLATION", "MALICIOUS")[level]
        return {
            "verdict": verdict, "blocked": level >= 2, "malicious": level == 3, "reasons": reasons or ["no layer raised a concern"],
            "ai_mode": self.ai_mode,
            "layers": {"policy": policy.to_dict(), "ast": ast_result, "ai": ai},
            "timings": timings, "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }

    # ------------------------------------------------------------------ one request
    def inspect(self, request: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        filename = str(request.get("filename") or "program.py")[:200]
        source = request.get("source")
        options = request.get("options") or {}
        if not isinstance(source, str) or len(source) > MAX_SOURCE_CHARS:
            raise ValueError("source missing or too large")
        security = self.security(filename, source, options)
        eligibility = None
        if not security["blocked"]:  # FR-2.4: parallelization analysis only after screening passed
            eligibility = analyze_eligibility(
                source, filename, options.get("library_allowlist") or DEFAULT_ALLOWLIST,
                int(options.get("chunk_factor", 4)), int(options.get("worker_nodes", 1)))
            eligibility["astmaster_transform"] = self.astmaster_transform(source, filename, eligibility)
        return {"security": security, "eligibility": eligibility,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2)}

    @staticmethod
    def astmaster_transform(source: str, filename: str, eligibility: dict[str, Any]) -> dict[str, Any] | None:
        """AST Master's executable thread-to-cluster transform (its own runtime Mediator), when it applies."""
        if not any(c["construct"] == "threading.Thread" for c in eligibility.get("concurrency", [])):
            return None
        try:
            from astmaster.pipeline import analyze_source
        except ImportError:
            return {"available": False, "reason": "AST Master not importable"}
        result = analyze_source(source.encode("utf-8"), filename, security=False)
        return {
            "available": True, "feasible": result.feasible,
            "templates": [{"template_id": t.template_id, "target": t.target, "sites": len(t.sites)}
                          for t in result.templates],
            "issues": [{"severity": i.severity.value, "code": i.code, "message": i.message, "line": i.lineno}
                       for i in result.issues if i.severity.value != "info"][:15],
            "transformed_program": result.transformed_source if result.feasible else None,
        }


def serve(inspector: Inspector) -> int:
    """JSON-lines loop. Results go to the real stdout; anything else printed goes to stderr."""
    out = os.fdopen(os.dup(1), "w", encoding="utf-8", buffering=1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr

    def send(message: dict[str, Any]) -> None:
        out.write(json.dumps(message, default=str) + "\n")
        out.flush()

    send(inspector.ready_message())
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        rid = None
        try:
            request = json.loads(line)
            rid = request.get("id")
            if request.get("op") == "ping":
                send({"type": "pong", "id": rid, "pid": os.getpid()})
                continue
            if request.get("op") == "exit":
                break
            result = inspector.inspect(request)
            send({"type": "result", "id": rid, "ok": True, "pid": os.getpid(), "host": platform.node(), **result})
        except (Exception, RecursionError, MemoryError) as exc:
            send({"type": "result", "id": rid, "ok": False, "pid": os.getpid(),
                  "error": f"{type(exc).__name__}: {exc}"[:500], "trace": traceback.format_exc()[-1500:]})
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Master Node inspection worker (sandboxed)")
    ap.add_argument("file", nargs="?")
    ap.add_argument("--serve", action="store_true", help="JSON-lines server on stdin/stdout")
    ap.add_argument("--artifacts", default=os.environ.get("ARTIFACT_DIR"))
    ap.add_argument("--ai-mode", default=os.environ.get("SCS_AI_MODE", "local"), choices=["local", "off"])
    ap.add_argument("--ai-url", default=os.environ.get("SCS_AI_URL"),
                    help="use the AI node (ai_engine service, which calls the AST node) instead of local models")
    args = ap.parse_args(argv)
    sys.setrecursionlimit(5000)
    inspector = Inspector(args.artifacts, args.ai_mode, args.ai_url)
    if args.serve:
        return serve(inspector)
    if not args.file:
        ap.error("give a file or --serve")
    with open(args.file, encoding="utf-8") as fh:
        print(json.dumps(inspector.inspect({"filename": os.path.basename(args.file), "source": fh.read()}),
                         indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
