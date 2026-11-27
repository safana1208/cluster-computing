"""System self-test: runs the project's own core-flow tests (tests/test_core_flow.py) on the Master.

This is trusted project code, started from the dashboard - not an uploaded program, so it is not screened
or distributed. The tests start their own temporary Master Node and Worker Nodes (free ports, temporary
folder), so the running system and its data are not touched. Only one self-test runs at a time.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from master.config import PROJECT_ROOT

TEST_FILE = "tests/test_core_flow.py"
_LINE = re.compile(r"::(test_\w+)\s+(PASSED|FAILED|ERROR|SKIPPED)")
_TITLES = {
    "test_security_screening_blocks_malicious_rejects_prohibited_and_allows_safe": "Security screening",
    "test_ast_analysis_decides_go_no_go_and_generates_tasks": "AST analysis and transformation",
    "test_distributed_execution_pulls_tasks_on_several_workers_and_aggregates": "Distributed execution and aggregation",
    "test_cluster_output_is_validated_against_the_sequential_run_with_speedup": "Validation and speedup",
    "test_worker_failure_is_retried_and_program_errors_are_not": "Fault handling and retries",
}


class SelfTest:
    def __init__(self, publish: Callable[..., Any], timeout: float = 600.0) -> None:
        self.publish = publish
        self.timeout = timeout
        self._lock = threading.Lock()
        self.state: dict[str, Any] = {"status": "never run"}

    def available(self) -> bool:
        if not (PROJECT_ROOT / TEST_FILE).is_file():
            return False
        try:
            import pytest  # noqa: F401
        except ImportError:
            return False
        return True

    def status(self) -> dict[str, Any]:
        return {**self.state, "available": self.available()}

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self.state.get("status") == "running":
                raise RuntimeError("a self-test is already running")
            if not self.available():
                raise RuntimeError(f"{TEST_FILE} or pytest is not installed on this Master")
            self.state = {"status": "running", "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                          "tests": [{"name": n, "title": t, "result": "pending"} for n, t in _TITLES.items()],
                          "output": "", "duration_s": None, "passed": 0, "failed": 0}
        threading.Thread(target=self._run, name="mn-selftest", daemon=True).start()
        self._publish()
        return self.status()

    def _publish(self) -> None:
        self.publish("selftest", selftest={k: v for k, v in self.status().items() if k != "output"})

    def _run(self) -> None:
        started = time.perf_counter()
        cmd = [sys.executable, "-m", "pytest", "-v", "-p", "no:cacheprovider", "--color=no", TEST_FILE]
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        lines: list[str] = []
        try:
            proc = subprocess.Popen(cmd, cwd=PROJECT_ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1, start_new_session=True)
            killer = threading.Timer(self.timeout, proc.kill)
            killer.start()
            assert proc.stdout is not None
            for line in proc.stdout:
                lines.append(line.rstrip())
                m = _LINE.search(line)
                if m:
                    for t in self.state["tests"]:
                        if t["name"] == m.group(1):
                            t["result"] = m.group(2)
                    self._publish()
            code = proc.wait()
            killer.cancel()
        except OSError as exc:
            lines.append(f"could not start pytest: {exc}")
            code = -1
        tests = self.state["tests"]
        passed = sum(t["result"] == "PASSED" for t in tests)
        failed = sum(t["result"] in ("FAILED", "ERROR") for t in tests)
        for t in tests:
            if t["result"] == "pending":
                t["result"] = "NOT RUN"
        self.state.update(status="passed" if code == 0 and passed == len(tests) else "failed", passed=passed,
                          failed=failed, exit_code=code, duration_s=round(time.perf_counter() - started, 1),
                          output="\n".join(lines[-400:]))
        self._publish()
