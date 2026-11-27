"""The 5 system tests of the Cluster Computing core flow (SRS 5.1-5.6).

1. Security screening: malicious code blocked and purged, prohibited operations rejected, safe code allowed.
2. AST analysis: Go/No-Go decisions, task templates and the transformed program.
3. Distributed execution: tasks pulled by several Worker Nodes, results aggregated.
4. Correctness and performance: cluster output validated against the sequential run; T_seq, T_par, speedup.
5. Fault handling: a Worker Node dies mid-run, its task is retried elsewhere; program errors are not retried.

A real Master Node runs in a temporary folder: inspector as a plain process (AI off for speed), three local
Worker Node agents over TCP. Skipped where master / worker are not installed.
"""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
pytest.importorskip("master.runs")

from master.config import load_config  # noqa: E402
from master.core import MasterNode  # noqa: E402
from master.demo_programs import EXAMPLES, example_inputs  # noqa: E402
from master.eligibility import analyze_eligibility  # noqa: E402
from master.runs import compare_outputs  # noqa: E402

ACTIVE = ("RECEIVED", "QUEUED", "VALIDATING", "SCREENING")


@pytest.fixture(scope="module")
def master(tmp_path_factory):
    cfg = load_config(None, {"master": {"data_dir": str(tmp_path_factory.mktemp("master_data")),
                                        "import_poll_seconds": 0},
                             "sandbox": {"backend": "process", "pool_size": 2},
                             "security": {"ai_mode": "off"},
                             "cluster": {"port": 0, "local_workers": 3, "task_timeout_min": 20.0}})
    node = MasterNode(cfg)
    node.start()
    assert node.runs.sched.wait_for_workers(3, 30) >= 3, "local Worker Nodes did not connect"
    yield node
    node.stop()


def _submit(node, name, source=None, inputs=None):
    job = node.submit(name, (source if source is not None else EXAMPLES[name]["source"]).encode(),
                      inputs=example_inputs(name) if inputs is None else inputs)
    deadline = time.time() + 60
    while job.state in ACTIVE and time.time() < deadline:
        time.sleep(0.05)
    return job


def _run(node, job, mode, workers=None):
    run = node.runs.request(job.id, mode, "detailed", workers)
    deadline = time.time() + 240
    while run.state in ("PENDING", "RUNNING") and time.time() < deadline:
        time.sleep(0.1)
    return run


# ---------------------------------------------------------------------------------------------- 1
def test_security_screening_blocks_malicious_rejects_prohibited_and_allows_safe(master):
    # Malicious (SRS N3): blocked, file deleted, purged from the history database, never executed.
    bad = _submit(master, "n3_privilege.py")
    assert bad.state == "BLOCKED" and bad.security_verdict == "MALICIOUS" and bad.disposition == "DELETED"
    assert not (master.dirs["runs"] / bad.id).exists()
    assert bad.id not in {r["id"] for r in master.history.recent()}
    with pytest.raises(ValueError, match="malicious"):
        master.runs.request(bad.id, "standard", None, None)

    # Prohibited operation only (file write outside output/): rejected and not executed, but kept for editing.
    writes = "import os\ntotal = 0\nfor i in range(10):\n    total += i\nos.replace('a.tmp', 'report.txt')\n"
    rejected = _submit(master, "writes_report.py", writes, inputs={})
    assert rejected.security_verdict == "VIOLATION" and rejected.state == "REJECTED"
    assert (master.dirs["runs"] / rejected.id / "program.py").exists()
    with pytest.raises(ValueError, match="security violation"):
        master.runs.request(rejected.id, "standard", None, None)

    # Safe code, including threads and a write inside the run output folder, is allowed.
    safe = _submit(master, "safe.py", "import os\nos.replace('output/a.tmp', 'output/a.json')\n"
                                      "total = 0\nfor i in range(10):\n    total += i\nprint(total)\n", inputs={})
    assert safe.security_verdict == "SAFE" and safe.state == "READY"


# ---------------------------------------------------------------------------------------------- 2
def test_ast_analysis_decides_go_no_go_and_generates_tasks():
    mixed = analyze_eligibility(EXAMPLES["monte_carlo_sum.py"]["source"], "monte_carlo_sum.py")
    assert mixed["verdict"] == "PARTIALLY_ELIGIBLE"
    go, nogo = [r for r in mixed["regions"] if r["decision"] == "GO"], [r for r in mixed["regions"]
                                                                        if r["decision"] != "GO"]
    assert go[0]["template"] == "Sum / counter" and go[0]["split"] == "range"
    assert "def task_1(chunk" in go[0]["task_template"]
    assert "carried dependency" in nogo[0]["reason"]                       # N1-style loop stays sequential
    assert "__mediator__.run_region('task_1'" in mixed["transformed_program"]
    compile(mixed["transformed_program"], "<transformed>", "exec")       # T1

    threads = analyze_eligibility(EXAMPLES["w5_threaded_hash.py"]["source"], "w5.py")
    assert threads["verdict"] == "ELIGIBLE" and threads["regions"][0]["kind"] == "thread-group"
    assert "__mediator__.Thread(" in threads["transformed_program"]        # SRS 5.3.2 thread-to-task rewrite

    not_eligible = analyze_eligibility((ROOT / "examples/concurrency_test.py").read_text(), "c.py")
    assert not_eligible["verdict"] == "NOT_ELIGIBLE"
    reasons = " ".join(c["detail"] for c in not_eligible["program_checks"])
    assert "multiprocessing" in reasons and "Semaphore" in reasons        # P1, with the reasons listed


# ---------------------------------------------------------------------------------------------- 3
def test_distributed_execution_pulls_tasks_on_several_workers_and_aggregates(master):
    # Thread group + sum loop + two-phase sort: three templates, three kinds of aggregation.
    job = _submit(master, "concurrency_go.py")
    assert job.state == "READY", job.error
    before = {w.name: w.done for w in master.runs.sched.online()}
    run = _run(master, job, "cluster")
    assert run.state == "COMPLETED", run.error
    cluster = run.metrics["cluster"]
    assert {r["kind"] for r in cluster["regions"]} == {"thread-group", "for-loop", "sort"}
    assert cluster["tasks"] > 3
    pulled = {w.name: w.done - before.get(w.name, 0) for w in master.runs.sched.online()}
    assert sum(1 for n in pulled.values() if n > 0) >= 2                 # pull model: several nodes took tasks
    assert cluster["stdout_preview"].startswith("800 ")                          # aggregated thread-group results


# ---------------------------------------------------------------------------------------------- 4
def test_cluster_output_is_validated_against_the_sequential_run_with_speedup(master):
    job = _submit(master, "poc_count_primes.py")
    std = _run(master, job, "standard")
    assert std.state == "COMPLETED", std.error
    assert std.metrics["standard"]["t_seq_ms"] > 0
    cl = _run(master, job, "cluster", workers=2)
    assert cl.state == "COMPLETED", cl.error
    assert cl.validation["status"] == "PASSED"                           # FR-5.2
    assert "216816" in cl.metrics["cluster"]["stdout_preview"]
    assert "216816" in (cl.out_dir / "result.txt").read_text()               # full output kept in a file
    assert cl.metrics["cluster"]["t_par_ms"] > 0 and cl.metrics["speedup"] > 0   # FR-5.5
    # The validator rejects real differences: tolerant on floats, strict on types and values.
    assert compare_outputs("1.0000000000001\n", "1.0\n", False)["status"] == "PASSED"
    assert compare_outputs("[('x', 2)]\n", "[['x', 2]]\n", False)["status"] == "FAILED"
    assert compare_outputs("1\n", "2\n", False)["status"] == "FAILED"


# ---------------------------------------------------------------------------------------------- 5
def test_worker_failure_is_retried_and_program_errors_are_not(master):
    job = _submit(master, "w2_hash_search.py")
    _run(master, job, "standard")
    run = master.runs.request(job.id, "cluster", "detailed", None)
    deadline = time.time() + 60
    while time.time() < deadline:                                        # kill a node while it holds a task
        busy = [w for w in master.runs.sched.online() if w.inflight]
        if busy:
            os.kill(int(busy[0].info["pid"]), signal.SIGKILL)
            break
        time.sleep(0.01)
    while run.state in ("PENDING", "RUNNING") and time.time() < deadline + 120:
        time.sleep(0.1)
    assert run.state == "COMPLETED", run.error                           # FR-5.3: reassigned, run completes
    assert run.metrics["cluster"]["retries"] >= 1 and run.validation["status"] == "PASSED"
    assert master.runs.sched.wait_for_workers(3, 20) >= 3                # the local node was restarted

    crash = _submit(master, "n4_zero_division.py")                       # FR-5.4: deterministic error
    failed = _run(master, crash, "cluster")
    assert failed.state == "FAILED" and failed.error["type"] == "ZeroDivisionError"
    assert failed.error["category"] == "program error" and failed.error["line"] == 4
