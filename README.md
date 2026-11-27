# Cluster Computing

A Python framework that screens submitted `.py` programs for security problems, uses `ast` to find
loops that can run in parallel, splits them into tasks, runs those tasks on Worker Nodes over a LAN
(for example Raspberry Pis), and checks the cluster output and speedup against a sequential run.

> **Branch `Daniel_Test`:** this is Daniel's implementation, kept separate from `main` for review and testing.

## Components

| Component | Folder | Role |
|---|---|---|
| **Master Server** | `master/` | Validates submitted `.py` files, runs security screening (SAST policy + AST + AI), decides cluster eligibility, schedules tasks, aggregates results, and serves the web dashboard (port 8080). Worker Nodes connect on the cluster port (7070). |
| **Worker Node** | `worker/` | Standard-library-only agent. Pulls tasks from the Master, runs each one in a restricted process (no network, memory limit), sends heartbeats, and returns results. |
| **AST analyzer** | `analyzer/` | AST security policy (`policy.py`), feature extraction, and the AST detection HTTP service (port 8000). |
| **AI engine** | `ai_engine/` | Isolation Forest + Random Forest + hybrid scorer used for AI screening (port 8100). |
| **Security dashboard** | `dashboard/` | Live admin dashboard for the screening pipeline (port 8501). |
| **AST Master (vendored)** | `vendor/ast_master/` | Third-party AST engine used by the analyzer. |

### Flow
1. Submit a `.py` file in the Master dashboard (or with `python -m master check`).
2. The Master checks syntax and runs security screening. Blocking findings stop the run, and the file is deleted or quarantined.
3. The AST analysis finds eligible loops and patterns and splits them into tasks (Go/No-Go per region).
4. Worker Nodes run the tasks. The Master merges the results, compares them with the sequential run, and reports T_seq, T_par and the speedup.

## Folder structure

```
.
├── master/                 Master Server (python -m master)
│   ├── __main__.py         CLI: serve | check | poc | build-image
│   ├── core.py, app.py     pipeline + web dashboard (static/index.html)
│   ├── inspector.py        security screening + eligibility (runs inside the sandbox)
│   ├── eligibility.py      AST Go/No-Go analysis and task templates
│   ├── cluster.py, runs.py scheduler, task distribution, result aggregation
│   ├── sandbox.py          inspection sandboxes (docker | process)
│   ├── control_parameters.toml          config for local runs
│   ├── control_parameters.compose.toml  config inside Docker Compose
│   └── Dockerfile, Dockerfile.master    inspector sandbox image / Master image
├── worker/                 Worker Node agent (python -m worker, or copy worker.py to a Pi)
├── analyzer/               AST analysis + security policy + AST HTTP service
├── ai_engine/              AI models: training, prediction, HTTP service
├── dashboard/              security pipeline dashboard
├── shared/                 shared schemas (team skeleton)
├── examples/               cluster demo programs (prime counting, merge sort, concurrency tests)
├── samples/                test packages for security screening (benign, malicious, typosquat, ...)
├── artifacts/              pre-trained AI models (*.joblib) + training report
├── vendor/ast_master/      vendored AST Master engine
├── tests/                  system tests (test_core_flow.py) + test runner image
├── docs/                   Dashboard_User_Guide.pdf
├── scanner.py              recursive supply-chain scanner (CLI)
├── docker-compose.yml      the whole stack
├── run_pipeline.sh         build, train, test and start the dashboards with one command
├── requirements.txt        all Python dependencies for running locally
└── pytest.ini
```

The empty files from the team skeleton (`master/main.py`, `master/scheduler.py`,
`master/result_merger.py`, `worker/executor.py`, `analyzer/ast_analyzer.py`, `shared/schemas.py`,
`examples/prime_counter.py`) are unchanged. The implementation lives in the modules listed above.

## Requirements

- **Python 3.11+** (3.13 is used in the Docker images)
- Linux recommended (Worker Node task isolation uses Linux user/network namespaces and falls back gracefully elsewhere)
- Optional: **Docker + Docker Compose v2** for the full containerised stack and sandboxed inspection

Python dependencies (`requirements.txt` pulls in the per-component files):

| File | Packages |
|---|---|
| `ai_engine/requirements.txt` | numpy, pandas, scikit-learn, joblib |
| `dashboard/requirements.txt` | fastapi, uvicorn, websockets, httpx |
| `tests/requirements.txt` | pytest, httpx, websockets |
| `worker/` | standard library only |
| `analyzer/` | standard library only (+ the vendored AST Master) |

## Installation

```bash
git clone -b Daniel_Test https://github.com/safana1208/cluster-computing.git
cd cluster-computing
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## How to run

### Quick demo (no Docker): split, run on 2 workers, aggregate, compare
```bash
python -m master poc --workers 2                     # default: examples/poc_count_primes.py
python -m master poc examples/merge_sort_cluster.py --workers 2
```
Expected result: security `SAFE`, analysis `ELIGIBLE`, comparison `PASSED (exact match)`, and a speedup above 1x.

### Master dashboard (no Docker)
```bash
python -m master serve --backend process             # open http://127.0.0.1:8080
```
`--backend process` runs inspection without container isolation and is meant for development only.
For isolated inspection, build the sandbox image once and use the default `docker` backend:
```bash
python -m master build-image
python -m master serve
```

### Screen files from the command line
```bash
python -m master check --backend process examples/poc_count_primes.py examples/concurrency_test.py
```

### Real Worker Nodes (e.g. Raspberry Pi)
On the Master, set `[cluster] bind = "0.0.0.0"`, a `token` of at least 16 characters, and
`local_workers = 0` in `master/control_parameters.toml`. Then, on each Worker Node:
```bash
python3 worker/worker.py --master <MASTER_IP>:7070 --token <cluster token> --slots 4
```
The Worker Node needs only `worker/worker.py` and Python 3.

### Full stack with Docker Compose
```bash
./run_pipeline.sh            # build, train the models, run the tests, keep the dashboards running
# or
docker compose up --build
```
- Master dashboard: http://127.0.0.1:8080
- Security dashboard: http://127.0.0.1:8501
- Stop everything: `docker compose down`
- LAN access: `MASTER_BIND=0.0.0.0 CLUSTER_BIND=0.0.0.0 CLUSTER_PUBLISH=0.0.0.0 CLUSTER_TOKEN=<16+ chars> docker compose up -d`

## How to test

```bash
python -m pytest -v
```
This runs the 5 system tests in `tests/test_core_flow.py`. Each one starts a real Master Node and
3 local Worker Nodes:

1. Security screening: malicious code is blocked and purged, prohibited operations are rejected, safe code is allowed.
2. AST analysis: Go/No-Go decisions, task templates, and the transformed program.
3. Distributed execution: several Worker Nodes pull tasks, and the results are aggregated.
4. Correctness and performance: the cluster output matches the sequential run, with T_seq, T_par and the speedup reported.
5. Fault handling: a Worker Node dies mid-run and its task is retried elsewhere; program errors are not retried.

Inside Docker: `./run_pipeline.sh --down` (the exit code is the test suite's exit code).

## Documentation
- `docs/Dashboard_User_Guide.pdf`: user guide for the dashboard.
