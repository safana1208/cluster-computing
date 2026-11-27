# Cluster Computing

A Python framework that screens submitted `.py` programs for security problems, uses `ast` to find
loops that can run in parallel, splits them into tasks, runs those tasks on Worker Nodes over a LAN
(for example Raspberry Pis), and checks the cluster output and speedup against a sequential run.

> **Branch `Daniel_Test`:** this is Daniel's implementation, kept separate from `main` for review and testing.

## Components

| Component | Folder | Role |
|---|---|---|
| **Master Server** | `master/` | Validates submitted `.py` files, runs security screening, decides cluster eligibility, schedules tasks, aggregates results, and serves the web dashboard (port 8080). Worker Nodes connect on the cluster port (7070). |
| **Worker Node** | `worker/` | Standard-library-only agent. Pulls tasks from the Master, runs each one in a restricted process (no network, memory limit), sends heartbeats, and returns results. |
| **AST analyzer** | `analyzer/` | AST security policy (`policy.py`), feature extraction, and the AST detection HTTP service (port 8000). |
| **AI engine** | `analyzer/ai_engine/` | Isolation Forest + Random Forest + hybrid scorer used for AI screening (port 8100). |
| **Security dashboard** | `master/dashboard/` | Live admin dashboard for the screening pipeline (port 8501). |
| **AST Master (vendored)** | `analyzer/vendor/ast_master/` | Third-party AST engine used by the analyzer. |

### Flow
1. Submit a `.py` file in the Master dashboard (or with `python -m master check`).
2. The Master checks syntax and runs security screening (SAST policy + AST + AI). Blocking findings stop the run, and the file is deleted or quarantined.
3. The AST analysis finds eligible loops and patterns and splits them into tasks (Go/No-Go per region).
4. Worker Nodes run the tasks. The Master merges the results, compares them with the sequential run, and reports T_seq, T_par and the speedup.

## Folder structure

```
.
├── analyzer/                   AST analysis + security policy + AI screening
│   ├── policy.py               SRS SAST policy
│   ├── parser.py, extractors.py, analyzer.py   AST features (uses AST Master)
│   ├── server.py               AST detection service (python -m analyzer.server)
│   ├── scanner.py              recursive supply-chain scanner (python -m analyzer.scanner)
│   ├── ai_engine/              AI models: train.py, predict.py, server.py, models/, features/, data/
│   ├── vendor/ast_master/      vendored AST Master engine
│   └── Dockerfile              AST service image
├── examples/                   cluster demo programs (prime counting, merge sort, concurrency tests)
├── master/                     Master Server (python -m master)
│   ├── __main__.py             CLI: serve | check | poc | build-image
│   ├── core.py, app.py         pipeline + web dashboard (static/index.html)
│   ├── inspector.py            security screening + eligibility (runs inside the sandbox)
│   ├── eligibility.py          AST Go/No-Go analysis and task templates
│   ├── cluster.py, runs.py     scheduler, task distribution, result aggregation
│   ├── sandbox.py              inspection sandboxes (docker | process)
│   ├── dashboard/              security pipeline dashboard (python -m master.dashboard.app)
│   ├── control_parameters.toml          config for local runs
│   ├── control_parameters.compose.toml  config inside Docker Compose
│   └── Dockerfile, Dockerfile.master    inspector sandbox image / Master image
├── shared/                     shared code, models, infrastructure and docs
│   ├── schemas.py              (team skeleton)
│   ├── artifacts/              pre-trained AI models (*.joblib) + training report
│   ├── docker-compose.yml      the whole stack
│   ├── run_pipeline.sh         build, train, test and start the dashboards with one command
│   ├── docs/                   Dashboard_User_Guide.pdf
│   └── reports/, datasets/real/, supply_chain_lab/   mount points used by Docker Compose
├── tests/                      system tests
│   ├── test_core_flow.py       the 5 core-flow tests
│   ├── samples/                packages for security screening (benign, malicious, typosquat, ...)
│   ├── pytest.ini, requirements.txt
│   └── Dockerfile              test runner image
├── worker/                     Worker Node agent (python -m worker, or copy worker.py to a Pi)
├── .gitignore
├── docker-compose.yml          `docker compose up -d` from the root (includes shared/docker-compose.yml)
├── README.md
└── requirements.txt            all Python dependencies for running locally
```

The empty files from the team skeleton (`master/main.py`, `master/scheduler.py`,
`master/result_merger.py`, `worker/executor.py`, `analyzer/ast_analyzer.py`, `shared/schemas.py`,
`examples/prime_counter.py`) are unchanged. The implementation lives in the modules listed above.
Each `*/Dockerfile*.dockerignore` file keeps local virtualenvs, trained models and untrusted data out of the images.

## Requirements

- **Python 3.11+** (3.13 is used in the Docker images)
- Linux recommended (Worker Node task isolation uses Linux user/network namespaces and falls back gracefully elsewhere)
- Optional: **Docker + Docker Compose v2** (with BuildKit, which is the default) for the full stack and sandboxed inspection

Python dependencies (`requirements.txt` pulls in the per-component files):

| File | Packages |
|---|---|
| `analyzer/ai_engine/requirements.txt` | numpy, pandas, scikit-learn, joblib |
| `master/dashboard/requirements.txt` | fastapi, uvicorn, websockets, httpx |
| `tests/requirements.txt` | pytest, httpx, websockets |
| `worker/` | standard library only |
| `analyzer/` (AST part) | standard library only (+ the vendored AST Master) |

## Installation

```bash
git clone -b Daniel_Test https://github.com/safana1208/cluster-computing.git
cd cluster-computing
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

All commands below are run from the repository root.

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
python -m master check --backend process examples/poc_count_primes.py tests/samples/malicious_backdoor/colorlogx/__init__.py
python -m analyzer.scanner tests/samples              # recursive scan with the local AI models
```

### Retrain the AI models (optional)
The pre-trained models are in `shared/artifacts/`. To retrain, start the AST service and run the trainer:
```bash
python -m analyzer.server --port 8000 &
python -m analyzer.ai_engine.train --ast-url http://127.0.0.1:8000
```

### Real Worker Nodes (e.g. Raspberry Pi)
On the Master, set `[cluster] bind = "0.0.0.0"`, a `token` of at least 16 characters, and
`local_workers = 0` in `master/control_parameters.toml`. Then, on each Worker Node:
```bash
python3 worker/worker.py --master <MASTER_IP>:7070 --token <cluster token> --slots 4
```
The Worker Node needs only `worker/worker.py` and Python 3.

### Full stack with Docker Compose
From the repository root:
```bash
docker compose up -d --build     # first time: builds the images, trains the models, runs the tests
docker compose up -d             # afterwards
docker compose ps                # status
docker compose down              # stop
```
- Master dashboard: http://127.0.0.1:8080
- Security dashboard: http://127.0.0.1:8501
- Test results: `docker compose logs tests`
- LAN access: `MASTER_BIND=0.0.0.0 CLUSTER_BIND=0.0.0.0 CLUSTER_PUBLISH=0.0.0.0 CLUSTER_TOKEN=<16+ chars> docker compose up -d`

The root `docker-compose.yml` only includes `shared/docker-compose.yml`, where the services are defined.
`shared/run_pipeline.sh` does the same in one step and returns the test suite's exit code.

## How to test

```bash
python -m pytest tests -v
```
This runs the 5 system tests in `tests/test_core_flow.py`. Each one starts a real Master Node and
3 local Worker Nodes:

1. Security screening: malicious code is blocked and purged, prohibited operations are rejected, safe code is allowed.
2. AST analysis: Go/No-Go decisions, task templates, and the transformed program.
3. Distributed execution: several Worker Nodes pull tasks, and the results are aggregated.
4. Correctness and performance: the cluster output matches the sequential run, with T_seq, T_par and the speedup reported.
5. Fault handling: a Worker Node dies mid-run and its task is retried elsewhere; program errors are not retried.

Inside Docker: `docker compose up -d --build`, then `docker compose logs tests`
(or `shared/run_pipeline.sh --down`, whose exit code is the test suite's exit code).

## Documentation
- `shared/docs/Dashboard_User_Guide.pdf`: user guide for the dashboard.
