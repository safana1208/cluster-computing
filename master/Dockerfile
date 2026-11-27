# Inspection sandbox for the Master Node: SRS SAST policy + AST Master + AI models + cluster eligibility.
#   docker build -f master/Dockerfile -t scs-inspector:latest .
# The Master Node starts it with --network none, a read-only root filesystem, no capabilities,
# a non-root user and memory/CPU/PID limits; the trained models are mounted read-only at /artifacts.
#
# The first layers are identical to analyzer/ai_engine/Dockerfile so the (slow on a Pi) wheel install is shared.
FROM python:3.13-slim-trixie

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ARTIFACT_DIR=/artifacts \
    SAMPLES_DIR=/app/samples \
    AST_SERVICE_URL=http://ast_detection:8000 \
    AI_HOST=0.0.0.0 \
    AI_PORT=8100

COPY analyzer/ai_engine/requirements.txt /tmp/requirements.txt
RUN pip install --only-binary=:all: -r /tmp/requirements.txt && rm /tmp/requirements.txt

ENV ASTMASTER_PATH=/opt/ast_master \
    PYTHONHASHSEED=0 \
    SCS_AI_MODE=local
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin inspector
COPY analyzer/vendor/ast_master /opt/ast_master
WORKDIR /app
COPY analyzer ./analyzer
COPY master/__init__.py master/eligibility.py master/inspector.py ./master/

USER 10001
CMD ["python", "-m", "master.inspector", "--serve"]
