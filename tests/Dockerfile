# Test runner: the 5 core-flow system tests (tests/test_core_flow.py). They start their own Master Node
# (inspector as a process) and local Worker Node agents inside this container.
FROM python:3.13-slim-trixie

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ASTMASTER_PATH=/opt/ast_master \
    ARTIFACT_DIR=/artifacts \
    SAMPLES_DIR=/app/samples

COPY ai_engine/requirements.txt /tmp/ai_engine/requirements.txt
COPY tests/requirements.txt /tmp/tests/requirements.txt
RUN pip install --only-binary=:all: -r /tmp/tests/requirements.txt && rm -r /tmp/ai_engine /tmp/tests
RUN useradd --uid 10001 --create-home tester && install -d -o tester -g tester /results
COPY vendor/ast_master /opt/ast_master
WORKDIR /app
COPY ai_engine ./ai_engine
COPY analyzer ./analyzer
COPY master ./master
COPY worker ./worker
COPY samples ./samples
COPY examples ./examples
COPY tests ./tests
COPY pytest.ini ./

USER tester
CMD ["python", "-m", "pytest", "-v", "--junitxml=/results/junit.xml"]
