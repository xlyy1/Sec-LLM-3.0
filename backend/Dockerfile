# Sec-LLM backend image: FastAPI + Agent runtime + security-tool sandbox client.
# The app connects to MySQL (see docker-compose.yml) and can talk to a host Ollama.
#
# Optional extras (build args):
#   INSTALL_BROWSERS=1   Chromium + OS deps for browser_* / Playwright tools
#   INSTALL_LOCAL_ML=1   torch + sentence-transformers for bundled BGE models
# Without them the API still starts; browser tools fail explicitly and RAG uses
# Ollama embeddings.

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

ARG PIP_INDEX_URL=https://pypi.org/simple
ARG INSTALL_LOCAL_ML=0
ARG INSTALL_BROWSERS=0

# Optional CPU torch + sentence-transformers. Kept behind a flag so the default
# image stays small and builds without the multi-hundred-MB ML dependency tree.
RUN --mount=type=cache,target=/root/.cache/pip \
    set -e; \
    if [ "$INSTALL_LOCAL_ML" = "1" ]; then \
        pip install --retries 10 --index-url https://download.pytorch.org/whl/cpu --no-deps torch; \
        pip install --retries 10 filelock typing_extensions sympy networkx jinja2 fsspec; \
        pip install --retries 10 --index-url "$PIP_INDEX_URL" -r requirements-ml.txt; \
    else \
        echo "Skipping local ML stack (INSTALL_LOCAL_ML != 1)"; \
    fi

COPY requirements.txt requirements.lock.txt ./
# The lock file is a host-verified freeze; --no-deps skips pip's resolver
# backtracking when the index has many incompatible major versions.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --retries 10 --no-deps --index-url "$PIP_INDEX_URL" -r requirements.lock.txt

RUN set -e; \
    if [ "$INSTALL_BROWSERS" = "1" ]; then \
        ok=0; \
        for i in 1 2 3 4; do \
            if playwright install --with-deps chromium; then ok=1; break; fi; \
            echo "playwright install failed (attempt $i), retrying..."; sleep 15; \
        done; \
        [ "$ok" = "1" ]; \
        rm -rf /var/lib/apt/lists/*; \
    else \
        echo "Skipping Chromium (INSTALL_BROWSERS != 1)"; \
    fi

# Non-root runtime user. Writable mount points are created here and owned by it,
# so named volumes inherit the right ownership on first use.
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /app/data /app/artifacts /app/temp /app/uploads /app/models /ms-playwright \
    && chown -R app:app /app /ms-playwright

COPY --chown=app:app . .

USER app

EXPOSE 8000

# Liveness only: the app must answer. Dependency readiness is /readyz.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
