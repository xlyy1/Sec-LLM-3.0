FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

ARG PIP_INDEX_URL=https://pypi.org/simple
RUN pip install --no-cache-dir --index-url "$PIP_INDEX_URL" \
    fastapi==0.128.0 \
    uvicorn==0.40.0 \
    docker==7.2.0 \
    pydantic==2.13.5

COPY runner.py .

EXPOSE 8090

HEALTHCHECK --interval=20s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/healthz', timeout=2)"

CMD ["uvicorn", "runner:app", "--host", "0.0.0.0", "--port", "8090"]
