"""Structured logging, request correlation and Prometheus metrics.

Kept dependency-light (stdlib + prometheus-client + starlette) so it can be
imported before the FastAPI app is built.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

from prometheus_client import Counter, Gauge, Histogram
from starlette.datastructures import Headers, MutableHeaders

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")

_SERVICE_NAME = "sec-llm-api"
_REQUEST_ID_RE = re.compile(r"[^A-Za-z0-9._-]")
_ID_SEGMENT_RE = re.compile(r"/(?:[0-9a-f]{8}|\d{1,12})(?=/|$)")

HTTP_REQUESTS = Counter(
    "sec_llm_http_requests_total",
    "HTTP requests handled by the API.",
    ["method", "path", "status"],
)
HTTP_DURATION = Histogram(
    "sec_llm_http_request_duration_seconds",
    "HTTP request latency in seconds.",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)
AGENT_TASKS_RUNNING = Gauge(
    "sec_llm_agent_tasks_running",
    "Agent tasks currently executing in this process.",
)
LLM_TOKENS = Counter(
    "sec_llm_llm_tokens_total",
    "LLM tokens consumed, by model and kind.",
    ["model", "kind"],
)


class RequestIdFilter(logging.Filter):
    """Attach the current request id to every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line; keeps the fields we actually query."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "service": _SERVICE_NAME,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }
        for key in ("method", "path", "status", "duration_ms"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str | None = None) -> None:
    """Route stdlib + uvicorn logs through one JSON handler."""
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RequestIdFilter())
    root.addHandler(handler)
    root.setLevel((level or os.getenv("LOG_LEVEL", "INFO")).upper())

    # Uvicorn installs its own handlers before importing the app; fold them in.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("httpx").setLevel(logging.WARNING)


def _normalize_path(path: str) -> str:
    """Collapse ids so the Prometheus path label stays low-cardinality."""
    return _ID_SEGMENT_RE.sub("/{id}", path)


class RequestContextMiddleware:
    """Pure ASGI middleware: request id, access log and latency metrics.

    Pure ASGI (instead of BaseHTTPMiddleware) keeps StreamingResponse and SSE
    behaviour unchanged.
    """

    def __init__(self, app):
        self.app = app
        self.logger = logging.getLogger("sec_llm.access")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        incoming = headers.get("x-request-id", "")
        request_id = _REQUEST_ID_RE.sub("", incoming)[:64] or uuid.uuid4().hex
        token = request_id_var.set(request_id)

        method = scope.get("method", "?")
        started = time.perf_counter()
        status = {"code": 500}

        async def send_with_id(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
                MutableHeaders(scope=message)["X-Request-ID"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        except Exception:
            self.logger.exception(
                "unhandled request error",
                extra={"method": method, "path": _normalize_path(scope.get("path", ""))},
            )
            raise
        finally:
            duration = time.perf_counter() - started
            route = scope.get("route")
            path = getattr(route, "path", None) or _normalize_path(scope.get("path", ""))
            HTTP_REQUESTS.labels(method, path, str(status["code"])).inc()
            HTTP_DURATION.labels(method, path).observe(duration)
            self.logger.info(
                "request",
                extra={
                    "method": method,
                    "path": path,
                    "status": status["code"],
                    "duration_ms": round(duration * 1000, 2),
                },
            )
            request_id_var.reset(token)
