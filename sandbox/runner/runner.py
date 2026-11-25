"""Narrow sandbox executor.

The API never talks to the Docker daemon. This service is the only component
with the socket; it accepts an allowlisted tool name and argv, then runs the
pre-built sandbox image with a fixed hardening profile. There are no host
mounts, no privileged mode and no arbitrary Docker API methods.
"""
from __future__ import annotations

import os
import secrets
import threading
import uuid
from typing import List, Optional

import docker
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="sec-llm sandbox runner", version="1.0")

_ALLOWED_TOOLS = {"nmap", "sqlmap", "nuclei", "ffuf", "nikto", "whatweb", "semgrep", "bandit"}
_NETWORK_TOOLS = {"nmap", "sqlmap", "nuclei", "ffuf", "nikto", "whatweb"}
_FORBIDDEN_PREFIXES = (
    "--privileged",
    "--cap-add",
    "--security-opt",
    "--device",
    "--mount",
    "--volume",
    "-v",
    "--pid",
    "--ipc",
    "--network",
    "--userns",
    "--uts",
    "--cgroup",
)
_STDOUT_LIMIT = 1_000_000
_SLOTS = threading.Semaphore(int(os.getenv("SANDBOX_RUNNER_CONCURRENCY", "4")))
_TOKEN = os.getenv("SANDBOX_RUNNER_TOKEN", "")
_IMAGE = os.getenv("SANDBOX_IMAGE", "sec-llm-sandbox:latest")


class RunRequest(BaseModel):
    tool: str = Field(..., max_length=32)
    args: List[str] = Field(default_factory=list, max_length=128)
    timeout: int = Field(default=300, ge=1, le=600)


def _check_token(token: Optional[str]) -> None:
    if not _TOKEN:
        raise HTTPException(status_code=503, detail="runner token is not configured")
    if not secrets.compare_digest(token or "", _TOKEN):
        raise HTTPException(status_code=401, detail="invalid runner token")


def _validate(req: RunRequest) -> None:
    if req.tool not in _ALLOWED_TOOLS:
        raise HTTPException(status_code=400, detail="tool is not allowlisted")
    for arg in req.args:
        if not isinstance(arg, str) or "\x00" in arg or "\n" in arg or "\r" in arg:
            raise HTTPException(status_code=400, detail="invalid argument")
        if any(arg == prefix or arg.startswith(prefix + "=") for prefix in _FORBIDDEN_PREFIXES):
            raise HTTPException(status_code=400, detail=f"argument not allowed: {arg}")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/run")
def run(req: RunRequest, x_runner_token: Optional[str] = Header(default=None)):
    _check_token(x_runner_token)
    _validate(req)

    if not _SLOTS.acquire(timeout=5):
        raise HTTPException(status_code=429, detail="sandbox runner is busy")
    container = None
    try:
        client = docker.from_env()
        name = f"sec-llm-run-{uuid.uuid4().hex[:12]}"
        container = client.containers.create(
            _IMAGE,
            command=[req.tool, *req.args],
            name=name,
            network_mode="bridge" if req.tool in _NETWORK_TOOLS else "none",
            mem_limit="512m",
            nano_cpus=1_000_000_000,
            pids_limit=64,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            read_only=True,
            tmpfs={"/tmp": "rw,noexec,nosuid,nodev"},
            user="sandbox",
            environment={"HOME": "/tmp"},
            tty=True,
            detach=True,
        )
        container.start()
        try:
            status = container.wait(timeout=req.timeout)
            exit_code = int(status.get("StatusCode", -1))
        except Exception:
            try:
                container.kill()
            except Exception:
                pass
            exit_code = -1
        output = container.logs(stdout=True, stderr=False) or b""
        text = output[:_STDOUT_LIMIT].decode("utf-8", errors="replace")
        return {"stdout": text, "stderr": "", "exit_code": exit_code}
    except docker.errors.DockerException as error:
        raise HTTPException(status_code=503, detail=f"sandbox unavailable: {error}") from error
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                pass
        _SLOTS.release()
