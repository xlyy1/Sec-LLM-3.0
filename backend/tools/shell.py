"""Docker sandbox shell execution tool."""
import shlex
import subprocess
from typing import Optional

from tools.registry import register_tool

# Only allow alphanumeric, dots, dashes, slashes, colons in commands
import re
_SAFE_CMD_RE = re.compile(r'^[a-zA-Z0-9\s\.\-_/:=\?\&\%\@\+\[\]\(\)\{\}\,\;\#\|\>\<\"\'\~\^\`\!\*\$]+$')


@register_tool(
    name="shell_exec",
    description="Execute a shell command in an isolated Docker sandbox. "
    "Use for running security tools like nmap, sqlmap, nuclei, ffuf, etc. "
    "Returns stdout, stderr, and exit code. Max 300s timeout.",
    category="recon",
    requires_provider=False,
)
async def shell_exec(command: str, timeout: int = 300) -> dict:
    """Execute a command in the Docker sandbox container."""
    import asyncio

    # Validate command against allowlist to prevent injection
    if not _SAFE_CMD_RE.match(command):
        return {"stdout": "", "stderr": "Command rejected: contains unsafe characters", "exit_code": -1}

    sandbox_image = "sec-llm-sandbox:latest"

    # Use shlex to safely split command into args
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--memory", "512m",
        "--cpus", "1",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec",
        sandbox_image,
        "sh", "-c", command,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return {
            "stdout": stdout.decode("utf-8", errors="replace")[:50000],
            "stderr": stderr.decode("utf-8", errors="replace")[:10000],
            "exit_code": proc.returncode or 0,
        }
    except asyncio.TimeoutError:
        return {"stdout": "", "stderr": f"Command timed out after {timeout}s", "exit_code": -1}
    except FileNotFoundError:
        return {"stdout": "", "stderr": "Docker is not available on this system", "exit_code": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e)[:1000], "exit_code": -1}
