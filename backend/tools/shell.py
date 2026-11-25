"""Docker sandbox security-tool execution."""
import ipaddress
import re
import shlex
import uuid
from typing import Iterable, List
from urllib.parse import urlsplit

from config import settings
from tools.registry import register_tool

_ALLOWED_TOOLS = {"nmap", "sqlmap", "nuclei", "ffuf", "nikto", "whatweb", "semgrep", "bandit"}
_STDOUT_LIMIT = 1_000_000
_STDERR_LIMIT = 256_000
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
_BLOCKED_HOSTS = {"host.docker.internal", "localhost", "metadata.google.internal"}


def _candidate_hosts(args: Iterable[str]) -> List[str]:
    hosts: List[str] = []
    for arg in args:
        if not arg or arg.startswith("-") or "=" in arg:
            continue
        if arg.isdigit():
            # Port numbers / thread counts are not targets.
            continue
        if "://" in arg:
            value = urlsplit(arg).hostname or ""
            if value:
                hosts.append(value)
            continue
        if "/" in arg:
            continue
        value = arg
        if ":" in arg and arg.count(":") == 1:
            value = arg.split(":", 1)[0]
        if not value:
            continue
        if _is_ip(value) or _HOSTNAME_RE.match(value) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", value):
            hosts.append(value)
    return hosts


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_blocked_host(host: str, allow_private: bool) -> bool:
    lowered = host.strip().lower().rstrip(".")
    if lowered in _BLOCKED_HOSTS or lowered.endswith((".localhost", ".local", ".internal")):
        return True
    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        # Hostnames are not resolved here: a synchronous DNS lookup would block
        # the request path. DNS-rebinding to a private address is covered by the
        # deployment-level egress policy documented in README.
        return False
    if ip.is_loopback and not allow_private:
        return True
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    return ip.is_private and not allow_private


def _target_error(args: Iterable[str]) -> str:
    allow_private = bool(getattr(settings, "AGENT_ALLOW_PRIVATE_TARGETS", False))
    for host in _candidate_hosts(args):
        if _is_blocked_host(host, allow_private):
            return f"Target rejected: {host} is loopback/private/internal"
    return ""


async def _capture(proc):
    import asyncio

    async def read(stream, limit):
        content = bytearray()
        while chunk := await stream.read(16384):
            if len(content) + len(chunk) > limit:
                raise ValueError("Tool output exceeded its size budget")
            content.extend(chunk)
        return bytes(content)

    tasks = [asyncio.create_task(read(proc.stdout, _STDOUT_LIMIT)),
             asyncio.create_task(read(proc.stderr, _STDERR_LIMIT)), asyncio.create_task(proc.wait())]
    try:
        stdout, stderr, _ = await asyncio.gather(*tasks)
        return stdout, stderr
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@register_tool(
    name="shell_exec",
        description="Run an approved command-line security tool (nmap, sqlmap, nuclei, ffuf, "
        "nikto, whatweb, semgrep, bandit) inside an isolated Docker sandbox and return stdout, "
        "stderr and exit code. Use this whenever the task names a CLI tool or asks to run a "
        "scan/detection program. It does NOT fetch, crawl or render web pages: use the browser_* "
        "tools for page access, and the *_probe tools for single-parameter vulnerability tests.",
    requires_provider=False,
)
async def shell_exec(command: str, timeout: int = 300) -> dict:
    """Execute an approved tool without invoking a shell."""
    import asyncio

    if any(char in command for char in ";&|><`$\n\r"):
        return {"stdout": "", "stderr": "Command rejected: shell syntax is not allowed", "exit_code": -1}
    try:
        args = shlex.split(command)
    except ValueError:
        args = []
    if not args or args[0] not in _ALLOWED_TOOLS:
        return {"stdout": "", "stderr": "Command rejected: unsupported tool", "exit_code": -1}

    target_error = _target_error(args[1:])
    if target_error:
        return {"stdout": "", "stderr": target_error, "exit_code": -1}

    sandbox_image = settings.AGENT_SANDBOX_IMAGE
    container_name = f"sec-llm-{uuid.uuid4().hex}"
    effective_timeout = min(max(timeout, 1), 300)

    tool_name = args[0]
    needs_network = tool_name in {"nmap", "sqlmap", "nuclei", "ffuf", "nikto", "whatweb"}

    # Preferred path: the API has no Docker socket; a narrow runner owns it.
    runner_url = (getattr(settings, "SANDBOX_RUNNER_URL", "") or "").rstrip("/")
    if runner_url:
        import httpx

        try:
            async with httpx.AsyncClient(timeout=effective_timeout + 15) as client:
                response = await client.post(
                    f"{runner_url}/run",
                    json={"tool": tool_name, "args": args[1:], "timeout": effective_timeout},
                    headers={"X-Runner-Token": settings.SANDBOX_RUNNER_TOKEN},
                )
        except Exception as error:  # noqa: BLE001
            return {"stdout": "", "stderr": f"Sandbox runner unavailable: {error}"[:1000], "exit_code": -1}
        if response.status_code != 200:
            return {
                "stdout": "",
                "stderr": f"Sandbox runner rejected the command ({response.status_code}): {response.text[:500]}",
                "exit_code": -1,
            }
        data = response.json()
        return {
            "stdout": str(data.get("stdout", ""))[:50000],
            "stderr": str(data.get("stderr", ""))[:10000],
            "exit_code": int(data.get("exit_code", -1)),
        }

    cmd = [
        "docker", "run", "--rm",
        "--name", container_name,
        "--network", "bridge" if needs_network else "none",
        "--memory", "512m",
        "--cpus", "1",
        "--pids-limit", "64",
        # 与 RSI 沙箱对齐：去掉所有 capability、禁止提权、不作 root 运行
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev",  # nosec B108: private per-container tmpfs, not a host temporary file
        "--log-driver", "none",
        "--env", "HOME=/tmp",
        sandbox_image,
        *args,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            _capture(proc), timeout=effective_timeout
        )
        return {
            "stdout": stdout.decode("utf-8", errors="replace")[:50000],
            "stderr": stderr.decode("utf-8", errors="replace")[:10000],
            "exit_code": proc.returncode or 0,
        }
    except (asyncio.TimeoutError, asyncio.CancelledError, ValueError) as error:
        cleanup_error = ""
        try:
            cleanup = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            if await asyncio.wait_for(cleanup.wait(), 10):
                cleanup_error = "; container removal could not be confirmed"
        except (OSError, asyncio.TimeoutError):
            cleanup_error = "; container removal could not be confirmed"
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
        if isinstance(error, asyncio.CancelledError):
            raise
        reason = str(error) if isinstance(error, ValueError) else f"Command timed out after {effective_timeout}s"
        return {"stdout": "", "stderr": reason + cleanup_error, "exit_code": -1}
    except FileNotFoundError:
        return {"stdout": "", "stderr": "Docker is not available on this system", "exit_code": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e)[:1000], "exit_code": -1}
