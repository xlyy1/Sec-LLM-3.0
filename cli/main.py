"""Sec-LLM Agent CLI — command-line interface for the AI agent platform."""
import os
import sys

import typer

BASE_URL = os.environ.get("SEC_LLM_BASE_URL", "http://localhost:8000")

app = typer.Typer(
    name="sec-llm",
    help="Sec-LLM AI Agent — autonomous cybersecurity testing platform",
)

_base_url_option = typer.Option(BASE_URL, "--base-url", "-u", help="Sec-LLM API base URL")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL or IP to scan"),
    mode: str = typer.Option("quick", help="Scan mode: quick, standard, deep"),
    provider: str = typer.Option("local", help="LLM provider: local or cloud"),
    base_url: str = _base_url_option,
):
    """Run an automated security scan against a target."""
    import httpx

    typer.echo(f"Starting {mode} scan against {target} (provider={provider})...")
    try:
        resp = httpx.post(
            "http://localhost:8000/api/agent/run",
            json={"target": target, "task_type": "web_scan", "provider": provider},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        session_id = data["session_id"]
        typer.echo(f"Task started. Session ID: {session_id}")
        typer.echo(f"Monitor: sec-llm stream {session_id}")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


@app.command()
def audit(
    path: str = typer.Argument(..., help="File or directory path to audit"),
    language: str = typer.Option("python", help="Programming language"),
    provider: str = typer.Option("local", help="LLM provider"),
    base_url: str = _base_url_option,
):
    """Audit source code for security vulnerabilities."""
    import httpx

    typer.echo(f"Auditing {path} ({language})...")
    try:
        resp = httpx.post(
            "http://localhost:8000/api/agent/run",
            json={"target": path, "task_type": "code_audit", "provider": provider},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        typer.echo(f"Task started. Session ID: {data['session_id']}")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


@app.command()
def stream(
    session_id: str = typer.Argument(..., help="Agent session ID to monitor"),
    base_url: str = _base_url_option,
):
    """Stream agent execution logs in real-time."""
    import httpx

    typer.echo(f"Streaming agent session {session_id}...\n")
    try:
        with httpx.stream(
            "GET", f"http://localhost:8000/api/agent/{session_id}/stream", timeout=None
        ) as resp:
            for line in resp.iter_lines():
                if line.startswith("data: "):
                    import json

                    try:
                        event = json.loads(line[6:])
                        if event["type"] == "log":
                            typer.echo(event["message"])
                        elif event["type"] == "done":
                            typer.echo(f"\n{'='*60}")
                            typer.echo(f"Task {event['status']}. Findings: {event.get('findings_count', 0)}")
                            break
                    except json.JSONDecodeError:
                        pass
    except KeyboardInterrupt:
        typer.echo("\nStream interrupted.")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


@app.command()
def status(session_id: str = typer.Argument(..., help="Agent session ID"), base_url: str = _base_url_option):
    """Check agent task status."""
    import httpx

    try:
        resp = httpx.get(f"http://localhost:8000/api/agent/{session_id}/status", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        typer.echo(f"Session: {data['session_id']}")
        typer.echo(f"Status: {data['status']}")
        typer.echo(f"Phase: {data['phase']}")
        typer.echo(f"Progress: {data['steps_completed']}/{data['steps_total']} steps")
        typer.echo(f"Findings: {data['findings_count']}")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


@app.command()
def report(session_id: str = typer.Argument(..., help="Agent session ID"), base_url: str = _base_url_option,
):
    """Print the final agent report."""
    import httpx

    try:
        resp = httpx.get(f"http://localhost:8000/api/agent/{session_id}/report", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if data.get("report"):
            typer.echo(data["report"])
        else:
            typer.echo("No report available yet.")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


@app.command()
def intel(
    ioc: str = typer.Argument(..., help="IOC to lookup: IP, domain, MD5, or SHA256"),
    base_url: str = _base_url_option,
):
    """Lookup threat intelligence for an IOC."""
    import httpx

    typer.echo(f"Looking up threat intelligence for: {ioc}")
    try:
        resp = httpx.post(
            "http://localhost:8000/api/security-tools/threat-intel/enrich",
            json={"ioc": ioc, "ioc_type": "auto"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        typer.echo(f"Type: {data.get('detected_type', '?')}")
        typer.echo(f"Verdict: {data.get('verdict', '?')}")
        typer.echo(f"Score: {data.get('total_score', 0)}/100")
        typer.echo(f"Sources: {data.get('source_hits', 0)}")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
