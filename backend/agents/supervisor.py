"""Multi-Agent Supervisor — orchestrates ReconAgent + ExploitAgent + ReportAgent."""
import asyncio
from typing import Any, Dict

from agents.collaboration import Blackboard
from agents.specialists.recon import run_recon
from agents.specialists.exploit import run_exploit
from config import settings
from core.llm.router import single_shot_completion


async def run_multi_agent(
    target: str,
    task_type: str = "comprehensive",
    provider: str = "local",
) -> Dict[str, Any]:
    """Run multi-agent security assessment with Recon + Exploit phases.

    Returns: {status, findings, report, blackboard_history}
    """
    blackboard = Blackboard()
    logs: list[str] = []
    all_findings: list[dict] = []

    # Phase 1: Reconnaissance
    logs.append("[SUPERVISOR] Starting Reconnaissance phase...")
    recon_result = await run_recon(target, provider, blackboard)
    logs.append(f"[SUPERVISOR] Recon complete — {len(blackboard.list_keys())} discoveries on blackboard")

    # Phase 2: Exploitation
    if task_type in ("comprehensive", "web_scan"):
        logs.append("[SUPERVISOR] Starting Exploitation phase...")
        exploit_result = await run_exploit(target, provider, blackboard)
        all_findings = blackboard.get("all_findings", [])
        logs.append(f"[SUPERVISOR] Exploit complete — {len(all_findings)} vulnerabilities found")

    # Phase 3: Generate report via LLM
    logs.append("[SUPERVISOR] Generating final report...")
    report = None
    try:
        bb_summary = f"Target: {target}\nDiscoveries: {blackboard.list_keys()}\nFindings: {len(all_findings)}"
        prompt = (
            f"You are a security lead. Synthesize the assessment results into a report.\n\n"
            f"{bb_summary}\n\nFindings detail:\n{str(all_findings)[:8000]}\n\n"
            f"Write in Chinese. Include: Executive Summary, Attack Surface, Key Findings, "
            f"Risk Assessment, Recommendations. Markdown format."
        )
        messages = [{"role": "system", "content": "You are a senior security consultant."},
                     {"role": "user", "content": prompt}]
        report = await single_shot_completion(messages, provider=provider, temperature=0.3)
    except Exception as e:
        logs.append(f"[SUPERVISOR] Report generation failed: {e}")

    logs.append(f"[SUPERVISOR] Assessment complete. {len(all_findings)} findings.")
    return {
        "status": "completed",
        "target": target,
        "phase": "complete",
        "findings": all_findings,
        "report": report,
        "blackboard_keys": blackboard.list_keys(),
        "logs": logs,
    }
