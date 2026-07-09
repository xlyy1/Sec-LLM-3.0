"""Reconnaissance specialist agent — attack surface mapping."""
import json
from typing import Any, Dict, List

from agents.collaboration import Blackboard
from core.llm.router import single_shot_completion
from tools.registry import get_tools_by_category, invoke_tool

RECON_PROMPT = """You are a reconnaissance specialist on a red team.
Your job: map the attack surface of the target and report discoveries.

Available recon tools:
{tool_list}

Target: {target}

Instructions:
1. Start with broad recon (browser navigate, port scan via shell_exec)
2. Enumerate technologies, open ports, forms, links, JavaScript files
3. Publish ALL discoveries to the blackboard using the exact key format:
   - open_ports: list of {{port, service, version}}
   - technologies: list of detected tech
   - endpoints: list of URLs found
   - forms: list of forms with inputs
4. Output a JSON summary: {{"phase": "recon_complete", "discoveries": [...], "next_targets": [...]}}
"""


async def run_recon(target: str, provider: str, blackboard: Blackboard) -> Dict[str, Any]:
    """Run reconnaissance phase — discover and map attack surface."""
    recon_tools = get_tools_by_category("recon")
    tool_list = "\n".join(f"- {name}: {info['description']}" for name, info in recon_tools.items())

    findings = []

    # Step 1: Browser recon
    try:
        result = await invoke_tool("browser_navigate", url=target)
        if isinstance(result, dict) and result.get("status") == "success":
            if result.get("links"):
                blackboard.publish("endpoints", result["links"][:50], "recon")
            if result.get("forms"):
                blackboard.publish("forms", result["forms"], "recon")
            if result.get("title"):
                findings.append({"type": "page_info", "title": result["title"]})
            blackboard.publish("page_title", result.get("title", ""), "recon")
    except Exception as e:
        findings.append({"type": "error", "tool": "browser_navigate", "error": str(e)})

    # Step 2: Port scan via shell (extract hostname if target is a URL)
    try:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        scan_target = parsed.hostname or target  # use hostname if URL, else raw target
        result = await invoke_tool("shell_exec", command=f"nmap -sV -F {scan_target}", timeout=120)
        if isinstance(result, dict) and result.get("exit_code") == 0:
            blackboard.publish("nmap_output", result.get("stdout", ""), "recon")
            findings.append({"type": "port_scan", "output": result.get("stdout", "")[:2000]})
    except Exception:
        pass  # Docker sandbox may not be available

    # Step 3: LLM synthesis
    try:
        prompt = RECON_PROMPT.format(tool_list=tool_list, target=target)
        messages = [{"role": "system", "content": prompt},
                     {"role": "user", "content": f"Target: {target}\nFindings so far: {json.dumps(findings, ensure_ascii=False)[:4000]}"}]
        plan = await single_shot_completion(messages, provider=provider, temperature=0.2)
        blackboard.publish("recon_plan", plan, "recon")
    except Exception as e:
        blackboard.publish("recon_error", str(e), "recon")

    return {"phase": "recon_complete", "findings": findings, "blackboard_keys": blackboard.list_keys()}
