"""Multi-Agent Supervisor — orchestrates ReconAgent + ExploitAgent + ReportAgent."""
from typing import Any, Awaitable, Callable, Dict, TypedDict

from langgraph.graph import END, StateGraph

from agents.collaboration import Blackboard
from agents.specialists.recon import run_recon
from agents.specialists.exploit import run_exploit
from core.llm.router import single_shot_completion


class SupervisorState(TypedDict):
    target: str
    task_type: str
    provider: str
    blackboard: Blackboard
    recon_state: Dict[str, Any]
    exploit_state: Dict[str, Any]
    report_state: Dict[str, Any]
    logs: list[str]


async def _recon_node(state: SupervisorState) -> dict:
    result = await run_recon(state["target"], state["provider"], state["blackboard"])
    result = {**result, "discoveries": state["blackboard"].get_by_source("recon")}
    errors = [f"[RECON] {item['tool']} failed: {item['error']}" for item in result.get("findings", []) if item.get("type") == "error"]
    return {
        "recon_state": result,
        "logs": state["logs"] + ["[SUPERVISOR] Starting Reconnaissance phase...",
                                 f"[SUPERVISOR] Recon complete — {len(state['blackboard'].list_keys())} discoveries on blackboard"] + errors,
    }


async def _exploit_node(state: SupervisorState) -> dict:
    result = await run_exploit(state["target"], state["provider"], state["blackboard"],
                               discoveries=state["recon_state"]["discoveries"])
    count = len(state["blackboard"].get("all_findings", []))
    errors = [f"[EXPLOIT] {item['tool']} failed: {item['error']}" for item in result.get("errors", [])]
    return {
        "exploit_state": result,
        "logs": state["logs"] + ["[SUPERVISOR] Starting Exploitation phase...",
                                 f"[SUPERVISOR] Detection complete — {count} findings awaiting classification"] + errors,
    }


async def _report_node(state: SupervisorState) -> dict:
    blackboard = state["blackboard"]
    all_findings = blackboard.get("all_findings", [])
    verified = [f for f in all_findings if f.get("verification_status") == "verified"]
    unverified = [f for f in all_findings if f.get("verification_status") != "verified"]
    logs = state["logs"] + ["[SUPERVISOR] Generating final report..."]
    report = None
    try:
        bb_summary = f"Target: {state['target']}\nDiscoveries: {blackboard.list_keys()}\nVerified: {len(verified)}\nUnverified: {len(unverified)}"
        prompt = (
            f"You are a security lead. Synthesize the assessment results into a report.\n\n"
            f"{bb_summary}\n\nScan limitations:\n{str([item for item in state['recon_state'].get('findings', []) if item.get('type') == 'error'])[:2000]}\n\nVerified vulnerabilities:\n{str(verified)[:4000]}\n\n"
            f"Unverified leads:\n{str(unverified)[:4000]}\n\n"
            f"Write in Chinese. Only call verified items vulnerabilities. Label all other items "
            f"as unverified leads; do not invent validation evidence. Include: Executive Summary, "
            f"Attack Surface, Verified Findings, Unverified Leads, Recommendations. Markdown format."
        )
        messages = [{"role": "system", "content": "You are a senior security consultant."},
                     {"role": "user", "content": prompt}]
        report = await single_shot_completion(messages, provider=state["provider"], temperature=0.3)
    except Exception as e:
        logs.append(f"[SUPERVISOR] Report generation failed: {e}")

    logs.append(f"[SUPERVISOR] Assessment complete. {len(verified)} verified, {len(unverified)} unverified.")
    return {"report_state": {"report": report, "findings": all_findings}, "logs": logs}


def _build_graph():
    workflow = StateGraph(SupervisorState)
    workflow.add_node("recon", _recon_node)
    workflow.add_node("exploit", _exploit_node)
    workflow.add_node("report", _report_node)
    workflow.set_entry_point("recon")
    workflow.add_conditional_edges("recon", lambda state: "exploit" if state["task_type"] in ("comprehensive", "web_scan") else "report")
    workflow.add_edge("exploit", "report")
    workflow.add_edge("report", END)
    return workflow.compile()


_graph = _build_graph()


async def run_multi_agent(
    target: str,
    task_type: str = "comprehensive",
    provider: str = "local",
    on_progress: Callable[[Dict[str, Any]], Awaitable[None]] | None = None,
) -> Dict[str, Any]:
    """Run independent specialist nodes through LangGraph; keep the public result shape."""
    initial = {
        "target": target, "task_type": task_type, "provider": provider,
        "blackboard": Blackboard(), "recon_state": {}, "exploit_state": {},
        "report_state": {}, "logs": [],
    }
    if on_progress:
        async for state in _graph.astream(initial, stream_mode="values"):
            completed = sum(bool(state[key]) for key in ("recon_state", "exploit_state", "report_state"))
            await on_progress({
                "phase": ("complete" if state["report_state"] else
                          "exploit" if state["exploit_state"] else
                          "recon" if state["recon_state"] else "pending"),
                "status": "completed" if state["report_state"] else "running",
                "steps_completed": completed, "steps_total": 3 if task_type in ("web_scan", "comprehensive") else 2,
                "findings": state["blackboard"].get("all_findings", []),
                "report": state["report_state"].get("report"), "logs": state["logs"],
            })
    else:
        state = await _graph.ainvoke(initial)
    return {
        "status": "completed",
        "target": target,
        "phase": "complete",
        "findings": state["report_state"]["findings"],
        "report": state["report_state"]["report"],
        "blackboard_keys": state["blackboard"].list_keys(),
        "logs": state["logs"],
    }
