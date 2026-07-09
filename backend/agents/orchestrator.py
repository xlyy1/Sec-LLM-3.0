"""Agent orchestrator — LangGraph StateGraph for autonomous security testing."""
import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from agents.state import AgentState, AgentTask
from config import settings
from core.llm.router import single_shot_completion
from tools.registry import get_all_tools, get_tool

# Auto-import tool modules so TOOL_REGISTRY is always populated
import tools.phishing      # noqa: E402
import tools.code_audit    # noqa: E402
import tools.rule_gen      # noqa: E402
import tools.report        # noqa: E402
import tools.threat_intel  # noqa: E402
import tools.browser       # noqa: E402
import tools.shell         # noqa: E402

# In-memory session store (replace with DB in production)
_sessions: Dict[str, Dict[str, Any]] = {}
_sessions_lock = asyncio.Lock()
_SESSION_TTL_SECONDS = 3600  # 1 hour auto-eviction


def _cleanup_expired_sessions():
    """Remove sessions older than TTL."""
    cutoff = time.time() - _SESSION_TTL_SECONDS
    expired = []
    for sid, s in list(_sessions.items()):
        try:
            created = datetime.fromisoformat(s["created_at"]).timestamp()
            if created < cutoff:
                expired.append(sid)
        except (ValueError, KeyError):
            expired.append(sid)
    for sid in expired:
        del _sessions[sid]
    if expired:
        print(f"[Sessions] Cleaned up {len(expired)} expired sessions")


def _persist_session(session_id: str):
    """Write session to MySQL agent_sessions table (best-effort, non-blocking)."""
    conn = None
    try:
        import pymysql
        from config import settings
        conn = pymysql.connect(
            host=settings.MYSQL_HOST, user=settings.MYSQL_USER, password=settings.MYSQL_PASSWORD,
            database=settings.MYSQL_DB, port=settings.MYSQL_PORT, charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor, autocommit=True,
        )
        s = _sessions.get(session_id)
        if not s: return
        state = s.get("state") or {}
        with conn.cursor() as c:
            c.execute(
                """INSERT INTO agent_sessions (id, target, task_type, provider, status, phase,
                   findings_count, steps_completed, steps_total, report, logs, created_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON DUPLICATE KEY UPDATE status=%s, phase=%s, findings_count=%s,
                   steps_completed=%s, steps_total=%s, report=%s, logs=%s""",
                (session_id, s["task"].get("target",""), s["task"].get("task_type","web_scan"),
                 s["task"].get("provider","local"), s["status"], state.get("phase",""),
                 len(s.get("findings",[])), state.get("current_step",0),
                 len(state.get("plan",[])), s.get("report"), json.dumps(s.get("logs",[])),
                 s.get("created_at",""), s["status"], state.get("phase",""),
                 len(s.get("findings",[])), state.get("current_step",0),
                 len(state.get("plan",[])), s.get("report"), json.dumps(s.get("logs",[]))))
    except Exception as e:
        print(f"[DB Persist] Failed to save session {session_id}: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


async def create_session(task: AgentTask) -> str:
    session_id = str(uuid.uuid4())[:8]
    async with _sessions_lock:
        _cleanup_expired_sessions()
        _sessions[session_id] = {
            "id": session_id,
            "task": task,
            "state": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "running",
            "logs": [],
            "findings": [],
        }
    return session_id


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    return _sessions.get(session_id)


def list_sessions(limit: int = 20) -> List[Dict[str, Any]]:
    """Public API for listing recent sessions."""
    items = list(_sessions.values())
    items.sort(key=lambda s: s.get("created_at", ""), reverse=True)
    return items[:limit]


# ---- Graph Nodes ----

async def planner_node(state: AgentState) -> AgentState:
    """Analyze task and target, generate ordered tool execution plan."""
    state["phase"] = "planning"
    tools_desc = ""
    for name, info in sorted(get_all_tools().items()):
        tools_desc += f"- {name}: {info['description']}\n"

    prompt = (
        f"You are a senior penetration testing lead. Generate a step-by-step plan as JSON array.\n\n"
        f"Task: {state['task']}\nTarget: {state['target']}\nTask Type: {state['task_type']}\n\n"
        f"Available tools:\n{tools_desc}\n"
        f"Format: [{{\"tool\": \"name\", \"args\": {{...}}, \"reason\": \"why\"}}]\n"
        f"Max {settings.AGENT_MAX_STEPS} steps. Output ONLY the JSON array, no markdown."
    )

    messages = [
        {"role": "system", "content": "You are a security testing planner. Output ONLY valid JSON arrays."},
        {"role": "user", "content": prompt},
    ]

    try:
        raw = await single_shot_completion(
            messages, provider=state.get("provider", "local"), temperature=0.1, json_mode=False
        )
        start = raw.find("[")
        end = raw.rfind("]") + 1
        if start >= 0 and end > start:
            plan = json.loads(raw[start:end])
            if isinstance(plan, list) and len(plan) > 0:
                for step in plan:
                    step["status"] = "pending"
                state["plan"] = plan[: settings.AGENT_MAX_STEPS]
                state["current_step"] = 0
                state["logs"].append(f"[PLAN] Generated {len(state['plan'])}-step plan")
            else:
                state["error"] = "Plan generation returned empty result"
                state["status"] = "failed"
        else:
            state["error"] = f"Could not parse plan from LLM output"
            state["status"] = "failed"
    except Exception as e:
        state["error"] = f"Planning failed: {e}"
        state["status"] = "failed"

    return state


async def execute_node(state: AgentState) -> AgentState:
    """Execute the current plan step's tool."""
    if state["current_step"] >= len(state["plan"]):
        state["phase"] = "done"
        return state

    step = state["plan"][state["current_step"]]
    tool_name = step["tool"]
    tool_args = dict(step.get("args", {}))

    from tools.registry import get_tool

    tool_info = get_tool(tool_name)
    if tool_info is None:
        state["logs"].append(f"[ERROR] Unknown tool: {tool_name}")
        step["status"] = "skipped"
        state["current_step"] += 1
        return state

    state["logs"].append(f"[EXEC] {tool_name}({json.dumps(tool_args, ensure_ascii=False)})")
    step["status"] = "running"

    try:
        if tool_info.get("requires_provider"):
            tool_args["provider"] = state.get("provider", "local")

        loop = asyncio.get_event_loop()
        start = loop.time()
        result = await asyncio.wait_for(
            tool_info["func"](**tool_args),
            timeout=settings.AGENT_STEP_TIMEOUT_SECONDS,
        )
        elapsed = int((loop.time() - start) * 1000)

        state["observations"].append({
            "tool": tool_name, "args": tool_args,
            "result": result, "duration_ms": elapsed,
        })
        step["status"] = "done"
        state["logs"].append(f"[DONE] {tool_name} completed in {elapsed}ms")

        if isinstance(result, dict):
            if "findings" in result and isinstance(result["findings"], list):
                for f in result["findings"]:
                    state["findings"].append(f)
                    state["logs"].append(f"[FINDING] {f.get('severity', '?')}: {f.get('title', 'Untitled')}")

    except asyncio.TimeoutError:
        step["status"] = "timeout"
        state["logs"].append(f"[TIMEOUT] {tool_name} exceeded {settings.AGENT_STEP_TIMEOUT_SECONDS}s")
    except Exception as e:
        step["status"] = "error"
        state["logs"].append(f"[ERROR] {tool_name} failed: {e}")

    state["current_step"] += 1
    return state


async def reflect_node(state: AgentState) -> AgentState:
    """Evaluate progress and decide next action."""
    state["phase"] = "reflect"
    if state.get("error"):
        state["status"] = "failed"
        return state
    if state["current_step"] >= len(state["plan"]):
        state["logs"].append("[REFLECT] All planned steps executed")
    return state


async def report_node(state: AgentState) -> AgentState:
    """Generate final security assessment report."""
    state["phase"] = "report"

    findings_text = json.dumps(state.get("findings", []), ensure_ascii=False, indent=2)[:8000] if state.get("findings") else "(none)"
    prompt = (
        f"You are a senior security consultant. Write a comprehensive security assessment report in Chinese.\n\n"
        f"Target: {state['target']}\nTask Type: {state['task_type']}\nSteps: {len(state['plan'])}\n"
        f"Findings:\n{findings_text}\n\n"
        f"Include: Executive Summary, Key Findings (sorted by severity), Attack Surface Analysis, "
        f"Risk Ratings, Remediation Recommendations, Testing Limitations. Output in Markdown."
    )

    try:
        report = await single_shot_completion(
            [{"role": "system", "content": "You are a security consultant. Write professional reports."},
             {"role": "user", "content": prompt}],
            provider=state.get("provider", "local"), temperature=0.3
        )
        state["report"] = report
        state["status"] = "completed"
        state["logs"].append(f"[REPORT] Generated report ({len(report)} chars)")
    except Exception as e:
        state["report"] = f"Report generation failed: {e}"
        state["status"] = "completed"
        state["logs"].append(f"[ERROR] Report generation: {e}")

    return state


# ---- Routing ----

def route_after_plan(state: AgentState) -> str:
    return "report" if state.get("error") else "execute"


def route_after_execute(state: AgentState) -> str:
    if state.get("error"):
        return "report"
    if state["current_step"] < len(state["plan"]):
        return "execute"
    return "reflect"


def route_after_reflect(state: AgentState) -> str:
    return "execute" if state["current_step"] < len(state["plan"]) else "report"


# ---- Build Graph (module-level singleton) ----

_agent_graph = None

def get_agent_graph():
    global _agent_graph
    if _agent_graph is None:
        workflow = StateGraph(AgentState)
        workflow.add_node("plan", planner_node)
        workflow.add_node("execute", execute_node)
        workflow.add_node("reflect", reflect_node)
        workflow.add_node("report", report_node)
        workflow.set_entry_point("plan")
        workflow.add_conditional_edges("plan", route_after_plan, {"execute": "execute", "report": "report"})
        workflow.add_conditional_edges("execute", route_after_execute, {"execute": "execute", "reflect": "reflect", "report": "report"})
        workflow.add_conditional_edges("reflect", route_after_reflect, {"execute": "execute", "report": "report"})
        workflow.add_edge("report", END)
        _agent_graph = workflow.compile(checkpointer=MemorySaver())
    return _agent_graph


# ---- Run Agent ----

async def run_agent(task: AgentTask) -> str:
    """Run an agent task. Returns session_id for status polling."""
    target = task.get("target", "")
    if not target:
        raise ValueError("Task must include a 'target' field")

    session_id = await create_session(task)
    graph = get_agent_graph()

    initial_state: AgentState = {
        "task": task.get("task", f"Security assessment of {target}"),
        "target": target,
        "task_type": task.get("task_type", "web_scan"),
        "provider": task.get("provider", settings.LLM_PROVIDER),
        "messages": [],
        "plan": [],
        "current_step": 0,
        "observations": [],
        "findings": [],
        "phase": "planning",
        "status": "running",
        "error": None,
        "report": None,
        "logs": [f"[START] Agent task: {target} (type={task.get('task_type', 'web_scan')})"],
    }

    try:
        final_state = await graph.ainvoke(
            initial_state,
            {"configurable": {"thread_id": session_id}},
        )
        async with _sessions_lock:
            _sessions[session_id]["state"] = final_state
            _sessions[session_id]["status"] = final_state.get("status", "completed")
            _sessions[session_id]["findings"] = final_state.get("findings", [])
            _sessions[session_id]["logs"] = final_state.get("logs", [])
            _sessions[session_id]["report"] = final_state.get("report")
    except Exception as e:
        async with _sessions_lock:
            _sessions[session_id]["status"] = "failed"
            _sessions[session_id]["logs"].append(f"[FATAL] {e}")

    # Persist to DB asynchronously (best-effort, non-blocking)
    asyncio.create_task(asyncio.to_thread(_persist_session, session_id))
    return session_id
