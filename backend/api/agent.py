"""Agent task API endpoints."""
import asyncio
import json
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from agents.orchestrator import create_session, get_session, list_sessions, run_agent
from core.auth.dependencies import get_current_user_or_skill, get_db

router = APIRouter(prefix="/api/agent", tags=["agent"])


# ---- Request/Response Models ----

class AgentTaskRequest(BaseModel):
    target: str = Field(..., description="Target URL, IP, file path, or repository")
    task_type: str = Field(
        default="web_scan",
        description="web_scan | code_audit | threat_intel | comprehensive",
    )
    provider: str = Field(default="local", description="LLM provider: local or cloud")


class AgentTaskResponse(BaseModel):
    session_id: str
    status: str
    message: str


class AgentStatusResponse(BaseModel):
    session_id: str
    status: str
    phase: str
    findings_count: int
    steps_completed: int
    steps_total: int
    logs: list
    report: str | None = None


# ---- Routes ----

@router.post("/run", response_model=AgentTaskResponse)
async def run_agent_task(
    req: AgentTaskRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_or_skill),
    db=Depends(get_db),
):
    """Submit a new agent task for execution."""
    task_dict: Dict[str, Any] = {
        "target": req.target,
        "task_type": req.task_type,
        "provider": req.provider,
    }
    try:
        session_id = await run_agent(task_dict)
        return AgentTaskResponse(
            session_id=session_id,
            status="running",
            message=f"Agent task started. Track with /api/agent/{session_id}/status",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions")
async def list_sessions(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_or_skill),
    db=Depends(get_db),
):
    """List recent agent sessions."""
    sessions = list_sessions(limit=20)
    return {
        "sessions": [
            {
                "id": s["id"],
                "status": s["status"],
                "task_type": s["task"].get("task_type", "?"),
                "target": s["task"].get("target", "?")[:80],
                "created_at": s["created_at"],
                "findings_count": len(s.get("findings", [])),
            }
            for s in sessions
        ]
    }


@router.get("/{session_id}/status")
async def get_agent_status(
    session_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_or_skill),
    db=Depends(get_db),
):
    """Get current agent session status."""
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    state = session.get("state") or {}
    return AgentStatusResponse(
        session_id=session_id,
        status=session["status"],
        phase=state.get("phase", "unknown"),
        findings_count=len(session.get("findings", [])),
        steps_completed=state.get("current_step", 0),
        steps_total=len(state.get("plan", [])),
        logs=session.get("logs", []),
        report=session.get("report"),
    )


@router.get("/{session_id}/stream")
async def stream_agent_logs(
    session_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_or_skill),
    db=Depends(get_db),
):
    """SSE stream of agent execution progress."""
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    async def generate():
        sent_count = 0
        while True:
            s = get_session(session_id)
            if s is None:
                break
            logs = s.get("logs", [])
            while sent_count < len(logs):
                yield f"data: {json.dumps({'type': 'log', 'message': logs[sent_count]}, ensure_ascii=False)}\n\n"
                sent_count += 1
                await asyncio.sleep(0.05)

            if s["status"] in ("completed", "failed"):
                yield f"data: {json.dumps({'type': 'done', 'status': s['status'], 'findings_count': len(s.get('findings', []))}, ensure_ascii=False)}\n\n"
                break

            await asyncio.sleep(0.5)

    return StreamingResponse(generate(), media_type="text/event-stream")


@router.get("/{session_id}/report")
async def get_agent_report(
    session_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_or_skill),
    db=Depends(get_db),
):
    """Get the final report for a completed agent session."""
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session["status"] not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Task still running")

    return {
        "session_id": session_id,
        "status": session["status"],
        "findings": session.get("findings", []),
        "report": session.get("report"),
    }
