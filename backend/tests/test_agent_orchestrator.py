"""Tests for the agent orchestrator and session management."""
import asyncio
import pytest
from agents.state import AgentState
from agents.orchestrator import (
    create_session,
    get_session,
    list_sessions,
    get_agent_graph,
)


class TestAgentGraph:
    def test_graph_nodes(self):
        graph = get_agent_graph()
        nodes = list(graph.nodes.keys())
        assert "__start__" in nodes
        assert "plan" in nodes
        assert "execute" in nodes
        assert "reflect" in nodes
        assert "report" in nodes

    def test_graph_is_singleton(self):
        g1 = get_agent_graph()
        g2 = get_agent_graph()
        assert g1 is g2


class TestSessionManagement:
    def setup_method(self):
        import agents.orchestrator as orch
        orch._sessions.clear()

    def teardown_method(self):
        import agents.orchestrator as orch
        orch._sessions.clear()

    def test_create_and_get(self):
        async def run():
            sid = await create_session({"target": "test.com", "task_type": "web_scan"})
            s = get_session(sid)
            assert s is not None
            assert s["status"] == "running"
            assert s["task"]["target"] == "test.com"
        asyncio.run(run())

    def test_get_nonexistent(self):
        assert get_session("nonexistent") is None

    def test_list_sessions(self):
        async def run():
            await create_session({"target": "a.com"})
            await create_session({"target": "b.com"})
            sessions = list_sessions()
            assert len(sessions) >= 2
        asyncio.run(run())
