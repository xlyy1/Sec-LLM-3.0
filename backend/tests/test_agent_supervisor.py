"""Tests for the multi-agent supervisor and specialists."""
import pytest
from agents.collaboration import Blackboard
from agents.supervisor import run_multi_agent
from agents.specialists.recon import run_recon
from agents.specialists.exploit import run_exploit


class TestBlackboard:
    def test_publish_and_get(self):
        bb = Blackboard()
        bb.publish("key1", "value1", "test")
        assert bb.get("key1") == "value1"

    def test_get_all(self):
        bb = Blackboard()
        bb.publish("a", 1)
        bb.publish("b", 2)
        all_data = bb.get_all()
        assert all_data == {"a": 1, "b": 2}

    def test_get_by_source(self):
        bb = Blackboard()
        bb.publish("x", 10, "recon")
        bb.publish("y", 20, "exploit")
        assert bb.get_by_source("recon") == {"x": 10}
        assert bb.get_by_source("exploit") == {"y": 20}

    def test_history(self):
        bb = Blackboard()
        bb.publish("k", "v", "src")
        assert len(bb.get_history()) == 1
        assert bb.get_history()[0]["source"] == "src"

    def test_list_keys(self):
        bb = Blackboard()
        bb.publish("z", 1)
        bb.publish("a", 2)
        assert bb.list_keys() == ["a", "z"]

    def test_clear(self):
        bb = Blackboard()
        bb.publish("k", "v")
        bb.clear()
        assert bb.get_all() == {}
        assert bb.get_history() == []


class TestReconSpecialist:
    def test_run_recon_no_tools(self):
        """Recon should return gracefully when tools are unavailable."""
        import asyncio
        bb = Blackboard()
        result = asyncio.run(run_recon("http://example.com", "local", bb))
        assert result["phase"] == "recon_complete"
        assert isinstance(result["findings"], list)


class TestExploitSpecialist:
    def test_run_exploit_empty_blackboard(self):
        """Exploit should handle empty blackboard gracefully."""
        import asyncio
        bb = Blackboard()
        result = asyncio.run(run_exploit("http://example.com", "local", bb))
        assert result["phase"] == "exploit_complete"
        assert result["findings_count"] == 0


class TestSupervisor:
    def test_run_supervisor_basic(self):
        """Supervisor should complete multi-agent run without crashing."""
        import asyncio
        result = asyncio.run(run_multi_agent(
            target="http://example.com",
            task_type="comprehensive",
            provider="local",
        ))
        assert result["status"] == "completed"
        assert "target" in result
        assert "logs" in result
        assert "blackboard_keys" in result
