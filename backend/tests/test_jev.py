"""Offline checks for the optional Jev tool guard."""
import asyncio

import pytest

from core.jev import _redact, evaluate_tool_action
from tools.registry import register_tool, invoke_tool


def test_redacts_secrets_and_limits_external_state():
    result = _redact({"api_key": "secret", "nested": {"password": "pw"}, "command": "x" * 5000})
    assert result["api_key"] == "[REDACTED]"
    assert result["nested"]["password"] == "[REDACTED]"
    assert len(result["command"]) == 4000


def test_guard_blocks_tool_before_execution(monkeypatch):
    executed = False

    @register_tool("_jev_guard_test", "test", requires_provider=False)
    async def guarded_tool():
        nonlocal executed
        executed = True

    async def deny(*_args, **_kwargs):
        return {"action": "deny", "confidence": 0.99}

    monkeypatch.setattr("core.jev.evaluate_tool_action", deny)
    with pytest.raises(PermissionError, match="Jev blocked"):
        asyncio.run(invoke_tool("_jev_guard_test"))
    assert not executed


def test_guard_fails_closed_without_api_key(monkeypatch):
    monkeypatch.setattr("core.jev.settings.TYPESAFE_API_KEY", None)
    decision = asyncio.run(evaluate_tool_action("shell_exec", {"command": "nmap example.com"}))
    assert decision["action"] == "require_approval"
