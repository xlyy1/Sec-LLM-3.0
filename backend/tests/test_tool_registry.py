"""Tests for the tool registry system."""
import pytest
from tools.registry import (
    TOOL_REGISTRY,
    register_tool,
    get_tool,
    get_all_tools,
    get_tools_by_category,
    list_tool_names,
    _extract_json,
)


class TestToolRegistry:
    def setup_method(self):
        self.original = dict(TOOL_REGISTRY)
        TOOL_REGISTRY.clear()

    def teardown_method(self):
        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(self.original)

    def test_register_and_get(self):
        @register_tool("test_tool", "A test tool", category="recon")
        async def my_tool(x: int) -> int:
            return x * 2

        assert "test_tool" in list_tool_names()
        info = get_tool("test_tool")
        assert info["name"] == "test_tool"
        assert info["category"] == "recon"
        assert info["requires_provider"] is True

    def test_get_unknown_tool(self):
        assert get_tool("nonexistent") is None

    def test_get_by_category(self):
        @register_tool("r1", "Recon 1", category="recon")
        async def r1(): pass

        @register_tool("e1", "Exploit 1", category="exploit")
        async def e1(): pass

        recon_tools = get_tools_by_category("recon")
        assert len(recon_tools) == 1
        assert "r1" in recon_tools

    def test_list_names_sorted(self):
        @register_tool("z_tool", "Z", category="general")
        async def z(): pass

        @register_tool("a_tool", "A", category="general")
        async def a(): pass

        names = list_tool_names()
        assert names[0] == "a_tool"
        assert names[-1] == "z_tool"


class TestExtractJson:
    def test_direct_parse(self):
        assert _extract_json('{"a": 1}') == {"a": 1}

    def test_markdown_code_block(self):
        result = _extract_json('```json\n{"b": 2}\n```')
        assert result == {"b": 2}

    def test_raw_decode_fallback(self):
        result = _extract_json('prefix text {"c": 3} suffix {"d": 4}')
        assert result == {"c": 3}

    def test_no_json_returns_none(self):
        assert _extract_json("no json here") is None

    def test_nested_json(self):
        result = _extract_json('{"outer": {"inner": [1,2,3]}}')
        assert result == {"outer": {"inner": [1, 2, 3]}}
