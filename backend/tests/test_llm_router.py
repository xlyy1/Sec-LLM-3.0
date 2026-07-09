"""Tests for the LLM provider router."""
import pytest
from core.llm.router import get_provider, get_ollama, get_deepseek, single_shot_completion


class TestProviderResolution:
    def test_get_local_provider(self):
        ollama = get_ollama()
        assert ollama is not None
        assert ollama.model_name is not None

    def test_get_provider_local(self):
        provider = get_provider("local")
        assert provider is not None

    def test_get_provider_cloud_no_key(self):
        provider = get_provider("cloud")
        assert provider is None

    def test_get_provider_default(self):
        provider = get_provider()
        assert provider is not None

    def test_singleton_same_instance(self):
        o1 = get_ollama()
        o2 = get_ollama()
        assert o1 is o2


class TestSingleShotCompletion:
    def test_missing_cloud_raises(self):
        import asyncio
        async def run():
            with pytest.raises(RuntimeError, match="Cloud engine"):
                await single_shot_completion([], provider="cloud")
        asyncio.run(run())
