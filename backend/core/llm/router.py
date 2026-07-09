"""Unified LLM provider router — dispatches to Ollama or DeepSeek."""
import threading
from typing import AsyncGenerator, Dict, List, Optional

from config import normalize_provider, settings
from core.llm.base import LLMProvider
from core.llm.deepseek import DeepSeekProvider
from core.llm.ollama import OllamaProvider

# Eager-init + thread-safe lazy singleton via lock
_lock = threading.Lock()
_ollama_provider: Optional[OllamaProvider] = None
_deepseek_provider: Optional[DeepSeekProvider] = None


def get_ollama() -> OllamaProvider:
    global _ollama_provider
    if _ollama_provider is None:
        with _lock:
            if _ollama_provider is None:
                _ollama_provider = OllamaProvider()
    return _ollama_provider


def get_deepseek() -> Optional[DeepSeekProvider]:
    global _deepseek_provider
    if settings.DEEPSEEK_API_KEY:
        if _deepseek_provider is None:
            with _lock:
                if _deepseek_provider is None:
                    _deepseek_provider = DeepSeekProvider(settings.DEEPSEEK_API_KEY)
        return _deepseek_provider
    return None


def get_provider(name: Optional[str] = None) -> Optional[LLMProvider]:
    """Resolve provider by name. Returns None if cloud is requested but not configured."""
    provider_name = normalize_provider(name or settings.LLM_PROVIDER)
    if provider_name == "cloud":
        return get_deepseek()
    return get_ollama()


async def single_shot_completion(
    messages: List[Dict[str, str]],
    provider: str = "local",
    temperature: float = 0.2,
    json_mode: bool = False,
) -> str:
    """Unified non-streaming completion. Raises RuntimeError if cloud not available."""
    llm = get_provider(provider)
    if llm is None:
        raise RuntimeError("Cloud engine is not configured (missing DEEPSEEK_API_KEY)")
    return await llm.complete(messages, temperature=temperature, json_mode=json_mode)


async def stream_completion(
    messages: List[Dict[str, str]],
    provider: str = "local",
    temperature: float = 0.2,
) -> AsyncGenerator[str, None]:
    """Unified streaming completion. Raises RuntimeError if cloud not available."""
    llm = get_provider(provider)
    if llm is None:
        raise RuntimeError("Cloud engine is not configured (missing DEEPSEEK_API_KEY)")

    async for chunk in llm.stream(messages, temperature=temperature):
        yield chunk
