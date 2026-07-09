"""Abstract base for LLM providers."""
from abc import ABC, abstractmethod
from typing import AsyncGenerator, Dict, List


class LLMProvider(ABC):
    """Abstract interface for LLM providers (Ollama, DeepSeek, OpenAI, etc.)."""

    def __init__(self, model_name: str):
        self.model_name = model_name

    @abstractmethod
    async def complete(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        json_mode: bool = False,
    ) -> str:
        """Non-streaming completion. Returns the full response text."""
        ...

    @abstractmethod
    async def stream(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
    ) -> AsyncGenerator[str, None]:
        """Streaming completion. Yields content chunks as they arrive."""
        ...
