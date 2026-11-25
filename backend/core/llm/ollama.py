"""Ollama LLM provider (local)."""
import json
from typing import AsyncGenerator, Dict, List

import httpx

from config import settings
from core.llm.base import LLMProvider
from core.llm.usage import record_usage


class OllamaProvider(LLMProvider):
    """Calls Ollama via its native HTTP API."""

    def __init__(self):
        super().__init__(model_name=settings.OLLAMA_MODEL_NAME)
        self.base_url = settings.OLLAMA_BASE_URL

    async def complete(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        json_mode: bool = False,
    ) -> str:
        payload: Dict = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if json_mode:
            payload["format"] = "json"

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0)
        ) as client:
            resp = await client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            body = resp.json()
            record_usage(
                self.model_name,
                body.get("prompt_eval_count", 0),
                body.get("eval_count", 0),
            )
            return body["message"]["content"]

    async def stream(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
    ) -> AsyncGenerator[str, None]:
        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": True,
            "options": {"temperature": temperature},
        }
        recorded = False

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(120.0, connect=10.0)
        ) as client:
            async with client.stream(
                "POST", f"{self.base_url}/api/chat", json=payload
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                        if chunk.get("done") and not recorded:
                            record_usage(
                                self.model_name,
                                chunk.get("prompt_eval_count", 0),
                                chunk.get("eval_count", 0),
                            )
                            recorded = True
                        content = chunk.get("message", {}).get("content", "")
                        if content:
                            yield content
                    except json.JSONDecodeError:
                        pass
