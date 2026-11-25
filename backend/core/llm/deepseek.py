"""DeepSeek LLM provider (cloud)."""
import json
from typing import AsyncGenerator, Dict, List

import httpx

from config import settings
from core.llm.base import LLMProvider
from core.llm.usage import record_usage


class DeepSeekProvider(LLMProvider):
    """Calls DeepSeek via OpenAI-compatible API."""

    def __init__(self, api_key: str):
        super().__init__(model_name=settings.DEEPSEEK_MODEL_NAME)
        self.base_url = settings.DEEPSEEK_BASE_URL.rstrip("/")
        self.api_key = api_key

    async def complete(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        json_mode: bool = False,
    ) -> str:
        payload: Dict = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {"Authorization": f"Bearer {self.api_key}"}

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0)
        ) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            body = resp.json()
            usage = body.get("usage") or {}
            record_usage(
                self.model_name,
                usage.get("prompt_tokens", 0),
                usage.get("completion_tokens", 0),
            )
            return body["choices"][0]["message"]["content"]

    async def stream(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
    ) -> AsyncGenerator[str, None]:
        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": True,
            "stream_options": {"include_usage": True},
            "temperature": temperature,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        recorded = False

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(120.0, connect=10.0)
        ) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
            ) as resp:
                if resp.status_code >= 400:
                    body = (await resp.aread()).decode("utf-8", errors="ignore")[:500]
                    print(f"[DeepSeek Error] HTTP {resp.status_code}: {body}")
                    raise httpx.HTTPStatusError(
                        f"DeepSeek API returned {resp.status_code}",
                        request=resp.request,
                        response=resp,
                    )

                async for line in resp.aiter_lines():
                    if not line:
                        continue
                    data = (
                        line[5:].strip()
                        if line.startswith("data:")
                        else line.strip()
                    )
                    if not data or data == "[DONE]":
                        continue
                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    usage = chunk.get("usage")
                    if usage and not recorded:
                        record_usage(
                            self.model_name,
                            usage.get("prompt_tokens", 0),
                            usage.get("completion_tokens", 0),
                        )
                        recorded = True
                    choices = chunk.get("choices") or []
                    if choices:
                        delta = choices[0].get("delta") or {}
                        content = delta.get("content")
                        if content:
                            yield content
