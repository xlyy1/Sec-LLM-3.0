"""Per-request LLM usage accounting.

Providers call ``record_usage`` with the token counts returned by the API. The
current user id travels in a ContextVar so agent graphs and tool calls are
attributed to the session owner without threading a user argument through every
prompt builder.
"""
from __future__ import annotations

import contextvars
from typing import Any, Dict, Optional

from core.observability import LLM_TOKENS

_current_user_id: contextvars.ContextVar[Optional[Any]] = contextvars.ContextVar(
    "llm_user_id", default=None
)


class user_context:
    """Attribute every LLM call inside the block to ``user_id``."""

    def __init__(self, user_id: Any) -> None:
        self.user_id = user_id
        self._token = None

    def __enter__(self):
        self._token = _current_user_id.set(self.user_id)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._token is not None:
            _current_user_id.reset(self._token)
        return False


def current_user_id() -> Optional[Any]:
    return _current_user_id.get()


def record_usage(
    model: str,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
) -> Dict[str, int]:
    """Record token usage for the active user (if any) and Prometheus."""
    prompt = max(int(prompt_tokens or 0), 0)
    completion = max(int(completion_tokens or 0), 0)
    usage = {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": prompt + completion,
    }
    if prompt:
        LLM_TOKENS.labels(model=model or "unknown", kind="prompt").inc(prompt)
    if completion:
        LLM_TOKENS.labels(model=model or "unknown", kind="completion").inc(completion)

    user_id = _current_user_id.get()
    if user_id is not None and usage["total_tokens"]:
        from core import state

        state.add_token_usage(user_id, model or "unknown", prompt, completion)
    return usage
