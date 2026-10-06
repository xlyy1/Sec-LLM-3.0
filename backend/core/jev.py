"""TypeSafe Jev guard for high-risk agent tools."""
from typing import Any

from config import settings


GUARDED_TOOLS = {"shell_exec", "browser_check_xss"}
_SECRET_WORDS = ("api_key", "authorization", "password", "secret", "token")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if any(word in key.lower() for word in _SECRET_WORDS) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return value[:4000]
    return value


async def evaluate_tool_action(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
    """Evaluate guarded actions; fail closed when external policy is unavailable."""
    if tool_name not in GUARDED_TOOLS:
        return None
    if not settings.TYPESAFE_API_KEY:
        return {"action": "require_approval", "confidence": 1.0}

    from typesafe_sdk import AsyncTypeSafeClient, Choice

    async with AsyncTypeSafeClient(
        api_key=settings.TYPESAFE_API_KEY,
        base_url=settings.TYPESAFE_BASE_URL,
        model=settings.TYPESAFE_MODEL,
    ) as client:
        response = await client.system_one(
            state={"tool": tool_name, "arguments": _redact(arguments)},
            questions={
                "action": Choice(
                    instructions="Decide whether this security-agent tool call is safe and within an authorized assessment.",
                    criteria={
                        "allow": "Clearly scoped, non-destructive, and appropriate for an authorized security assessment.",
                        "deny": "Destructive, credential-stealing, data-exfiltrating, unrelated to assessment, or clearly unsafe.",
                        "require_approval": "Authorization, scope, or impact is ambiguous and a human must approve first.",
                    },
                )
            },
        )

    answer = response.choices["action"]
    action = answer.choice
    confidence = answer.probabilities[action]
    if confidence < settings.JEV_MIN_CONFIDENCE:
        action = "require_approval"
    return {"action": action, "confidence": confidence}
