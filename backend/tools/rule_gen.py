"""Blue-team detection rule generator tool."""
from core.llm.router import stream_completion
from tools.registry import register_tool


@register_tool(
    name="rule_generator",
    description="Generate YARA/Suricata/Snort detection rules from a natural language "
    "description of the threat or detection requirement.",
    category="report",
)
async def generate_rule(
    requirement: str,
    rule_type: str = "yara",
    provider: str = "local",
) -> str:
    """Generate a defensive detection rule and stream the result."""
    system_prompt = (
        "You are a senior blue-team detection engineer. "
        "Generate practical defensive rules based on user requirement.\n\n"
        "Rules:\n"
        "1) Output in Simplified Chinese summary first.\n"
        f"2) Then provide the final {rule_type} rule in a fenced code block.\n"
        "3) Add a short validation checklist.\n"
        "4) Never answer non-security content."
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"需求：{requirement}"},
    ]
    chunks: list[str] = []
    async for chunk in stream_completion(messages, provider=provider, temperature=0.2):
        chunks.append(chunk)
    return "".join(chunks)
