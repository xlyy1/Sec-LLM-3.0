"""Code vulnerability auditor tool (SAST)."""
from core.llm.router import single_shot_completion
from tools.registry import register_tool

CODE_AUDIT_SYSTEM_PROMPT = """
你是高级应用安全代码审计专家。请审计用户提供的 {language} 代码，并且只返回 JSON。
输出结构：
{
  "risk_level": "Low|Medium|High|Critical",
  "findings": [
    {
      "title": "漏洞标题",
      "severity": "Low|Medium|High|Critical",
      "line_hint": "行号或位置描述",
      "description": "漏洞说明",
      "fix": "修复建议"
    }
  ],
  "fixed_code": "修复后的完整代码（保留换行）",
  "summary": "中文总结"
}
不要输出 markdown 或解释文本。
"""


@register_tool(
    name="code_auditor",
    description="Perform SAST analysis on source code. Returns vulnerability findings "
    "with severity ratings, descriptions, and fix suggestions. Supports Python, "
    "JavaScript, Go, Java, and more.",
    category="exploit",
)
async def audit_code(code: str, language: str = "python", provider: str = "local") -> dict:
    """Audit source code for security vulnerabilities."""
    from tools.registry import _extract_json

    system_prompt = CODE_AUDIT_SYSTEM_PROMPT.replace("{language}", language)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"请审计并修复以下代码：\n\n{code[:30000]}"},
    ]
    raw = await single_shot_completion(messages, provider=provider, temperature=0.2, json_mode=True)
    parsed = _extract_json(raw) or {}
    return {
        "risk_level": parsed.get("risk_level", "Low"),
        "findings": parsed.get("findings", []),
        "fixed_code": parsed.get("fixed_code", ""),
        "summary": parsed.get("summary", ""),
    }
