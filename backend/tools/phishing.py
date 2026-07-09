"""Phishing email analyzer tool."""
from core.llm.router import single_shot_completion
from tools.registry import register_tool

PHISHING_SYSTEM_PROMPT = """
你是资深反钓鱼分析师。请对输入邮件进行风险评估，并且只返回 JSON。
输出字段必须包含：
{
  "risk_score": 0-100 的整数,
  "verdict": "低风险|中风险|高风险",
  "dimensions": {
    "sender_spoofing": 0-100,
    "urgency_language": 0-100,
    "malicious_links": 0-100,
    "attachment_risk": 0-100
  },
  "suspicious_urls": [字符串数组],
  "suspicious_ips": [字符串数组],
  "summary": "中文总结",
  "recommendations": ["中文建议1","中文建议2"]
}
不要输出任何 markdown 或解释。
"""


@register_tool(
    name="phishing_analyzer",
    description="Analyze email content for phishing indicators. Returns risk score, "
    "verdict, suspicious URLs/IPs, and recommendations.",
    category="recon",
)
async def analyze_phishing(content: str, provider: str = "local") -> dict:
    """Analyze email content for phishing indicators."""
    from tools.registry import _extract_json

    messages = [
        {"role": "system", "content": PHISHING_SYSTEM_PROMPT},
        {"role": "user", "content": f"请分析这封可疑邮件：\n\n{content[:15000]}"},
    ]
    raw = await single_shot_completion(messages, provider=provider, temperature=0.2, json_mode=True)
    parsed = _extract_json(raw) or {}
    return {
        "risk_score": int(parsed.get("risk_score", 0)),
        "verdict": parsed.get("verdict", "低风险"),
        "dimensions": parsed.get("dimensions", {}),
        "suspicious_urls": parsed.get("suspicious_urls", []),
        "suspicious_ips": parsed.get("suspicious_ips", []),
        "summary": parsed.get("summary", ""),
        "recommendations": parsed.get("recommendations", []),
    }
