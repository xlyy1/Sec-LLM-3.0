"""Query rewriting for RAG — resolves pronouns and adds context."""
from typing import Dict, List

import httpx

from config import settings, normalize_provider


async def rewrite_query(user_msg: str, history: List[Dict[str, str]], provider: str = "local"):
    """Rewrite user query using conversation history for better RAG retrieval."""
    if not history:
        return user_msg

    print(f"[Rewriting] Original: {user_msg} | provider={provider}")

    history_text = ""
    for msg in history[-4:]:
        role = "User" if msg["role"] == "user" else "Assistant"
        history_text += role + ": " + msg["content"] + "\n"

    system_prompt = (
        "You are a search query optimization expert. "
        "Rewrite the follow-up question into a standalone search query. "
        "Rules: 1. Replace pronouns with nouns. 2. Fill in context. "
        "3. Keep meaning. 4. Output ONLY the rewritten sentence."
    )
    user_prompt = "[History]: " + history_text + "\n[Question]: " + user_msg + "\n[Rewritten]:"

    selected = normalize_provider(provider)
    try:
        if selected == "cloud":
            if not settings.DEEPSEEK_API_KEY:
                return user_msg
            from openai import OpenAI
            client = OpenAI(api_key=settings.DEEPSEEK_API_KEY, base_url=settings.DEEPSEEK_BASE_URL)
            response = client.chat.completions.create(
                model=settings.DEEPSEEK_MODEL_NAME,
                messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                temperature=0.1, max_tokens=200,
            )
            new_query = response.choices[0].message.content.strip()
        else:
            url = f"{settings.OLLAMA_BASE_URL}/api/chat"
            payload = {
                "model": settings.OLLAMA_MODEL_NAME,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
                "options": {"temperature": 0.1},
            }
            async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                new_query = resp.json()["message"]["content"].strip()
        print(f"[Rewriting] Result: {new_query}")
        return new_query
    except Exception as e:
        print(f"[Rewriting Error] {e}")
    return user_msg


def extract_query_keywords(text: str):
    """Extract English words and Chinese characters for keyword matching."""
    import re
    if not text:
        return []
    parts = re.findall(r"[A-Za-z0-9_]+|[一-鿿]{2,}", text.lower())
    dedup = []
    seen = set()
    for p in parts:
        if len(p) >= 2 and p not in seen:
            seen.add(p)
            dedup.append(p)
    return dedup


def query_matches_context(query: str, context: str) -> bool:
    """Check if query keywords appear in the retrieved context."""
    keywords = extract_query_keywords(query)
    if not keywords:
        return False
    ctx = (context or "").lower()
    return any(k in ctx for k in keywords)
