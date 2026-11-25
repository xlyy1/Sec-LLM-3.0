"""CPE 解析、归一与 fallback 映射。

nmap ``-sV`` 通常直接在 ``<cpe>`` 里给出 CPE，但那是 2.2 URI 形式
(``cpe:/a:apache:http_server:2.4.49``)，NVD 用的是 2.3 格式串
(``cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*``)。这里统一转成 2.3。

识别不出 CPE 时走本地 fallback 表（``data/cpe_fallback.json``）：表很小、
人工维护、可评审。**不做模糊匹配**——匹配不上就是 ``none``，让上层知道
"这里没识别出来"，而不是猜一个看起来合理的 CPE 出来。

已知限制：不处理 CPE 的转义语义（``\\:`` 之类），只在切分时保留原样。
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional, Tuple

#: CPE 2.3 的十一个属性，顺序即格式串中的顺序。
PARTS_23 = (
    "part", "vendor", "product", "version", "update", "edition",
    "language", "sw_edition", "target_sw", "target_hw", "other",
)
#: CPE 2.2 URI 支持的属性。
PARTS_22 = ("part", "vendor", "product", "version", "update", "edition", "language")

_FALLBACK_PATH = Path(__file__).with_name("data") / "cpe_fallback.json"
_WHITESPACE = re.compile(r"\s+")


def _split(cpe_string: str) -> list[str]:
    """按未转义的 ``:`` 切分。"""
    parts: list[str] = []
    buffer: list[str] = []
    escaped = False
    for char in cpe_string:
        if escaped:
            buffer.append(char)
            escaped = False
        elif char == "\\":
            buffer.append(char)
            escaped = True
        elif char == ":":
            parts.append("".join(buffer))
            buffer = []
        else:
            buffer.append(char)
    parts.append("".join(buffer))
    return parts


def parse_cpe(cpe_string) -> Optional[dict]:
    """解析 CPE 2.2 URI 或 2.3 格式串；无法识别返回 ``None``。"""
    text = (cpe_string or "").strip()
    if not text.startswith("cpe:"):
        return None
    fields = _split(text)

    if len(fields) >= 2 and fields[1] == "2.3":
        if len(fields) != 2 + len(PARTS_23):
            return None
        parsed = dict(zip(PARTS_23, fields[2:]))
        parsed["format"] = "2.3"
        return parsed

    # CPE 2.2 URI：cpe:/a:vendor:product:version...
    if len(fields) < 2 or not fields[1].startswith("/"):
        return None
    values = fields[1:]
    values[0] = values[0][1:]  # 去掉 part 前面的 '/'
    if len(values) > len(PARTS_22):
        return None
    parsed = {name: (values[i] if i < len(values) else "*") for i, name in enumerate(PARTS_22)}
    parsed["format"] = "2.2"
    for name in PARTS_23:
        parsed.setdefault(name, "*")
    return parsed


def build_cpe23(
    part: str = "a",
    vendor: str = "*",
    product: str = "*",
    version: str = "*",
    **extra: str,
) -> str:
    """拼一个 2.3 格式串；未给出的属性一律填 ``*``（ANY）。"""
    values = [
        part or "*",
        vendor or "*",
        product or "*",
        version or "*",
    ]
    values += [(extra.get(name) or "*") for name in PARTS_23[4:]]
    return "cpe:2.3:" + ":".join(values)


def to_cpe23(cpe_string) -> Optional[str]:
    """任何可识别的 CPE → 2.3 格式串；已经是 2.3 的原样返回。"""
    parsed = parse_cpe(cpe_string)
    if not parsed:
        return None
    if parsed["format"] == "2.3":
        return (cpe_string or "").strip()
    return build_cpe23(
        parsed["part"] or "*",
        parsed["vendor"] or "*",
        parsed["product"] or "*",
        parsed["version"] or "*",
        update=parsed.get("update"),
        edition=parsed.get("edition"),
        language=parsed.get("language"),
    )


@lru_cache(maxsize=1)
def _fallback_table() -> dict:
    """读 fallback 表。文件缺失或损坏时返回空表——不能因为一张可选表炸掉解析。"""
    try:
        with _FALLBACK_PATH.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return data.get("by_product") or {}


def _normalize_name(text) -> str:
    return _WHITESPACE.sub(" ", (text or "").strip().lower())


def service_to_cpe(
    service=None,
    product=None,
    version=None,
) -> Tuple[Optional[str], str]:
    """用 fallback 表把服务名/产品名映射成 CPE。

    返回 ``(cpe23 或 None, source)``，``source`` 取 ``"fallback"`` 或 ``"none"``。
    版本未知时 CPE 的 version 为 ``*``，上层因此不会拿它去匹配 CVE——
    ``*`` 版本的候选集太大，匹配出来就是噪音。
    """
    entry = _fallback_table().get(_normalize_name(product))
    if not entry:
        return None, "none"
    vendor = entry.get("vendor")
    name = entry.get("product")
    if not vendor or not name:
        return None, "none"
    return build_cpe23("a", vendor, name, (version or "").strip() or "*"), "fallback"
