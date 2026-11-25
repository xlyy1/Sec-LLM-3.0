"""资产-CVE 关联的核心逻辑，设计见 docs/kg.md。

分三层，互不依赖：
- ``version``      CPE 版本比较与区间判定（纯函数，无 IO）
- ``cpe``          CPE 解析、归一与 fallback 映射（只读本地 JSON）
- ``nmap_parse``   nmap XML → 服务指纹（只解析，不联网不匹配）

匹配层（store.py）与工具层（tools/cve_match.py）属于 P1，不在本包内。
"""
from core.kg.cpe import (
    build_cpe23,
    parse_cpe,
    service_to_cpe,
    to_cpe23,
)
from core.kg.nmap_parse import parse_nmap_xml
from core.kg.version import compare, is_any, is_na, matches

__all__ = [
    "parse_nmap_xml",
    "build_cpe23",
    "parse_cpe",
    "service_to_cpe",
    "to_cpe23",
    "compare",
    "is_any",
    "is_na",
    "matches",
]
