"""CVE 匹配：SQLite 只做窄化，Python 做版本判定。

为什么不在 SQL 里比版本：SQLite 没有语义版本比较，`ORDER BY version` 是字符串
序，`2.4.5` 会排在 `2.4.49` 后面。把判定放到 Python 里、复用 ``core.kg.version``，
才能和单测固定下来的规则保持一致。

只读打开数据库；库文件不存在时返回带 reason 的空结果，而不是抛异常——
扫描不应该因为一个可选的知识库没建好就整体失败。
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.kg.cpe import parse_cpe, service_to_cpe
from core.kg.version import is_any, is_na, matches

DEFAULT_TOP_N = 5

#: CPE 来源 → 边置信度。fallback 是查表猜的，置信度明显低于 nmap 直接给的。
SOURCE_CONFIDENCE = {"nmap": 0.95, "fallback": 0.6}
#: NVD 的 AND 组合节点需要同时满足多个条件，朴素实现只看见其中一条，降置信度。
AND_NODE_CONFIDENCE = 0.4

BOUNDS = ("version_start_incl", "version_start_excl", "version_end_incl", "version_end_excl")

_CANDIDATES_SQL = """
SELECT m.cve_id, m.cpe23, m.vendor, m.product,
       m.version_start_incl, m.version_start_excl,
       m.version_end_incl, m.version_end_excl,
       m.node_operator,
       c.cve_id, c.cvss_v3_score, c.cvss_vector, c.severity, c.published, c.description, c.cwe_ids
FROM kg_cpe_match AS m
JOIN kg_cve AS c ON c.cve_id = m.cve_id
WHERE m.product = ? AND m.vulnerable = 1
"""


def default_db_path() -> Path:
    """默认 ``backend/data/kg.db``；可用 ``AGENT_KG_DB_PATH`` 覆盖。"""
    configured = ""
    try:
        from config import settings

        configured = getattr(settings, "AGENT_KG_DB_PATH", "") or ""
    except Exception:  # noqa: BLE001 —— 配置层不可用时退回默认路径
        configured = ""

    if configured:
        path = Path(configured)
        return path if path.is_absolute() else Path(__file__).resolve().parents[2] / path
    return Path(__file__).resolve().parents[2] / "data" / "kg.db"


def _empty(kb: "KnowledgeBase", reason: str) -> Dict[str, Any]:
    return {"matched": [], "total": 0, "shown": 0, "reason": reason, "kb": kb.describe()}


class KnowledgeBase:
    """只读的 CVE 快照。

    正常用法是给一个 ``kg.db`` 路径。``connection`` 用于复用已有的连接（测试里的
    内存库、或调用方自己管生命周期），此时不关闭它、也不改它的 PRAGMA。
    """

    def __init__(self, path: Optional[Any] = None, *, connection: Optional[sqlite3.Connection] = None):
        self.path = Path(path) if path else default_db_path()
        self._connection = connection
        if connection is not None:
            connection.row_factory = sqlite3.Row
        self._available = connection is not None or self.path.is_file()

    @property
    def available(self) -> bool:
        return self._available

    def describe(self) -> Dict[str, Any]:
        return {"path": str(self.path), "available": self._available, "meta": self.meta()}

    def meta(self) -> Dict[str, str]:
        if not self._available:
            return {}
        try:
            with self._session() as connection:
                rows = connection.execute("SELECT key, value FROM kg_meta").fetchall()
        except sqlite3.DatabaseError:
            return {}
        return {str(key): str(value) for key, value in rows}

    def _connect(self) -> sqlite3.Connection:
        if self._connection is not None:
            return self._connection
        connection = sqlite3.connect(str(self.path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        return connection

    @contextmanager
    def _session(self):
        """借来的连接不关闭；自己开的连接用完即关。"""
        connection = self._connect()
        try:
            yield connection
        finally:
            if self._connection is None:
                connection.close()

    # ---------------------------------------------------------------- 匹配

    def match_service(self, service: Optional[Dict[str, Any]], top_n: int = DEFAULT_TOP_N) -> Dict[str, Any]:
        """把一个服务指纹匹配到候选 CVE。

        返回 ``{"matched": [...], "total": 命中总数, "shown": 实际返回数,
        "reason": None|"原因", "kb": {...}}``。
        """
        service = service or {}

        if not self._available:
            return _empty(self, f"knowledge base not found: {self.path}")

        version = str(service.get("version") or "").strip()
        cpe = str(service.get("cpe23") or "").strip()
        source = str(service.get("cpe_source") or "none")

        if not cpe:
            cpe, source = service_to_cpe(service.get("service"), service.get("product"), version)
        if not cpe:
            return _empty(self, "no cpe identified for this service")

        parsed = parse_cpe(cpe) or {}
        product = str(parsed.get("product") or "").strip()
        if not product or product == "*":
            return _empty(self, "cpe has no product component")

        if not version:
            version = str(parsed.get("version") or "").strip()

        # nmap 的 version 属性常带发行版后缀（实测 "8.9p1 Ubuntu 3ubuntu0.1"），
        # 拿它去比 NVD 区间会算出无意义的结果；CPE 里的版本是归一化过的，优先用。
        cpe_version = str(parsed.get("version") or "").strip()
        if cpe_version and not is_any(cpe_version) and not is_na(cpe_version):
            version = cpe_version

        if is_any(version) or is_na(version):
            return _empty(self, "service version is unknown; a wildcard would match everything")
        if any(char.isspace() for char in version):
            # 仍然不像单个版本（例如 "3.5 - 3.10" 这种区间 banner）：宁可漏报，不猜。
            return _empty(self, f"service version is not a single version token: {version!r}")

        try:
            with self._session() as connection:
                rows = connection.execute(_CANDIDATES_SQL, (product,)).fetchall()
        except sqlite3.DatabaseError as error:
            return _empty(self, f"knowledge base is unreadable: {error}")

        hits: List[Dict[str, Any]] = []
        seen = set()
        for row in rows:
            if not _version_in_match(version, row):
                continue
            if row["cve_id"] in seen:
                continue
            seen.add(row["cve_id"])
            hits.append(_hit(row, service, version, cpe, source))

        hits.sort(
            key=lambda item: (
                item["cvss_score"] or 0.0,
                # 同分时"精确版本命中"优先于宽区间：NVD 直接把 criteria 写成 2.4.49 的条目，
                # 比"≤2.4.69、无下界"这种更能说明这条 CPE 就是这个版本。
                item["specificity"],
                item["published"] or "",
            ),
            reverse=True,
        )
        top = hits[: max(0, int(top_n))]
        return {
            "matched": top,
            "total": len(hits),
            "shown": len(top),
            "reason": None if hits else "no CVE matched this product and version",
            "kb": self.describe(),
        }

    def match_services(self, services: List[Dict[str, Any]], top_n: int = DEFAULT_TOP_N) -> Dict[str, Any]:
        """批量匹配，返回按服务分组的结果与汇总计数。"""
        results = {}
        total = 0
        matched_services = 0
        reasons: List[str] = []

        for service in services or []:
            label = f"{service.get('host', '')}:{service.get('port', '')}"
            outcome = self.match_service(service, top_n=top_n)
            results[label] = outcome
            total += outcome["total"]
            if outcome["matched"]:
                matched_services += 1
            elif outcome["reason"] and outcome["reason"] not in reasons:
                reasons.append(outcome["reason"])

        return {
            "by_service": results,
            "summary": {
                "services": len(services or []),
                "matched_services": matched_services,
                "total_candidates": total,
            },
            "reasons": reasons,
            "kb": self.describe(),
        }


def _version_in_match(version: str, row: sqlite3.Row) -> bool:
    """一条 ``cpeMatch`` 是否覆盖 ``version``。"""
    bounds = {key: row[key] for key in BOUNDS}
    if all(value is None for value in bounds.values()):
        parsed = parse_cpe(row["cpe23"]) or {}
        return matches(version, parsed.get("version"))
    return matches(
        version,
        start_including=bounds["version_start_incl"],
        start_excluding=bounds["version_start_excl"],
        end_including=bounds["version_end_incl"],
        end_excluding=bounds["version_end_excl"],
    )


def _hit(row: sqlite3.Row, service: Dict[str, Any], version: str, cpe: str, source: str) -> Dict[str, Any]:
    confidence = SOURCE_CONFIDENCE.get(source, 0.0)
    operator = str(row["node_operator"] or "OR").upper()
    if operator == "AND":
        confidence = min(confidence, AND_NODE_CONFIDENCE) if confidence else AND_NODE_CONFIDENCE

    # 1 = NVD 的 criteria 直接写死版本且没有区间；0 = 靠区间覆盖。
    criteria_version = (parse_cpe(row["cpe23"]) or {}).get("version")
    exact = all(row[key] is None for key in BOUNDS) and not is_any(criteria_version) and not is_na(criteria_version)

    cwe_ids = []
    raw_cwe = row["cwe_ids"]
    if raw_cwe:
        import json

        try:
            cwe_ids = [str(item) for item in json.loads(raw_cwe)]
        except (ValueError, TypeError):
            cwe_ids = []

    return {
        "cve_id": row["cve_id"],
        "description": row["description"] or "",
        "cvss_score": row["cvss_v3_score"],
        "cvss_vector": row["cvss_vector"] or "",
        # NVD 给的是全大写（CRITICAL），项目其余部分用首字母大写，这里统一。
        "severity": _title(row["severity"]) or _severity(row["cvss_v3_score"]),
        "published": row["published"] or "",
        "cwe_ids": cwe_ids,
        "fix_version": row["version_end_excl"] or "",
        "cpe": cpe,
        "matched_version": version,
        "asset": {
            "host": service.get("host", ""),
            "port": service.get("port", ""),
            "service": service.get("service", ""),
            "product": service.get("product", ""),
            # 一路带到报告/图上：CPE 是 nmap 直接给的，还是查表猜的。
            "cpe_source": source,
        },
        "cpe_source": source,
        "provenance": [
            {
                "edge": "service->cpe",
                "source": source,
                "confidence": SOURCE_CONFIDENCE.get(source, 0.0),
            },
            {
                "edge": "cpe->cve",
                "source": "nvd",
                "confidence": 1.0 if operator != "AND" else AND_NODE_CONFIDENCE,
                "node_operator": operator,
            },
        ],
        "confidence": confidence,
        "specificity": 1 if exact else 0,
        "inference": True,
    }


def _title(value: Any) -> str:
    text = str(value or "").strip()
    return text.capitalize() if text else ""


def _severity(score: Any) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "Unknown"
    if value >= 9.0:
        return "Critical"
    if value >= 7.0:
        return "High"
    if value >= 4.0:
        return "Medium"
    if value > 0:
        return "Low"
    return "Unknown"
