"""把服务指纹匹配到 CVE 的 Agent 工具。

输入是侦察阶段解析出的服务列表（``nmap_services``），输出是候选 CVE。它不改动
目标、不发请求、不产出证据文件——因此结果只能是 ``unverified`` 的推断，
这一点由调用方（``agents.reporting.annotate_finding``）强制。
"""
from __future__ import annotations

from typing import Any, Dict, List

from core.kg.nmap_parse import parse_nmap_xml
from core.kg.store import DEFAULT_TOP_N, KnowledgeBase
from tools.registry import register_tool

INFERENCE_KIND = "version_range_inference"


def _finding(hit: Dict[str, Any], snapshot: str = "") -> Dict[str, Any]:
    asset = hit.get("asset") or {}
    product = asset.get("product") or "unknown product"
    version = hit.get("matched_version") or ""
    cwe_ids = hit.get("cwe_ids") or []

    finding = {
        "title": f"疑似受影响组件：{product} {version} 匹配 {hit['cve_id']}".strip(),
        "severity": hit.get("severity") or "Unknown",
        "description": hit.get("description") or "",
        "cvss_score": hit.get("cvss_score"),
        "cvss_vector": hit.get("cvss_vector") or "",
        "cvss_source": "nvd",
        "cve_id": hit["cve_id"],
        "cpe": hit.get("cpe") or "",
        "affected_asset": asset,
        "matched_version": version,
        "fix_version": hit.get("fix_version") or "",
        "confidence": hit.get("confidence"),
        "provenance": hit.get("provenance") or [],
        "evidence_kind": INFERENCE_KIND,
        "inference": True,
        "verification_reason": "版本区间推断（NVD cpeMatch），未在目标上复现",
    }
    if cwe_ids:
        finding["cwe_id"] = cwe_ids[0]
        finding["cwe_ids"] = cwe_ids

    # 快照日期写进 provenance：报告和图上都必须能看出"这是哪天的库"。
    if snapshot:
        for item in finding["provenance"]:
            if isinstance(item, dict) and item.get("edge") == "cpe->cve":
                item["snapshot"] = snapshot
    return finding


@register_tool(
    name="cve_match",
    description=(
        "Match detected service banners (product + version) against the local offline NVD "
        "knowledge base and return candidate CVEs with CVSS, CWE and fix version. "
        "Results are version-range inferences, never confirmed exploits, and this tool never "
        "touches the target. Use it after a port scan produced service versions."
    ),
    category="recon",
    requires_provider=False,
)
async def cve_match(
    services: List[Dict[str, Any]] | None = None,
    nmap_xml: str = "",
    top_n: int = DEFAULT_TOP_N,
) -> Dict[str, Any]:
    """``services`` 优先；没有时尝试解析 ``nmap_xml``。"""
    if not services and nmap_xml:
        services = parse_nmap_xml(nmap_xml).get("services") or []

    services = [item for item in (services or []) if isinstance(item, dict)]
    if not services:
        return {"status": "skipped", "reason": "no service fingerprints available",
                "findings": [], "summary": {"services": 0, "matched_services": 0, "total_candidates": 0}}

    knowledge = KnowledgeBase()
    if not knowledge.available:
        return {
            "status": "skipped",
            "reason": f"knowledge base not built ({knowledge.path}); run python -m tools.kg_import",
            "findings": [],
            "summary": {"services": len(services), "matched_services": 0, "total_candidates": 0},
        }

    outcome = knowledge.match_services(services, top_n=top_n)
    snapshot = str((outcome["kb"].get("meta") or {}).get("snapshot_date") or "")
    findings: List[Dict[str, Any]] = []
    for result in outcome["by_service"].values():
        for hit in result["matched"]:
            findings.append(_finding(hit, snapshot))

    return {
        "status": "success",
        "findings": findings,
        "summary": {
            **outcome["summary"],
            "shown": len(findings),
            "reasons": outcome["reasons"],
        },
        "kb": outcome["kb"],
        "note": "这些是版本区间推断，不是已验证漏洞；只有复现成功才可升级为 verified。",
    }
