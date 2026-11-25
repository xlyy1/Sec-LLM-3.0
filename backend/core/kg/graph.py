"""会话发现 → 图投影。

输入就是 ``agent_sessions.findings`` 里的列表，输出是前端能直接画的 nodes/edges。
不查库、不联网、不重跑匹配：图必须和报告是同一份数据，否则两边对不上。

只有 CVE 类发现会出现在图上。端口开着但没匹配到 CVE 的服务在 findings 里没有
对应记录，因此不会画出节点——这是已知的表示缺口，不在这里补（补的话要么改
会话存储，要么每次请求重跑扫描，都不划算）。

每条边都带 ``source_of_truth`` 与 ``confidence``：图上的连线是推断，不是证据。
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

#: 渲染顺序：从资产到结论，前端可以照着这个顺序做布局初始化。
NODE_ORDER = {"asset": 0, "service": 1, "cpe": 2, "cve": 3, "cwe": 4, "fix": 5}

#: cpe_source → 边置信度，与 core.kg.store 保持一致。
CONFIDENCE = {"nmap": 0.95, "fallback": 0.6}


def _node_id(kind: str, value: str) -> str:
    return f"{kind}:{value}"


def _add_node(nodes: Dict[str, Dict[str, Any]], node: Dict[str, Any]) -> None:
    # 先出现的赢：同一节点可能被多个 finding 重复引用，保留第一次的标签。
    nodes.setdefault(node["id"], node)


def _add_edge(edges: Dict[tuple, Dict[str, Any]], source: str, target: str, rel: str,
              *, source_of_truth: str = "nvd", confidence: float = 1.0, **extra: Any) -> None:
    key = (source, target, rel)
    if key in edges:
        return
    edge = {
        "source": source,
        "target": target,
        "rel": rel,
        "source_of_truth": source_of_truth,
        "confidence": confidence,
    }
    edge.update({key: value for key, value in extra.items() if value})
    edges[key] = edge


def _component_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        finding for finding in findings
        if isinstance(finding, dict) and finding.get("cve_id") and isinstance(finding.get("affected_asset"), dict)
    ]


def _snapshot_of(findings: Iterable[Dict[str, Any]]) -> str:
    """从 provenance 里取 NVD 快照日期；不同 finding 可能来自不同快照，取第一个。"""
    for finding in findings:
        for item in finding.get("provenance") or []:
            if isinstance(item, dict) and item.get("snapshot"):
                return str(item["snapshot"])
    return ""


def build_graph(findings: Optional[List[Dict[str, Any]]], *, session_id: str = "",
                snapshot: str = "") -> Dict[str, Any]:
    """把 findings 投影成 ``{nodes, edges, summary, reason}``。"""
    findings = [item for item in (findings or []) if isinstance(item, dict)]
    components = _component_findings(findings)

    nodes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[tuple, Dict[str, Any]] = {}
    verified = 0

    for finding in components:
        asset = finding["affected_asset"]
        host = str(asset.get("host") or "").strip()
        port = str(asset.get("port") or "").strip()
        if not host:
            continue

        cve_id = str(finding["cve_id"])
        cpe = str(finding.get("cpe") or "")
        cpe_source = str(asset.get("cpe_source") or finding.get("cpe_source") or "nmap")
        confidence = CONFIDENCE.get(cpe_source, 0.6)

        if finding.get("verification_status") == "verified":
            verified += 1

        asset_id = _node_id("asset", host)
        _add_node(nodes, {"id": asset_id, "type": "asset", "label": host, "attrs": {}})

        service_label = " ".join(part for part in (
            str(asset.get("service") or ""),
            str(asset.get("product") or ""),
            str(finding.get("matched_version") or ""),
        ) if part) or f"{host}:{port}"
        service_id = _node_id("svc", f"{host}:{port}")
        _add_node(nodes, {
            "id": service_id, "type": "service", "label": service_label,
            "attrs": {"port": port, "cpe_source": cpe_source},
        })
        # "端口开着"这件事是 nmap 直接观测到的，与 CPE 是否靠查表无关。
        _add_edge(edges, asset_id, service_id, "runs",
                  source_of_truth="nmap", confidence=0.95)

        cve_node_id = _node_id("cve", cve_id)
        _add_node(nodes, {
            "id": cve_node_id, "type": "cve", "label": cve_id,
            "attrs": {
                "cvss_score": finding.get("cvss_score"),
                "severity": finding.get("severity"),
                "verification_status": finding.get("verification_status"),
            },
        })

        if cpe:
            cpe_id = cpe
            cpe_label = " ".join(part for part in (
                str(asset.get("product") or ""),
                str(finding.get("matched_version") or ""),
            ) if part) or cpe
            _add_node(nodes, {"id": cpe_id, "type": "cpe", "label": cpe_label,
                              "attrs": {"cpe23": cpe}})
            _add_edge(edges, service_id, cpe_id, "normalizes_to",
                      source_of_truth=cpe_source, confidence=confidence)
            _add_edge(edges, cpe_id, cve_node_id, "affected_by",
                      source_of_truth="nvd", confidence=float(finding.get("confidence") or 1.0),
                      snapshot=snapshot)
        else:
            # 没有 CPE 时无法表达"归一"这一跳，直接连 service→cve，并标记为弱证据。
            _add_edge(edges, service_id, cve_node_id, "affected_by",
                      source_of_truth="nvd", confidence=0.4,
                      snapshot=snapshot, note="no cpe")

        for cwe in finding.get("cwe_ids") or ([finding["cwe_id"]] if finding.get("cwe_id") else []):
            cwe_id = _node_id("cwe", str(cwe))
            _add_node(nodes, {"id": cwe_id, "type": "cwe", "label": str(cwe), "attrs": {}})
            _add_edge(edges, cve_node_id, cwe_id, "has_weakness", source_of_truth="nvd")

        fix_version = str(finding.get("fix_version") or "").strip()
        if fix_version:
            fix_id = _node_id("fix", fix_version)
            _add_node(nodes, {"id": fix_id, "type": "fix", "label": fix_version, "attrs": {}})
            _add_edge(edges, cve_node_id, fix_id, "fixed_in", source_of_truth="nvd")

    ordered_nodes = sorted(nodes.values(), key=lambda item: (NODE_ORDER.get(item["type"], 99), item["id"]))
    ordered_edges = sorted(edges.values(), key=lambda item: (item["source"], item["target"], item["rel"]))

    reason = None
    if not components:
        reason = "no component findings in this session; run a port scan first"

    return {
        "session_id": session_id,
        "snapshot": snapshot or _snapshot_of(components),
        "nodes": ordered_nodes,
        "edges": ordered_edges,
        "summary": {
            "nodes": len(ordered_nodes),
            "edges": len(ordered_edges),
            "cves": len([item for item in ordered_nodes if item["type"] == "cve"]),
            "verified": verified,
            "inference_only": len(components) - verified,
        },
        "reason": reason,
        "disclaimer": "边为版本区间推断，不代表已验证漏洞；节点数不含未匹配到 CVE 的服务。",
    }
