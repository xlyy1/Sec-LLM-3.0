"""findings → 图投影。

固定的是**表示契约**：节点 id 的命名、边的方向与来源、去重与排序。前端按这些
约定画图，改了就得同步改前端。
"""
from core.kg.graph import build_graph

CPE = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


def _finding(cve_id="CVE-2021-41773", *, port=80, host="192.0.2.10", cpe=CPE,
             fix="", cwe=("CWE-22",), version="2.4.49", verified=False,
             snapshot="2026-11-24", product="Apache httpd", severity="Critical", score=9.8):
    return {
        "title": f"疑似受影响组件：{product} {version} 匹配 {cve_id}",
        "severity": severity,
        "cvss_score": score,
        "cvss_source": "nvd",
        "cve_id": cve_id,
        "cpe": cpe,
        "matched_version": version,
        "fix_version": fix,
        "confidence": 0.95,
        "cwe_ids": list(cwe),
        "affected_asset": {
            "host": host, "port": port, "service": "http",
            "product": product, "cpe_source": "nmap",
        },
        "provenance": [
            {"edge": "service->cpe", "source": "nmap", "confidence": 0.95},
            {"edge": "cpe->cve", "source": "nvd", "confidence": 1.0, "snapshot": snapshot},
        ],
        "verification_status": "verified" if verified else "unverified",
    }


def _ids(graph, kind=None):
    return [n["id"] for n in graph["nodes"] if kind is None or n["type"] == kind]


def _edges(graph):
    return {(e["source"], e["target"], e["rel"]) for e in graph["edges"]}


# --- 空输入 -----------------------------------------------------------------


def test_empty_session_returns_empty_graph_with_reason():
    graph = build_graph([], session_id="abc")
    assert graph["nodes"] == [] and graph["edges"] == []
    assert "no component findings" in graph["reason"]
    assert graph["summary"]["nodes"] == 0


def test_non_component_findings_are_ignored():
    graph = build_graph([{"title": "反射型 XSS", "severity": "High", "parameter": "q"}])
    assert graph["nodes"] == []
    assert graph["reason"]


# --- 节点与边 ---------------------------------------------------------------


def test_component_finding_projects_to_full_chain():
    graph = build_graph([_finding()], session_id="abc")
    assert _ids(graph, "asset") == ["asset:192.0.2.10"]
    assert _ids(graph, "service") == ["svc:192.0.2.10:80"]
    assert _ids(graph, "cpe") == [CPE]
    assert _ids(graph, "cve") == ["cve:CVE-2021-41773"]
    assert _ids(graph, "cwe") == ["cwe:CWE-22"]

    assert _edges(graph) == {
        ("asset:192.0.2.10", "svc:192.0.2.10:80", "runs"),
        ("svc:192.0.2.10:80", CPE, "normalizes_to"),
        (CPE, "cve:CVE-2021-41773", "affected_by"),
        ("cve:CVE-2021-41773", "cwe:CWE-22", "has_weakness"),
    }


def test_fix_version_becomes_a_node_only_when_known():
    assert not _ids(build_graph([_finding()]), "fix"), "快照没给修复版本时不画节点"
    graph = build_graph([_finding(fix="2.4.50")])
    assert _ids(graph, "fix") == ["fix:2.4.50"]
    assert ("cve:CVE-2021-41773", "fix:2.4.50", "fixed_in") in _edges(graph)


def test_two_cves_on_one_service_share_the_asset_node():
    graph = build_graph([
        _finding("CVE-2021-41773"),
        _finding("CVE-2021-42013", severity="Critical", score=9.8),
    ])
    assert len(_ids(graph, "asset")) == 1
    assert len(_ids(graph, "service")) == 1
    assert len(_ids(graph, "cve")) == 2
    assert graph["summary"]["cves"] == 2


def test_same_cve_on_two_hosts_is_two_nodes_only_by_asset():
    graph = build_graph([
        _finding(host="192.0.2.10"),
        _finding(host="192.0.2.11"),
    ])
    assert len(_ids(graph, "asset")) == 2
    assert len(_ids(graph, "cve")) == 1, "同一个 CVE 只有一个节点"
    # 2 个资产 + 2 个服务 + 1 个 CPE + 1 个 CVE + 1 个 CWE
    assert graph["summary"]["nodes"] == 7


def test_runs_edge_confidence_is_independent_of_cpe_source():
    """端口是 nmap 直接看到的；CPE 靠查表不影响"这里开着端口"这件事。"""
    finding = _finding()
    finding["affected_asset"]["cpe_source"] = "fallback"
    graph = build_graph([finding])

    runs = next(e for e in graph["edges"] if e["rel"] == "runs")
    normalizes = next(e for e in graph["edges"] if e["rel"] == "normalizes_to")
    assert runs["confidence"] == 0.95
    assert normalizes["confidence"] == 0.6, "查表来的 CPE 必须体现在归一这条边上"


def test_cpe_node_label_is_human_readable():
    graph = build_graph([_finding()])
    node = next(n for n in graph["nodes"] if n["type"] == "cpe")
    assert node["label"] == "Apache httpd 2.4.49"
    assert node["attrs"]["cpe23"] == CPE


def test_missing_cpe_degrades_to_direct_edge():
    graph = build_graph([_finding(cpe="")])
    edge = next(e for e in graph["edges"] if e["rel"] == "affected_by")
    assert edge["source"] == "svc:192.0.2.10:80"
    assert edge["confidence"] == 0.4
    assert edge.get("note") == "no cpe"
    assert not _ids(graph, "cpe")


# --- 证据状态 ---------------------------------------------------------------


def test_verified_and_inference_counts_are_separate():
    graph = build_graph([_finding("CVE-1"), _finding("CVE-2", verified=True)])
    assert graph["summary"]["verified"] == 1
    assert graph["summary"]["inference_only"] == 1


def test_disclaimer_is_always_present():
    assert "推断" in build_graph([])["disclaimer"]
    assert "推断" in build_graph([_finding()])["disclaimer"]


# --- 快照与稳定性 -----------------------------------------------------------


def test_snapshot_comes_from_provenance_when_not_given():
    assert build_graph([_finding(snapshot="2026-11-01")])["snapshot"] == "2026-11-01"


def test_explicit_snapshot_wins():
    graph = build_graph([_finding(snapshot="2026-11-01")], snapshot="2026-12-01")
    assert graph["snapshot"] == "2026-12-01"


def test_output_is_deterministic():
    findings = [_finding("CVE-B"), _finding("CVE-A")]
    assert build_graph(findings) == build_graph(list(reversed(findings)))


def test_nodes_are_ordered_from_asset_to_conclusion():
    kinds = [n["type"] for n in build_graph([_finding(fix="2.4.50")])["nodes"]]
    assert kinds == ["asset", "service", "cpe", "cve", "cwe", "fix"]
