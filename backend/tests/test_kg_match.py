"""CVE 匹配链路：导入 → 产品窄化 → 版本区间判定 → 工具产出。

fixture 是一份手工的最小 NVD 快照（``tests/fixtures/kg/mini_nvd.json``），
覆盖了真实数据里会踩到的几类条目：区间、精确版本、AND 组合节点、
``vulnerable: false``、无区间通配、只有 CVSS v2 的记录。
"""
import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

from core.kg.store import KnowledgeBase
from tools.kg_import import create_schema, import_records, parse_years

FIXTURE = Path(__file__).parent / "fixtures" / "kg" / "mini_nvd.json"


def _service(version="2.4.49", product="Apache httpd", cpe=True, host="192.0.2.10"):
    return {
        "host": host,
        "port": 80,
        "service": "http",
        "product": product,
        "version": version,
        "cpe23": f"cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*" if cpe else None,
        "cpe_source": "nmap" if cpe else "none",
    }


@pytest.fixture(scope="module")
def built():
    """内存库：不依赖可写的临时目录，测试在任何沙箱下都能跑。"""
    connection = sqlite3.connect(":memory:")
    create_schema(connection)
    stats = import_records(connection, json.loads(FIXTURE.read_text(encoding="utf-8")))
    return KnowledgeBase(connection=connection), stats


def _ids(result):
    return {item["cve_id"] for item in result["matched"]}


# --- 导入 -------------------------------------------------------------------


def test_import_counts_and_drops(built):
    _, stats = built
    assert stats["cves"] == 8
    assert stats["matches"] == 6, "AND 节点的 OS 条目与通配条目都不应入库"
    assert stats["not_applicable"] == 1, "version='-' 的 OS/硬件条目"
    assert stats["wildcard"] == 1, "无区间且版本为 '*' 的条目"
    assert stats["not_vulnerable"] == 1


def test_parse_years_accepts_ranges_and_lists():
    assert parse_years("2021-2023") == [2021, 2022, 2023]
    assert parse_years("2021,2023") == [2021, 2023]
    assert parse_years(" 2022 ") == [2022]


# --- 匹配 -------------------------------------------------------------------


def test_version_inside_range_matches(built):
    knowledge, _ = built
    result = knowledge.match_service(_service("2.4.49"))
    assert _ids(result) == {
        "CVE-2021-41773", "CVE-2021-42013", "CVE-2022-22720",
        "CVE-2020-1111", "CVE-2017-5555",
    }
    assert result["total"] == 5


def test_upper_bound_is_exclusive(built):
    knowledge, _ = built
    result = knowledge.match_service(_service("2.4.50"))
    assert "CVE-2021-41773" not in _ids(result), "2.4.50 已在 2.4.49 的修复版本上"
    assert "CVE-2021-42013" in _ids(result), "42013 的上界是 2.4.51"


def test_exact_version_criteria_only_matches_that_version(built):
    knowledge, _ = built
    at_248 = _ids(knowledge.match_service(_service("2.4.48")))
    assert "CVE-2018-4444" in at_248
    assert "CVE-2018-4444" not in _ids(knowledge.match_service(_service("2.4.49")))


def test_wildcard_only_entry_never_matches(built):
    knowledge, _ = built
    assert "CVE-2018-3333" not in _ids(knowledge.match_service(_service("2.4.49")))


def test_not_vulnerable_entry_never_matches(built):
    knowledge, _ = built
    for version in ("2.4.0", "2.4.20", "2.4.49"):
        assert "CVE-2019-2222" not in _ids(knowledge.match_service(_service(version)))


def test_top_n_truncates_but_keeps_total(built):
    knowledge, _ = built
    result = knowledge.match_service(_service("2.4.49"), top_n=2)
    assert len(result["matched"]) == 2
    assert result["shown"] == 2
    assert result["total"] == 5, "被截断的事实必须保留在 total 里"
    assert result["matched"][0]["cvss_score"] == 9.8


def test_and_node_is_downgraded(built):
    knowledge, _ = built
    hits = {item["cve_id"]: item for item in knowledge.match_service(_service("2.4.49"))["matched"]}
    assert hits["CVE-2020-1111"]["confidence"] <= 0.4
    assert hits["CVE-2021-41773"]["confidence"] > hits["CVE-2020-1111"]["confidence"]


def test_cvss_v2_only_record_still_has_a_score(built):
    knowledge, _ = built
    hits = {item["cve_id"]: item for item in knowledge.match_service(_service("2.4.49"))["matched"]}
    assert hits["CVE-2017-5555"]["cvss_score"] == 4.3
    assert hits["CVE-2017-5555"]["severity"] == "Medium"


def test_severity_is_normalized_to_title_case(built):
    """NVD 给的是 CRITICAL；项目其余部分按首字母大写比较，不能两套写法混用。"""
    knowledge, _ = built
    hits = {item["cve_id"]: item for item in knowledge.match_service(_service("2.4.49"))["matched"]}
    assert hits["CVE-2021-42013"]["severity"] == "Critical"
    assert hits["CVE-2021-41773"]["severity"] == "High"


def test_fix_version_is_the_exclusive_upper_bound(built):
    knowledge, _ = built
    hits = {item["cve_id"]: item for item in knowledge.match_service(_service("2.4.49"))["matched"]}
    assert hits["CVE-2021-41773"]["fix_version"] == "2.4.50"


def test_exact_version_entry_has_no_fix_version(built):
    """NVD 常用精确版本而不是区间；这时推导不出修复版本，留空，不编一个。"""
    knowledge, _ = built
    hits = {item["cve_id"]: item for item in knowledge.match_service(_service("2.4.48"))["matched"]}
    assert hits["CVE-2018-4444"]["fix_version"] == ""


# --- 拒绝猜测 ---------------------------------------------------------------


def test_unknown_version_is_refused(built):
    knowledge, _ = built
    result = knowledge.match_service({**_service("2.4.49"), "version": "*", "cpe23": None})
    assert result["matched"] == []
    assert "unknown" in result["reason"]


def test_service_without_cpe_is_refused(built):
    knowledge, _ = built
    result = knowledge.match_service(_service("1.0", product="Mystery Daemon", cpe=False))
    assert result["matched"] == []
    assert "no cpe" in result["reason"]


def test_distro_suffix_in_banner_uses_clean_cpe_version(built):
    """真实 nmap 会给出 "8.9p1 Ubuntu 3ubuntu0.1"；CPE 里才是干净的版本。"""
    knowledge, _ = built
    service = _service("2.4.49 Ubuntu 3ubuntu0.1")
    service["cpe23"] = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    result = knowledge.match_service(service)
    assert "CVE-2021-41773" in _ids(result), "必须按 CPE 的 2.4.49 匹配，而不是带后缀的整串"


def test_version_that_is_not_a_single_token_is_refused(built):
    """像 "3.5 - 3.10" 这种范围 banner，且 CPE 也没给出版本时不做猜测。"""
    knowledge, _ = built
    service = _service("3.5 - 3.10")
    service["cpe23"] = "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"
    service["product"] = "Python http.server"
    result = knowledge.match_service(service)
    assert result["matched"] == []
    assert "single version token" in result["reason"]


def test_missing_database_is_reported_not_raised():
    knowledge = KnowledgeBase(Path("__absent_kg__.db"))
    result = knowledge.match_service(_service("2.4.49"))
    assert result["matched"] == []
    assert "not found" in result["reason"]


def test_equal_score_prefers_exact_version_match():
    """同分时：NVD 写死版本的条目应排在"宽区间覆盖"的条目前面。

    真实场景：Apache 2.4.49 命中 88 条候选，CVE-2021-41773 的 criteria 是精确的
    2.4.49，而它前面挤着一堆"≤2.4.69、无下界"的新 CVE。
    """
    def record(cve_id, criteria, score, published, start=None, end_excl=None):
        match = {"vulnerable": True, "criteria": criteria, "matchCriteriaId": cve_id}
        if start:
            match["versionStartIncluding"] = start
        if end_excl:
            match["versionEndExcluding"] = end_excl
        return {"cve": {
            "id": cve_id, "published": published,
            "descriptions": [{"lang": "en", "value": cve_id}],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                "baseScore": score, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"}}]},
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [match]}]}],
        }}

    exact = record("CVE-EXACT", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                   7.5, "2020-01-01")
    broad = record("CVE-BROAD", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                   7.5, "2026-06-01", start="2.4.0", end_excl="2.4.50")
    severe = record("CVE-SEVERE", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                    9.8, "2019-01-01", start="2.4.0", end_excl="2.4.50")

    connection = sqlite3.connect(":memory:")
    create_schema(connection)
    import_records(connection, [broad, exact, severe])

    result = KnowledgeBase(connection=connection).match_service(_service("2.4.49"))
    assert [hit["cve_id"] for hit in result["matched"]] == ["CVE-SEVERE", "CVE-EXACT", "CVE-BROAD"]
    assert result["matched"][1]["specificity"] == 1
    assert result["matched"][2]["specificity"] == 0


def test_product_with_quote_is_parameterized(built):
    knowledge, _ = built
    cpe = "cpe:2.3:a:vendor:o'brien:1.0:*:*:*:*:*:*:*"
    result = knowledge.match_service({"version": "1.0", "cpe23": cpe, "cpe_source": "nmap"})
    assert result["matched"] == []


# --- 工具层 -----------------------------------------------------------------


def test_tool_returns_inference_findings(monkeypatch, built):
    import tools.cve_match as tool

    knowledge, _ = built
    monkeypatch.setattr(tool, "KnowledgeBase", lambda: knowledge)

    result = asyncio.run(tool.cve_match(services=[_service("2.4.49")]))
    assert result["status"] == "success"
    assert result["findings"]
    finding = result["findings"][0]
    assert finding["cvss_source"] == "nvd"
    assert finding["inference"] is True
    assert finding["verification_reason"].startswith("版本区间推断")
    assert finding["provenance"][-1]["source"] == "nvd"
    assert finding["affected_asset"]["cpe_source"] == "nmap", "CPE 来源要带到资产信息里"


def test_annotate_keeps_nvd_score_and_never_verifies(monkeypatch, built):
    """CVE 推断不得被 enhance_finding 覆盖分数，也不得变成 verified。"""
    from agents.reporting import annotate_finding
    import tools.cve_match as tool

    knowledge, _ = built
    monkeypatch.setattr(tool, "KnowledgeBase", lambda: knowledge)
    result = asyncio.run(tool.cve_match(services=[_service("2.4.49")]))
    finding = next(item for item in result["findings"] if item["cve_id"] == "CVE-2021-41773")

    annotated = annotate_finding(dict(finding), "cve_match", {})
    assert annotated["verification_status"] == "unverified"
    assert annotated["cvss_score"] == 7.5, "NVD 的 7.5 不能被严重级反推值覆盖"
    assert annotated["verification_reason"].startswith("版本区间推断")
    assert annotated["owasp_category"] == "Vulnerable Component"
