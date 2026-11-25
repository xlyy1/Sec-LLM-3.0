"""nmap XML 解析与 CPE 归一。

fixture 是手工构造的（见文件头注释），不是真实扫描采集。它固定的是**结构
契约**：哪些字段取哪个属性、closed 端口是否过滤、没有 CPE 时怎么标来源。
"""
from pathlib import Path

from core.kg.cpe import build_cpe23, parse_cpe, service_to_cpe, to_cpe23
from core.kg.nmap_parse import MAX_XML_BYTES, parse_nmap_xml

FIXTURE = Path(__file__).parent / "fixtures" / "nmap" / "apache-2.4.49.xml"
#: 真实采集：docker 里的 nmap 7.95 扫 httpd:2.4.49 容器，目标 IP 已替换为文档地址。
REAL_FIXTURE = Path(__file__).parent / "fixtures" / "nmap" / "apache-2.4.49.real.xml"


def _parsed():
    return parse_nmap_xml(FIXTURE.read_text(encoding="utf-8"))


def _by_port(services, port):
    return next(item for item in services if item["port"] == port)


# --- 解析 -------------------------------------------------------------------


def test_fixture_parses_without_error():
    result = _parsed()
    assert result["error"] is None
    assert len(result["hosts"]) == 1
    assert result["hosts"][0]["address"] == "192.0.2.10"
    assert result["hosts"][0]["hostnames"] == ["demo.internal"]


def test_closed_ports_are_excluded():
    services = _parsed()["services"]
    ports = [item["port"] for item in services]
    assert 3306 not in ports, "closed 端口不应进入服务列表"
    assert ports == [22, 25, 80, 443]


def test_nmap_cpe_is_normalized_to_23():
    service = _by_port(_parsed()["services"], 80)
    assert service["product"] == "Apache httpd"
    assert service["version"] == "2.4.49"
    assert service["cpe23"] == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert service["cpe_source"] == "nmap"


def test_service_without_cpe_falls_back_when_known():
    service = _by_port(_parsed()["services"], 443)
    assert service["cpe_source"] == "fallback"
    assert service["cpe23"].startswith("cpe:2.3:a:")


def test_unknown_product_stays_none_instead_of_guessing():
    service = _by_port(_parsed()["services"], 25)
    assert service["product"] == "Postfix smtpd"
    assert service["cpe23"] is None
    assert service["cpe_source"] == "none"


def test_real_nmap_capture_parses():
    """真实 nmap 输出带 <!DOCTYPE nmaprun> 与 xml-stylesheet，必须能解析。

    这条用例来自真实扫描：早期实现把 DOCTYPE 当成注入拒掉，导致生产环境永远
    解析出 0 个服务，而手写 fixture 里没有 DOCTYPE，测试全绿也没发现。
    """
    result = parse_nmap_xml(REAL_FIXTURE.read_text(encoding="utf-8"))
    assert result["error"] is None
    service = result["services"][0]
    assert service["product"] == "Apache httpd"
    assert service["version"] == "2.4.49"
    assert service["cpe23"] == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert service["cpe_source"] == "nmap"


def test_empty_input_reports_reason():
    result = parse_nmap_xml("")
    assert result["services"] == []
    assert result["error"] == "empty xml"


def test_malformed_xml_reports_reason_instead_of_raising():
    result = parse_nmap_xml("<nmaprun><host>")
    assert result["services"] == []
    assert result["error"].startswith("invalid xml")


def test_non_nmap_root_is_rejected():
    result = parse_nmap_xml("<foo/>")
    assert result["error"].startswith("unexpected root element")


def test_nmap_doctype_is_accepted():
    """真实 nmap 会输出 <!DOCTYPE nmaprun>；拒掉它等于让整个功能失效。"""
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
        '<nmaprun scanner="nmap"><host><address addr="192.0.2.10" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="nginx" version="1.27.5">'
        '<cpe>cpe:/a:igor_sysoev:nginx:1.27.5</cpe></service></port></ports></host></nmaprun>'
    )
    result = parse_nmap_xml(xml)
    assert result["error"] is None
    assert [item["port"] for item in result["services"]] == [80]


def test_entity_declarations_are_rejected():
    payload = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE nmaprun [<!ENTITY a "aaaa">]>'
        '<nmaprun><host><address addr="&a;"/></host></nmaprun>'
    )
    result = parse_nmap_xml(payload)
    assert "entity" in result["error"].lower()


def test_oversized_input_is_rejected():
    result = parse_nmap_xml(" " * (MAX_XML_BYTES + 1))
    assert "exceeds" in result["error"]


# --- CPE 解析与归一 ---------------------------------------------------------


def test_cpe_22_is_upgraded_to_23():
    assert to_cpe23("cpe:/a:apache:http_server:2.4.49") == (
        "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    )
    assert to_cpe23("cpe:/o:linux:linux_kernel:5.15") == (
        "cpe:2.3:o:linux:linux_kernel:5.15:*:*:*:*:*:*:*"
    )


def test_cpe_23_passes_through():
    value = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert to_cpe23(value) == value


def test_invalid_cpe_is_not_invented():
    assert to_cpe23("Apache httpd 2.4.49") is None
    assert to_cpe23("") is None
    assert parse_cpe("cpe:2.3:a:apache") is None


def test_parse_cpe_exposes_components():
    parsed = parse_cpe("cpe:/a:openbsd:openssh:8.9p1")
    assert parsed["format"] == "2.2"
    assert (parsed["part"], parsed["vendor"], parsed["product"], parsed["version"]) == (
        "a", "openbsd", "openssh", "8.9p1",
    )


def test_build_cpe23_defaults_to_any():
    assert build_cpe23("a", "apache", "http_server") == (
        "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
    )


def test_fallback_keeps_unknown_version_visible_as_star():
    """版本未知时保留 '*'，上层据此跳过匹配，而不是匹配一大堆 CVE。"""
    cpe, source = service_to_cpe("http", "nginx", "")
    assert source == "fallback"
    assert cpe == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"


def test_fallback_is_case_and_space_insensitive():
    assert service_to_cpe(None, "  Apache   HTTPD ", "2.4.49") == (
        "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        "fallback",
    )


def test_fallback_unknown_product_returns_none():
    assert service_to_cpe("smtp", "Postfix smtpd", "3.7") == (None, "none")
