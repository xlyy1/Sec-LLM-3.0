"""nmap XML 解析：把 ``-sV`` 的服务指纹变成可匹配的结构。

只接受 XML（``nmap -sV -oX -``）。**不解析文本输出**：文本里没有 ``<cpe>``
标签，从 banner 反推版本等于把"猜版本"重新引进来了，那是本模块明确要避免的事。

解析失败不抛异常，``error`` 字段说明原因、``services`` 为空。侦察阶段不能因为
一段 XML 没解析出来就让整个任务失败。
"""
from __future__ import annotations

from defusedxml.ElementTree import ParseError, fromstring
from typing import Any, Dict

from core.kg.cpe import service_to_cpe, to_cpe23

#: 体积上限。nmap 的 XML 一般几十 KB，超过这个量级说明输入不对。
MAX_XML_BYTES = 8 * 1024 * 1024
#: nmap 自己会输出 ``<!DOCTYPE nmaprun>``，这是合法的，不能拒。
#: 要防的是实体声明：expat 会展开内部实体，``<!ENTITY`` 才是实体膨胀的入口。
_ENTITY = "<!ENTITY"


def _attribute(node, name: str, default: str = "") -> str:
    return (node.get(name) or default).strip() if node is not None else default


def _text(node) -> str:
    return (node.text or "").strip() if node is not None else ""


def _port_id(value: str) -> Any:
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def parse_nmap_xml(xml_text: str) -> Dict[str, Any]:
    """解析 nmap XML。

    返回::

        {
          "hosts":    [{"address", "addr_type", "hostnames"}],
          "services": [{"host", "port", "protocol", "service", "product",
                        "version", "cpe23", "cpe_source", "extra_info"}],
          "error":    None | "原因"
        }

    ``cpe_source`` 取 ``nmap`` / ``fallback`` / ``none``。它会一路带到报告里，
    用于说明这条关联的可信度。
    """
    result: Dict[str, Any] = {"hosts": [], "services": [], "error": None}

    # 先判体积：对超大输入做 strip() 会先复制一份，没必要的开销。
    if len(xml_text or "") > MAX_XML_BYTES:
        result["error"] = f"xml exceeds {MAX_XML_BYTES} bytes"
        return result
    if not xml_text or not xml_text.strip():
        result["error"] = "empty xml"
        return result
    # 只拦实体声明，不拦 DOCTYPE：真实 nmap 输出就带 <!DOCTYPE nmaprun>。
    # 首次实现时把两者一起拒了，导致真实扫描永远解析出 0 个服务。
    if _ENTITY in xml_text.upper():
        result["error"] = "entity declarations are not accepted"
        return result

    try:
        root = fromstring(xml_text)
    except ParseError as error:
        result["error"] = f"invalid xml: {error}"
        return result
    if root.tag != "nmaprun":
        result["error"] = f"unexpected root element: {root.tag}"
        return result

    for host in root.findall("host"):
        address_node = host.find("address")
        address = _attribute(address_node, "addr")
        hostnames = [
            node.get("name", "").strip()
            for node in host.findall("./hostnames/hostname")
            if (node.get("name") or "").strip()
        ]
        result["hosts"].append({
            "address": address,
            "addr_type": _attribute(address_node, "addrtype"),
            "hostnames": hostnames,
        })

        for port in host.findall("./ports/port"):
            if _attribute(port.find("state"), "state") != "open":
                continue

            service_node = port.find("service")
            name = _attribute(service_node, "name")
            product = _attribute(service_node, "product")
            version = _attribute(service_node, "version")

            declared = [node.text.strip() for node in service_node.findall("cpe")] if service_node is not None else []
            declared = [item for item in declared if item]
            cpe23 = to_cpe23(declared[0]) if declared else None
            source = "nmap" if cpe23 else "none"

            if not cpe23:
                cpe23, source = service_to_cpe(name, product, version)

            result["services"].append({
                "host": address,
                "port": _port_id(_attribute(port, "portid")),
                "protocol": _attribute(port, "protocol"),
                "service": name,
                "product": product,
                "version": version,
                "cpe23": cpe23,
                "cpe_source": source,
                "extra_info": _attribute(service_node, "extrainfo"),
            })

    return result
