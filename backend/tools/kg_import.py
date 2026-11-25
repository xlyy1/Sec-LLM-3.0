"""NVD CVE JSON feed → 本地 SQLite 快照。

在 ``backend`` 目录下运行::

    python -m tools.kg_import --years 2021-2026
    python -m tools.kg_import --years 2023 --cache-dir data/nvd_cache --offline

产物是 ``backend/data/kg.db``，只读使用、可随时重建（删掉重跑）。NVD 的
``.json.gz`` 按年发布，脚本一年一年处理，处理完即释放。

内存：单年解压后是几百 MB 量级的 JSON，``json.load`` 会整份放进内存。这是
脚本不是服务，可以接受；但不要一次把多年拼进一个列表。

只保留本模块用得到的字段。以下条目**不导入**（宁可漏报不可误报）：

- ``vulnerable: false`` 的 cpeMatch：它描述的是"不受影响"，不是漏洞。
- 无区间且 ``criteria`` 版本为 ``*`` 的 cpeMatch：会对该产品的所有版本命中，
  噪音远大于信息量（见 docs/kg.md）。
- ``negate: true`` 的节点：语义是"除此之外"，朴素实现无法正确表达，直接丢弃。
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.kg.cpe import parse_cpe
from core.kg.version import is_any, is_na

FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
DEFAULT_DB = Path(__file__).resolve().parents[1] / "data" / "kg.db"

RANGE_KEYS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)

SCHEMA = """
CREATE TABLE kg_cve (
  cve_id          TEXT PRIMARY KEY,
  cvss_v3_score   REAL,
  cvss_vector     TEXT,
  severity        TEXT,
  published       TEXT,
  last_modified   TEXT,
  description     TEXT,
  cwe_ids         TEXT,
  references_json TEXT
);

CREATE TABLE kg_cpe_match (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id             TEXT NOT NULL,
  cpe23              TEXT NOT NULL,
  vendor             TEXT,
  product            TEXT,
  version_start_incl TEXT,
  version_start_excl TEXT,
  version_end_incl   TEXT,
  version_end_excl   TEXT,
  vulnerable         INTEGER NOT NULL,
  node_operator      TEXT
);

CREATE INDEX idx_cpe_product ON kg_cpe_match(product, vendor);
CREATE INDEX idx_cpe_cve     ON kg_cpe_match(cve_id);

CREATE TABLE kg_meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);
"""

_INSERT_CVE = """
INSERT OR REPLACE INTO kg_cve
  (cve_id, cvss_v3_score, cvss_vector, severity, published, last_modified,
   description, cwe_ids, references_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_INSERT_MATCH = """
INSERT INTO kg_cpe_match
  (cve_id, cpe23, vendor, product, version_start_incl, version_start_excl,
   version_end_incl, version_end_excl, vulnerable, node_operator)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)


# ----------------------------------------------------------------- 抽取


def _severity(score: Optional[float]) -> str:
    if score is None:
        return ""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def _cvss(metrics: Dict[str, Any]) -> Tuple[Optional[float], str, str]:
    """优先 CVSS v3.1，其次 v3.0，最后退回 v2（v2 没有 baseSeverity 和 3.x 向量）。"""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next(
            (item for item in entries if str(item.get("type", "")).lower() == "primary"),
            entries[0],
        )
        data = entry.get("cvssData") or {}
        return data.get("baseScore"), data.get("baseSeverity") or "", data.get("vectorString") or ""

    entries = metrics.get("cvssMetricV2") or []
    if entries:
        entry = next(
            (item for item in entries if str(item.get("type", "")).lower() == "primary"),
            entries[0],
        )
        data = entry.get("cvssData") or {}
        return data.get("baseScore"), "", ""
    return None, "", ""


def extract_record(vulnerability: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], Dict[str, int]]:
    """一条 NVD 记录 → (CVE 行, cpeMatch 行的列表, 丢弃计数)。"""
    dropped = {"not_vulnerable": 0, "not_applicable": 0, "wildcard": 0, "negated": 0, "no_product": 0}
    cve = (vulnerability or {}).get("cve") or {}
    cve_id = str(cve.get("id") or "").strip()
    if not cve_id:
        return None, [], dropped

    score, severity, vector = _cvss(cve.get("metrics") or {})

    cwe_ids: List[str] = []
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = str(description.get("value") or "").strip()
            if value.startswith("CWE-") and value not in cwe_ids:
                cwe_ids.append(value)

    description = next(
        (str(item.get("value") or "") for item in cve.get("descriptions") or [] if item.get("lang") == "en"),
        "",
    )
    references = [
        str(item.get("url") or "")
        for item in cve.get("references") or []
        if item.get("url")
    ][:20]

    row = {
        "cve_id": cve_id,
        "cvss_v3_score": score,
        "cvss_vector": vector,
        "severity": severity or _severity(score),
        "published": cve.get("published") or "",
        "last_modified": cve.get("lastModified") or "",
        "description": description[:4000],
        "cwe_ids": json.dumps(cwe_ids, ensure_ascii=False),
        "references_json": json.dumps(references, ensure_ascii=False),
    }

    matches: List[Dict[str, Any]] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            if node.get("negate"):
                dropped["negated"] += 1
                continue
            operator = str(node.get("operator") or "OR").upper()
            for match in node.get("cpeMatch") or []:
                criteria = str(match.get("criteria") or "").strip()
                if not match.get("vulnerable"):
                    dropped["not_vulnerable"] += 1
                    continue
                parsed = parse_cpe(criteria) or {}
                product = str(parsed.get("product") or "")
                if not product or product == "*":
                    dropped["no_product"] += 1
                    continue
                has_range = any(match.get(key) for key in RANGE_KEYS)
                criteria_version = parsed.get("version")
                if not has_range:
                    # 分开计数：'-' 是"该字段不适用"（多为 OS/硬件），'*' 才是"任意版本"。
                    # 合成一个数会让人误判丢弃是否过量。
                    if is_na(criteria_version):
                        dropped["not_applicable"] += 1
                        continue
                    if is_any(criteria_version):
                        dropped["wildcard"] += 1
                        continue
                matches.append({
                    "cve_id": cve_id,
                    "cpe23": criteria,
                    "vendor": parsed.get("vendor") or "",
                    "product": product,
                    "version_start_incl": match.get("versionStartIncluding"),
                    "version_start_excl": match.get("versionStartExcluding"),
                    "version_end_incl": match.get("versionEndIncluding"),
                    "version_end_excl": match.get("versionEndExcluding"),
                    "vulnerable": 1,
                    "node_operator": operator,
                })
    return row, matches, dropped


def import_records(connection: sqlite3.Connection, records: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    """导入一批 NVD 记录，返回计数。同一 CVE 重复导入是幂等的。"""
    totals = {
        "records": 0, "cves": 0, "matches": 0,
        "not_vulnerable": 0, "not_applicable": 0, "wildcard": 0, "negated": 0, "no_product": 0,
    }
    for vulnerability in records:
        totals["records"] += 1
        row, matches, dropped = extract_record(vulnerability)
        if row is None:
            continue
        for key in dropped:
            totals[key] += dropped[key]

        # 显式构造元组：不依赖 dict 顺序，避免列错位时静默写坏数据。
        connection.execute(_INSERT_CVE, (
            row["cve_id"], row["cvss_v3_score"], row["cvss_vector"], row["severity"],
            row["published"], row["last_modified"], row["description"],
            row["cwe_ids"], row["references_json"],
        ))
        connection.execute("DELETE FROM kg_cpe_match WHERE cve_id = ?", (row["cve_id"],))
        if matches:
            connection.executemany(_INSERT_MATCH, [
                (
                    item["cve_id"], item["cpe23"], item["vendor"], item["product"],
                    item["version_start_incl"], item["version_start_excl"],
                    item["version_end_incl"], item["version_end_excl"],
                    item["vulnerable"], item["node_operator"],
                )
                for item in matches
            ])
        totals["cves"] += 1
        totals["matches"] += len(matches)
    connection.commit()
    return totals


# ----------------------------------------------------------------- 数据源


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def feed_path(year: int, cache_dir: Path) -> Path:
    return Path(cache_dir) / f"nvdcve-2.0-{year}.json.gz"


def fetch_feed(year: int, cache_dir: Path, *, offline: bool = False, timeout: int = 120,
               use_proxy: bool = True) -> Path:
    """取一年的 feed：缓存命中直接用，否则下载。``offline`` 时不发网络请求。

    ``use_proxy=False`` 绕过系统代理直连。Windows 上注册表里配了代理但代理没运行时，
    ``urllib`` 会跟着走代理并失败，看起来像"连不上 NVD"——实测就是这样。
    """
    target = feed_path(year, cache_dir)
    if target.is_file() and target.stat().st_size > 0:
        return target
    if offline:
        raise FileNotFoundError(
            f"{target} 不存在且指定了 --offline；先手工下载 {FEED_URL.format(year=year)} 放进 {cache_dir}"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        FEED_URL.format(year=year),
        headers={"User-Agent": "sec-llm-kg-import/1.0 (+offline-snapshot-builder)"},
    )
    opener = urllib.request.build_opener() if use_proxy else urllib.request.build_opener(
        urllib.request.ProxyHandler({})
    )
    temporary = target.with_name(target.name + ".part")
    try:
        with opener.open(request, timeout=timeout) as response, temporary.open("wb") as handle:
            shutil.copyfileobj(response, handle)
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return target


def load_feed(path: Path) -> List[Dict[str, Any]]:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)
    return list(payload.get("vulnerabilities") or [])


def parse_years(text: str) -> List[int]:
    """"2021-2023" / "2021,2023" / "2021" → 年份列表。"""
    years: List[int] = []
    for chunk in str(text).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            years.extend(range(int(start), int(end) + 1))
        else:
            years.append(int(chunk))
    return sorted(set(years))


# ----------------------------------------------------------------- 构建


def build_database(
    target: Path,
    years: List[int],
    *,
    cache_dir: Optional[Path] = None,
    offline: bool = False,
    timeout: int = 120,
    use_proxy: bool = True,
) -> Dict[str, Any]:
    """把若干年份的 feed 建成一个 SQLite 快照，原子替换目标文件。"""
    target = Path(target)
    cache_dir = Path(cache_dir) if cache_dir else target.parent / "nvd_cache"
    target.parent.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    temporary = target.with_name(target.name + ".tmp")
    temporary.unlink(missing_ok=True)

    feeds: List[Dict[str, Any]] = []
    totals = {"records": 0, "cves": 0, "matches": 0, "not_vulnerable": 0,
              "not_applicable": 0, "wildcard": 0, "negated": 0, "no_product": 0}

    connection = sqlite3.connect(temporary)
    try:
        create_schema(connection)
        for year in years:
            source = fetch_feed(year, cache_dir, offline=offline, timeout=timeout, use_proxy=use_proxy)
            records = load_feed(source)
            stats = import_records(connection, records)
            for key in totals:
                totals[key] += stats[key]
            feeds.append({"year": year, "sha256": _sha256(source), "records": len(records)})
            del records

        latest = connection.execute("SELECT MAX(last_modified) FROM kg_cve").fetchone()[0] or ""
        meta = {
            "imported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "snapshot_date": (latest or "")[:10],
            "years": ",".join(str(year) for year in years),
            "feeds": json.dumps(feeds, ensure_ascii=False),
            "cves": str(totals["cves"]),
            "cpe_matches": str(totals["matches"]),
        }
        connection.executemany(
            "INSERT OR REPLACE INTO kg_meta(key, value) VALUES (?, ?)",
            list(meta.items()),
        )
        connection.commit()
    except BaseException:
        connection.close()
        temporary.unlink(missing_ok=True)
        raise
    else:
        connection.close()

    os.replace(temporary, target)
    return {**totals, "path": str(target), "feeds": feeds}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Build the offline NVD knowledge base used by cve_match.")
    parser.add_argument("--years", default="2021-2026", help="例如 2021-2026 或 2021,2023")
    parser.add_argument("--output", default=str(DEFAULT_DB), help="输出的 SQLite 路径")
    parser.add_argument("--cache-dir", default="", help="feed 缓存目录（默认与输出同级的 nvd_cache）")
    parser.add_argument("--offline", action="store_true", help="只读缓存，不下载")
    parser.add_argument("--no-proxy", action="store_true",
                        help="绕过系统代理直连（代理配了但没运行时需要）")
    parser.add_argument("--timeout", type=int, default=120, help="单年下载超时（秒）")
    arguments = parser.parse_args(argv)

    years = parse_years(arguments.years)
    if not years:
        parser.error("--years 解析为空")

    result = build_database(
        Path(arguments.output),
        years,
        cache_dir=Path(arguments.cache_dir) if arguments.cache_dir else None,
        offline=arguments.offline,
        timeout=arguments.timeout,
        use_proxy=not arguments.no_proxy,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
