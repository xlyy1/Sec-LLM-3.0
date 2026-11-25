# 资产-CVE 知识图谱

扫描器目前只能回答"这台机器开着 80 端口、跑着 Apache httpd 2.4.49"，回答不了"这意味着什么"。
本模块在侦察阶段之后增加一段确定性的关联：**服务指纹 → CPE → CVE → CWE / 修复版本**，并把结果表示成一张可查询、可展示的子图。

本文档描述的是设计，不是已完成的实现。落地情况以各阶段验收命令的实际输出为准。

| 阶段 | 状态 | 证据 |
|---|---|---|
| P0 解析与版本比较 | 已完成 | `pytest tests/test_kg_version.py tests/test_kg_nmap.py` → 33 passed |
| P1 导入与匹配 | 已完成（真实 feed 2021–2026 + 落盘） | `data/kg.db` 390.7 MB / 264,147 CVE / 900,331 cpeMatch / 44,697 个产品，integrity_check=ok；`--offline` 重建 7.7s（单年）；`pytest tests/test_kg_match.py` → 19 passed |
| P2 接口与前端 | 已完成 | `GET /api/agent/{id}/graph` + `AssetCveGraph`；`pytest tests/test_kg_graph.py` → 15 passed；`next build` 通过 |
| 端到端（真机） | 已完成 | Docker 内真实 nmap 7.95 扫 `httpd:2.4.49` 靶容器：88 个候选 → 5 条 finding → 图；详见"真机验证" |
| P3 攻击链 | 未开始（可选） | — |

## 范围与非目标

**做**

- 从 `nmap -sV` 的 XML 输出解析出服务指纹，归一为 CPE 2.3。
- 用离线的 NVD 快照做版本区间匹配，产出"疑似受影响组件"。
- 以节点/边形式返回关联结果，供报告与前端展示。
- 每一条边带来源与推导依据，可回溯到 NVD 的 `cpeMatch` 条目。

**不做（且不要以后顺手做）**

| 不做 | 原因 |
|---|---|
| 引入 Neo4j 或其他图数据库 | 查询是固定 3–4 跳（service → cpe → cve），不是任意深度遍历。多一个服务、一套备份和一份运维成本，换不到能力 |
| 把 `/api/chat` 的检索改成 GraphRAG | 现有混合检索有 dev/val/test 隔离评测和 RSI 闭环（见 [RAG 评测](rag-optimization.md)），换掉等于推倒已验证的基线 |
| 让 LLM 生成 CVE 与版本的对应关系 | CPE 归一和版本比较是可枚举、可单测、可复现的确定性逻辑。LLM 只在"解析不了的服务名"上作为最后一级提示，且结果必须标注 |
| 把推断结果写成 `verified` | 见"证据纪律"一节 |
| 跨会话累积资产图 | 需要数据规模和真实需求，当前没有。单会话子图已经够用 |

## 图模型

六类节点、五类边。节点全部是只读参考数据或会话内计算产物，只有 CVE/CPE 侧落盘。

```
asset:host:port  --runs----------->  service:host:port
service          --normalizes_to-->  cpe:2.3:...
cpe              --affected_by---->  cve:CVE-YYYY-NNNN
cve              --has_weakness--->  cwe:CWE-NNN
cve              --fixed_in------->  version:2.4.50
```

| 节点 | 来源 | 是否落盘 |
|---|---|---|
| `asset` | 任务目标 + nmap 主机 | 否，会话内计算 |
| `service` | nmap XML `<service>` | 否，会话内计算 |
| `cpe` | nmap `<cpe>` 或 fallback 映射表 | 否 |
| `cve` | NVD 快照 | 是（SQLite） |
| `cwe` | NVD `weaknesses` | 是（随 CVE 行） |
| `version` | NVD 区间边界与 `fixed_in` 推导 | 否 |

**为什么不建图数据库**，一句话版本：图数据库的价值在"路径不确定的遍历"，这里的路径是写死的三跳。用 SQLite 的 `cpeMatch` 表做窄化、用 Python 做版本判断，已经能表达完整语义，而且删掉文件就回到干净状态。

## 数据来源

### 离线快照

NVD 的 CVE JSON feed（`nvdcve-2.0-*.json.gz`）按年发布。只导入**近 5 年**且**带 `cpeMatch` 条目**的记录：

- 单年压缩包约数十 MB 量级，五年解压后约 1–2 GB；导入后 SQLite 预计几百 MB 量级（以实际下载为准，不在这里写死）。
- 全量导入没有必要：2015 年之前的 CVE 对应的组件版本几乎不会出现在当前扫描目标上，而且会显著拖慢匹配。
- 快照日期、源文件 SHA-256、导入条数写入 `kg_meta`，用于报告里声明"本结论基于 YYYY-MM-DD 的快照"。

导入脚本 `backend/tools/kg_import.py`，产物 `backend/data/kg.db`。该文件是可重建的派生产物，**不进版本库**，加入 `.gitignore`。

### 只读与可重建

`kg.db` 只读打开（`file:...?mode=ro`）。代码不写它；重建 = 删文件 + 重跑导入。这样它不会变成"某个环境上有一份谁也说不清来源的数据"。

## 版本比较（P0，唯一的真难点）

CPE 的版本区间不是字符串比较。`"2.4.49" < "2.4.5"` 在字符串语义下成立，但版本语义下 `2.4.49 > 2.4.5`。这一步做错，后面所有结论都是错的且不会报错。

### 规则

实现于 `backend/core/kg/version.py`，规则如下，每条都有对应单测固定。

1. `*` 或空 → `ANY`，不设限。
2. `-`（CPE 的 NOT_APPLICABLE）→ `UNKNOWN`，不参与匹配。
3. 归一化：去掉前导 `v`，转小写。
4. 切分：连续数字为一段（转 `int`），连续字母为一段（保留 `str`），`.-_+` 及其他非字母数字作分隔。
5. 逐段比较：
   - 数字对数字：比数值。
   - 字母对字母：按字节序。
   - 类型不同：**数字段视为小于字母段**。这条是约定，不是真理，但必须唯一且被测试固化。
6. 长度不一致：数字段补 `0`，字母段补空串。
7. 不支持：epoch、`~` 预发布语义、Debian/RPM 的特殊排序。遇到这些形态记录 `UNKNOWN`，不猜。

### 区间判定

给定目标版本 `v` 与一条 `cpeMatch` 的四个边界（`versionStartIncluding` / `versionStartExcluding` / `versionEndIncluding` / `versionEndExcluding`），全部满足才算命中。任一比较返回 `UNKNOWN` → **不命中**。

这是有意的取舍：**宁可漏报，不可误报**。漏报在报告里体现为"该服务未匹配到已知 CVE"，可见；误报会直接污染结论，且用户看不出来。

### 已知不覆盖

- `cpeMatch` 无区间、`criteria` 版本为 `*`：不建任何 CVE 关联，只标注"版本未知，无法匹配"。
- NVD `configurations` 中存在 `AND` 组合节点（需要同时满足多个条件）。朴素实现会把 AND 节点里的每条 `cpeMatch` 当成独立条件，导致过报。处理方式：只采信"单一 `cpeMatch`"或"`OR` 节点"的命中；来自 `AND` 节点的命中降为低置信度并在报告里单独标注。
- `vulnerable: false` 的 `cpeMatch` 一律丢弃。它表示"此配置不受影响"，用于反向说明，不是漏洞。

## 管线接入

只有四处改动，全部是加法。

### 1. 侦察阶段取 XML

[`backend/agents/specialists/recon.py:108`](../backend/agents/specialists/recon.py) 把

```python
command=f"nmap -sV -F {scan_target}"
```

改为

```python
command=f"nmap -sV -F -oX - {scan_target}"
```

`-oX -` 让 nmap 把 XML 写到 stdout。多数服务在 `-sV` 下会带 `<cpe>` 标签，等于免费拿到 CPE；拿不到时走 fallback 映射表。

注意 [`backend/tools/shell.py`](../backend/tools/shell.py) 的命令黑名单拒绝 `;&|><\`$\n\r`，`-oX -` 不含这些字符，可以通过；**不要把输出重定向到文件**，容器是 `--rm` 的只读根文件系统，扫完读不到。

同时把原始 XML 发布到 blackboard（`nmap_xml`），文本形式的 `nmap_output` 保留，因为 [`backend/agents/strategy.py:42`](../backend/agents/strategy.py) 用 `nmap_output` 判断 `host` 资产类型，改动它会影响现有报告口径。

### 2. 解析与归一

`backend/core/kg/nmap_parse.py`：

```python
def parse_nmap_xml(xml_text: str) -> dict:
    """返回 {"hosts": [...], "services": [...], "error": None | "原因"}。

    services 每项：{host, port, protocol, service, product, version, cpe23, cpe_source}
    """
```

- 只取 `state="open"`。
- `<cpe>` 可能是 CPE 2.2 URI（`cpe:/a:apache:http_server:2.4.49`）或 2.3 格式串，统一转 2.3。
- `cpe_source` 记录 `nmap` / `fallback` / `none`。这个字段要一路带到报告里，用于说明置信度。
- 解析失败（非 XML、被截断）返回空列表并记录原因，不能让整个任务挂掉。

`backend/core/kg/cpe.py` 提供 fallback：`service` + `product` → CPE 前缀，数据在 `backend/core/kg/data/cpe_fallback.json`，人工维护、可评审、条目少而精（先覆盖 nginx / apache httpd / openssh / mysql / redis / postgresql / tomcat / php-fpm）。**不做模糊匹配**，匹配不上就是 `none`。

### 3. 匹配与工具注册

`backend/core/kg/store.py`：

```python
def match_cves(service: dict, *, top_n: int = 5) -> list[dict]:
    """product 窄化 → 版本区间判定 → 按 CVSS 降序取前 N 条，附带 provenance。"""
```

SQLite 只负责窄化（`WHERE product = ?`），版本判断在 Python 里做——SQLite 没有语义版本比较，强行在 SQL 里排序就是上面那个坑的另一种写法。

`backend/tools/cve_match.py` 注册一个新工具：

```python
@register_tool(name="cve_match", category="recon", requires_provider=False)
async def cve_match(host: str, services: list) -> dict: ...
```

产出的 finding 形态：

```json
{
  "title": "疑似受影响组件：Apache httpd 2.4.49 匹配 CVE-2021-41773",
  "severity": "High",
  "source_tool": "cve_match",
  "verification_status": "unverified",
  "verification_reason": "版本区间推断（NVD cpeMatch），未在目标上复现",
  "cvss_score": 7.5,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "cvss_source": "nvd",
  "cwe_id": "CWE-22",
  "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
  "affected_asset": {"host": "10.0.0.5", "port": 80, "service": "http", "cpe_source": "nmap"},
  "fix_version": "2.4.50",
  "provenance": [
    {"edge": "service->cpe", "source": "nmap", "confidence": 0.95},
    {"edge": "cpe->cve", "source": "nvd", "confidence": 0.9, "snapshot": "2026-11-01"}
  ]
}
```

### 4. 报告与评分口径

- [`backend/agents/strategy.py:111`](../backend/agents/strategy.py)：`host` 类型不再只写 `"未做 CVE 匹配"`，改为产出一条 `{"check": "cve_match", ...}` 检查项。`coverage_gaps` 里那条删除——**这是可量化的成果，报告里能直接看到缺口少了一项**。
- [`backend/agents/reporting.py:143`](../backend/agents/reporting.py) `enhance_finding()` 目前**无条件覆写** `cvss_score`，用 severity 反推一个值。CVE 发现必须保留 NVD 的真实评分，否则图上所有分数都是编的，而且不会报错。改动：`if finding.get("cvss_source") == "nvd": 保留 nvd 的 cvss/cwe，只补 owasp_category`。
- [`backend/core/security_score.py`](../backend/core/security_score.py) 只统计 `verification_status == "verified"` 的发现，所以 CVE 推断天然不进入评分。**这条要写测试固定住**，防止以后有人"顺手"把推断算进扣分。

## 证据纪律

这是本模块最该被讲清楚的部分。

现有规则：`verified` 必须有请求、响应、payload、内容哈希和可重放 PoC（见 [`backend/core/evidence.py`](../backend/core/evidence.py)）。而 CVE 匹配产出的是**推断**：

```
(host, runs, Apache 2.4.49) + (CVE-2021-41773, affects, cpe:...:2.4.49)
  ⇒  (host, suspected_affected_by, CVE-2021-41773)        ← 没有任何请求证据
```

约束：

1. 每条边必须有 `source`（`nmap` / `nvd` / `rule` / `llm` / `manual`）与 `confidence`。
2. `cve_match` 产出的发现 `verification_status` 恒为 `unverified`，`verification_reason` 必须写明是区间推断。
3. 不进入安全评分。
4. 报告里单独成节"疑似受影响组件（未复现）"，不与已验证漏洞混排。
5. 未来若接入 PoC 复现（例如 nuclei 模板），复现成功才可升级为 `verified`，并把该证据写进 `provenance`。**升级路径要留出来，但默认不打通**。

一句话：**系统可以做推断，但推断不能伪装成证据。**

## 接口

### 图谱数据

```
GET /api/agent/{id}/graph
```

认证与既有 Agent 端点一致（JWT 或 Skill Key）。返回：

```json
{
  "session_id": "abc123",
  "snapshot": {"nvd_date": "2026-11-01", "imported": 128431},
  "nodes": [
    {"id": "asset:10.0.0.5", "type": "asset", "label": "10.0.0.5"},
    {"id": "svc:10.0.0.5:80", "type": "service", "label": "http / Apache httpd 2.4.49"},
    {"id": "cpe:2.3:a:apache:http_server:2.4.49", "type": "cpe", "label": "http_server 2.4.49"},
    {"id": "cve:CVE-2021-41773", "type": "cve", "label": "CVE-2021-41773", "attrs": {"cvss": 7.5, "severity": "High"}},
    {"id": "cwe:CWE-22", "type": "cwe", "label": "CWE-22"}
  ],
  "edges": [
    {"source": "asset:10.0.0.5", "target": "svc:10.0.0.5:80", "rel": "runs", "source_of_truth": "nmap", "confidence": 0.95},
    {"source": "svc:10.0.0.5:80", "target": "cpe:...", "rel": "normalizes_to", "source_of_truth": "nmap", "confidence": 0.95},
    {"source": "cpe:...", "target": "cve:CVE-2021-41773", "rel": "affected_by", "source_of_truth": "nvd", "confidence": 0.9}
  ]
}
```

`confidence` 在服务侧取 `cpe_source` 的映射（`nmap` → 0.95，`fallback` → 0.6），CVE 侧固定 0.9，`AND` 节点命中降为 0.4。

没有 nmap 输出（Docker 不可用、目标不是纯主机名）时返回空图 + `reason`，不返回 404——"没做到"和"服务坏了"要能区分。

响应里另有 `status`（会话状态）与 `disclaimer`。会话运行中也可以取图，拿到的是当前已产生的部分；`snapshot` 取 findings 的 provenance，取不到时回退到本地 `kg.db` 的 `kg_meta`。

### 前端

`frontend/components/AssetCveGraph.tsx`，在既有 `/agent` 页面报告区下方作为可折叠面板渲染，**不新增路由**（避免动态段）。

- 布局是**分层的左→右**（asset → service → cpe → cve → cwe/fix），不是力导向：这张图表达的是
  一条推断链，力导向会把它揉成一团，反而看不出因果。顺带不需要引入 d3。
- 节点颜色按类型，CVE 按严重级着色；点节点在右侧显示 id、CVSS、验证状态与 CPE。
- 低置信度边（CPE 为查表推断或来自 AND 节点）画成虚线。
- 图例必须写明：**边为推断，不代表已验证漏洞**。
- **未匹配到 CVE 的服务不会出现在图上**：findings 里没有对应记录。要画出"这里没查到"
  需要改会话存储或重跑匹配，当前不做（见"已知限制"）。

## 数据表

```sql
CREATE TABLE kg_cve (
  cve_id          TEXT PRIMARY KEY,
  cvss_v3_score   REAL,
  cvss_vector     TEXT,
  severity        TEXT,
  published       TEXT,
  last_modified   TEXT,
  description     TEXT,
  cwe_ids         TEXT,   -- JSON 数组
  references_json TEXT    -- JSON 数组
);

CREATE TABLE kg_cpe_match (
  id                 INTEGER PRIMARY KEY,
  cve_id             TEXT NOT NULL,
  cpe23              TEXT NOT NULL,   -- criteria
  vendor             TEXT,
  product            TEXT,
  version_start_incl TEXT,
  version_start_excl TEXT,
  version_end_incl   TEXT,
  version_end_excl   TEXT,
  vulnerable         INTEGER NOT NULL,
  node_operator      TEXT             -- OR / AND，用于降置信度
);

CREATE INDEX idx_cpe_product ON kg_cpe_match(product, vendor);
CREATE INDEX idx_cpe_cve     ON kg_cpe_match(cve_id);

CREATE TABLE kg_meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);
```

会话侧的资产与关联不落库：它由 `agent_sessions.findings` 携带，随会话生命周期存在。这样不需要 alembic 迁移，也不存在"图数据和 finding 对不上"的第二份真相。

## 分阶段验收

| 阶段 | 内容 | 验收 | 风险 |
|---|---|---|---|
| P0 | `version.py`、`nmap_parse.py`、`cpe.py` + 单测 | 见下方命令 | 低，纯函数 |
| P1 | 导入脚本、`store.py`、`cve_match` 工具、strategy 接线 | 见下方命令 | 中，改变 planner 工具清单 |
| P2 | `/graph` 接口 + 前端面板 | 手测 + 前端测试 | 低 |
| P3（可选） | 跨发现攻击链（SSRF → 内网资产 → 其 CVE） | 另行设计 | 高，暂不做 |

### P0

```powershell
cd backend
python -m pytest tests/test_kg_version.py tests/test_kg_nmap.py -q
```

必须覆盖的版本用例：`2.4.49 > 2.4.5`、`9.10 > 9.8`、`1.0.2k < 1.0.2u`、`2.4.50 > 2.4.5`、`*` → ANY、`-` → UNKNOWN、不可比较时区间判定返回不命中。

nmap 解析用固定样例 `backend/tests/fixtures/nmap/apache-2.4.49.xml`，断言解析出的端口数、CPE 归一结果与 `cpe_source`。

> `apache-2.4.49.xml` 是手工构造的（首次实现时 Docker 未运行），用于覆盖多端口、
> 缺失 CPE、closed 端口等边界；`apache-2.4.49.real.xml` 是后来真实采集的 nmap 输出，
> 专门锁住 DOCTYPE 与真实字段形态。两者都要保留：前者测分支，后者防回归。

### P1

```powershell
python -m tools.kg_import --years 2021-2026 --output ../backend/data/kg.db
python -m pytest tests/test_kg_match.py -q
```

`kg_import` 默认从 `nvd.nist.gov` 下载并按年缓存到 `data/nvd_cache/`；没有外网时先手工把 `nvdcve-2.0-<年>.json.gz` 放进缓存目录，再带 `--offline` 运行。

若本机配了系统代理（Windows 注册表 `ProxyServer`）但代理没在运行，`urllib` 会跟着走代理并失败，表现为"连不上 NVD"。加 `--no-proxy` 绕过代理直连——首次验证时正是这个原因，不是网络不通。

匹配测试用固定快照子集（`backend/tests/fixtures/kg/mini_nvd.json`，手工摘几条真实 NVD 条目），断言：命中列表、排序、Top-N 截断、`vulnerable:false` 被丢弃、`AND` 节点降置信度。

**P1 合入前必须重跑**：

```powershell
python -m pytest tests/ -q -k "not integration"
```

原因：新增工具会进入 planner 的工具签名清单，改变 Agent 策略评测的输入；改动 `strategy.py` 会改变报告文本。`tools/optimize_agent` 的固定任务集和 RSI 固定回归都可能受影响，必须确认 137 项回归无变化。

### P2

```powershell
python -m pytest tests/test_kg_graph.py -q
cd ../frontend && npm run build
```

## 真机验证

用真实容器做靶、真实 nmap 做指纹，走完整的 `run_recon → run_exploit → build_graph`，
不绕过任何业务代码（只有 LLM 综合与 MySQL 持久化未参与：Ollama 与数据库未启动，
两者失败都被代码捕获，不影响链路）。

环境：Docker 29.7.2 + `sec-llm-sandbox:latest`（含 nmap 7.95）。

| 靶 | nmap 指纹 | 候选 CVE | 产出 |
|---|---|---:|---|
| `httpd:2.4.49` | `Apache httpd 2.4.49`，CPE 由 nmap 直接给出 | 88 | 5 条 finding（Top-N，首位 CVE-2021-42013 / 41773），图 12 节点 / 15 边 |
| 伪造 banner 的 `OpenSSH 8.9p1` | `OpenSSH 8.9p1`，CPE `cpe:/a:openbsd:openssh:8.9p1` | 33 | 5 条 finding，图 17 节点 / 17 边 |
| `nginx:1.27-alpine` | `nginx 1.27.5` | 0 | 空图 + reason（1.27.5 已含 2025-23419 的修复，属正确结果） |

**真机暴露并修复的两个 bug**（手写 fixture 与离线单测都发现不了）：

1. **把 DOCTYPE 当注入拒掉**。真实 nmap 固定输出 `<!DOCTYPE nmaprun>`，早期实现一律拒收，
   结果生产环境永远解析出 0 个服务、`cve_match` 永远拿不到指纹。改为只拦 `<!ENTITY`。
2. **版本字段带发行版后缀**。nmap 实测给出 `version="8.9p1 Ubuntu 3ubuntu0.1"`，
   拿它去比 NVD 区间会算出无意义结果。改为优先采用 CPE 里归一化后的版本；
   若仍含空白（如 `3.5 - 3.10` 这类区间 banner），直接判定为不可比较、不猜测。

真实输出已固化为 `tests/fixtures/nmap/apache-2.4.49.real.xml`（IP 替换为文档地址），
`test_real_nmap_capture_parses` 保证 DOCTYPE 回归不会重演。

## 误报控制

一个 Apache 匹配出 187 条 CVE 的演示是失败的演示。控制手段：

1. **版本区间精确过滤**，`*` 版本条目直接不参与。
2. 丢弃 `vulnerable: false`。
3. 每个服务 Top-N（默认 5），排序键是 `(CVSS, 精确版本命中, 发布时间)`——同分时优先
   "NVD 直接写死这个版本"的条目，避免被同分的宽区间新 CVE 挤出展示位。
4. 跨服务按 `cve_id` 去重，保留评分最高的一条，其余记为"同一 CVE 影响多个服务"。
5. 报告里给出匹配总数与展示数（"命中 23 条，展示 5 条"），**不隐藏被截断的事实**。

## 已知限制

- 只覆盖 nmap 能识别出产品与版本的服务。识别不出就是匹配不到，不猜。
- 解析、入库、落盘均已在真实 feed 上验证：2021–2026 六年 feed 生成 `backend/data/kg.db`
  （390.7 MB，264,147 条 CVE / 900,331 条 cpeMatch / 44,697 个产品，`PRAGMA integrity_check` = ok，
  `kg_meta` 写入了快照日期）；`--offline` 复用缓存重建 7.7s、原子替换生效、无 `.tmp` 残留；
  只读连接上的写入被拒绝。
- 单个服务可能命中几十条 CVE（实测 Apache httpd 2.4.58 命中 69 条，OpenSSH 8.9p1 命中 33 条），
  原因是 NVD 大量使用"上界 2.4.69、无下界"这类区间。报告只展示 Top-N（默认 5），
  但必须同时给出 `total`，否则读者会以为只匹配到 5 条。
- 本地的 `kg.db` 被 `.gitignore` 的 `backend/data/*` 排除、不入库，属于可重建的派生数据。
- 候选排序为 `(CVSS, 精确版本命中, 发布时间)`。第二名排序键是必要的：Apache 2.4.49 实测有
  88 个候选，只按 CVSS+时间排序时 CVE-2021-41773 掉到第 15 位，被一堆同分的 2026 年新 CVE
  挤出去；加入"criteria 直接写死版本 > 宽区间覆盖"后它回到第 2 位（第 1 是同样精确匹配的
  CVE-2021-42013，发布时间更晚）。
- 2026 年 feed 的条目数（96,560）明显高于往年（2021–2025 为 2.3 万–4.6 万），
  导入前应核对 feed 是否被上游调整过口径或做过补录；这不影响解析逻辑，但会影响命中数量级。
- 修复版本只在 NVD 给出**区间上界**（`versionEndExcluding`）时可得。NVD 对相当一部分 CVE
  用的是精确版本 `criteria`（如 `apache:http_server:2.4.49`，CVE-2021-41773 就是），
  这类记录的 `fix_version` 为空——报告里应显示"快照未给出修复版本"，不要编一个。
- 分数与受影响版本会随 NVD 修订变化：CVE-2021-41773 在 2026-06 的快照里 Primary 已是 9.8，
  而早期资料多写 7.5。报告必须显示快照日期，否则读者无法判断分数属于哪个时点。
- 单年快照对现代组件基本无效：只导 2021 时 OpenSSH 8.9p1、nginx 1.25.3 命中均为 0。
  实际使用至少导入近 5 年。
- 不支持 CVSS v4.0 指标（遇到时退回 v3.1 / v3.0 / v2）。
- 只做单节点 `cpeMatch`，不做完整 NVD 配置树求解（`AND`/`OR`/`negate` 组合只做降置信度）。
- 版本比较是最小实现，不支持 epoch、`~` 预发布等发行版特有语义。
- 快照有时效性，最新 CVE 可能缺失；报告必须显示快照日期。
- 不做可达性判断：组件版本受影响 ≠ 目标上该功能可达、可被利用。这一层只能靠复现，属于未来工作。
- 数据库是新建的，历史会话不会补做匹配。

## 与既有契约的关系

| 契约 | 是否受影响 | 说明 |
|---|---|---|
| `verified` 口径 | 不受影响 | CVE 发现恒为 `unverified` |
| 安全评分 | 不受影响 | 只统计 `verified`，加测试固定 |
| 证据链 | 不受影响 | `cve_match` 不产出证据文件，也不假装产出 |
| RAG 评测 | 不受影响 | 不触碰检索层 |
| Agent 策略评测 | **受影响** | 工具清单变化，需重跑并确认基线 |
| 数据库迁移 | 不受影响 | 参考数据在独立 SQLite，会话数据沿用 `findings` |

## 写作与汇报口径

### 可以讲的四个事实

- 补上了覆盖率缺口清单里明确列出的"CVE 匹配未做"一项（`strategy.py` 里那行 skipped 删掉了）。
- 把 `reporting.py` 里一直存在的 `OWASP_CATEGORIES["cve"]` 死代码接活——在此之前没有任何代码
  会产出 CVE 类发现。
- 版本比较有独立单测（15 条），误报有 `vulnerable:false` 过滤、区间精确判定、Top-N 与 `total` 并列展示。
- 推断与证据分离：CVE 发现恒为 `unverified`，不进安全评分，`verified` 口径没有松动。

数字：快照 264,147 条 CVE / 900,331 条 cpeMatch（2021–2026），390.7 MB；KG 相关测试 72 条（`test_kg_version` 15 / `test_kg_nmap` 20 / `test_kg_match` 22 / `test_kg_graph` 15）。

### 值得单独讲的案例：真机验证推翻了 33 个通过的用例

这是整个模块最有信息量的部分，建议按"我原以为是 → 实际是 → 怎么发现"的顺序讲。

**背景。** P0 交付时 33 个单元测试全绿：CPE 2.2→2.3 归一、版本区间、closed 端口过滤、
缺失 CPE 的 fallback 分支，全部覆盖。测试用的是自己手写的 nmap XML fixture。

**转折。** 第一次跑真机扫描（Docker 里的 nmap 7.95 扫 `httpd:2.4.49` 容器），
侦察阶段跑完了、`nmap_xml` 也拿到了，但 `nmap_services` 是空数组，`cve_match` 报
"no service fingerprints available"。也就是说：**功能在真实环境里一次都没成功过，而测试全绿。**

**定位。** 把 `shell_exec` 的原始 stdout 打出来，前 300 字节就看到了答案：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" ...?>
```

解析器返回的错误是 `doctype/entity declarations are not accepted`。

**根因。** 我最初把 `<!DOCTYPE>` 和 `<!ENTITY>` 一起当成实体膨胀（billion laughs）拦掉了。
这是一个**安全直觉压过了真实输入**的错误：真正的攻击面是 `<!ENTITY` 的内部实体展开，
而 nmap 每次都会输出 DOCTYPE。我的 fixture 里恰好没有 DOCTYPE——**因为是我照着实现写的**。

**修法。** 只拦 `<!ENTITY`，放行 DOCTYPE；把这次真实采集的输出固化成
`tests/fixtures/nmap/apache-2.4.49.real.xml`，新增 `test_real_nmap_capture_parses`
锁住真实字段形态。原来的手写 fixture 保留，继续覆盖多端口 / 缺失 CPE / closed 端口等分支。

**第二个 bug，同一轮发现。** 换 OpenSSH 靶继续验证时，nmap 给出
`version="8.9p1 Ubuntu 3ubuntu0.1"`（发行版后缀），而 CPE 里是干净的 `8.9p1`。
匹配器用的是那个脏字段，会拿它去和 NVD 区间做分段比较，结果毫无意义。
真实环境里这种 `version` 字段几乎总是带后缀，所以这也是主干路径上的 bug。
修法：优先用 CPE 里归一化后的版本；若仍含空白（如 `3.5 - 3.10` 这类区间 banner），
直接判定为不可比较，不猜。

**一句话总结（可以直接说）：**

> fixture 是照着自己的实现写的，它只能验证"我以为的输入"对不对，
> 不能证伪"我以为的输入"是不是真的。能证伪假设的只有真实输出。

### 被追问时怎么答

| 追问 | 答案 |
|---|---|
| 为什么不用 Neo4j | 查询是固定 3–4 跳，不是任意深度遍历。图库的价值在路径不确定的场景；这里多一个服务、一套备份换不到能力。数据用 SQLite 三张表，删掉即回到干净状态 |
| 为什么不让 LLM 做 CPE 归一 | 归一和版本区间是可枚举、可单测、可复现的确定性逻辑。实测 2021–2026 快照里 `vulnerable:false` 的 cpeMatch 有 406,061 条、无区间通配 3,892 条，靠模型猜会同时引入漏报和过报，且无法回归 |
| 一个服务 88 个候选，怎么控制误报 | 三层：`vulnerable:false` 与无区间通配在入库时就丢了；版本区间精确判定（不可比较即不命中）；Top-N 展示 + 必须给出 `total`。另外排序里加了"精确版本命中优先"，否则同分的宽区间新 CVE 会把 CVE-2021-41773 挤到第 15 位 |
| 怎么保证推断不被当成证据 | CVE 发现恒为 `unverified`，`verification_reason` 写明是区间推断；不进安全评分（只统计 verified）；图上的边带 `source_of_truth` 与 `confidence`，虚线表示低置信度。系统可以推断，但推断不能伪装成证据 |
| 覆盖多少 | 只覆盖快照内、且 nmap 能识别出版本的服务。识别不出就不猜。不做可达性判断——版本受影响 ≠ 可利用，那一层只能靠复现 |
| 为什么这套测试没早点发现问题 | 见上面的案例。后续凡是"外部输入格式"都要求至少一份真实样本进回归，而不是全部手造 |

### 不能说

- "实现了漏洞检测能力提升"——本模块只做组件版本关联，不代表能利用。
- "知识图谱推理发现攻击链"——P3 没做。
- "覆盖所有 CVE"——只覆盖快照内、且 nmap 能识别出版本的服务。
- "验证了完整的 Agent 流程"——真机验证只跑到 `run_recon → run_exploit → build_graph`，
  LLM 综合与 MySQL 持久化没有参与。
