---
name: sec-llm
version: 1.0.0
description: 调用 Sec-LLM 网络安全平台能力，包括威胁情报富化与研判、钓鱼邮件鉴定、源码审计、蓝队规则生成、扫描报告解析、RAG 知识库对话。Use when the user asks for threat intelligence on IP/domain/hash, phishing email analysis, code security audit, detection rule generation, scan report explanation, or cybersecurity knowledge query.
author: Sec-LLM
permissions:
  - network:outbound
---

# Sec-LLM 网络安全技能

当用户需要以下能力时，使用本 Skill 调用 Sec-LLM 平台：

- **威胁情报**：对 IP、域名、MD5、SHA256 进行富化与研判
- **钓鱼邮件鉴定**：分析邮件内容是否为钓鱼
- **源码审计**：审计代码中的安全漏洞
- **规则生成**：生成 YARA/Suricata 等蓝队检测规则
- **报告解析**：将 Nmap/Nessus 等扫描报告转为可读摘要
- **安全知识问答**：基于 RAG 知识库的安全问答（需 Sec-LLM 已上传文档）

## 前置条件

在 OpenClaw 运行环境中配置环境变量：

- `SEC_LLM_BASE_URL`：Sec-LLM 后端地址（如 `http://localhost:8000`）
- `SEC_LLM_SKILL_API_KEY`：与 Sec-LLM 后端 `SEC_LLM_SKILL_API_KEY` 一致的 API Key

Sec-LLM 后端需在 `.env` 中设置 `SEC_LLM_SKILL_API_KEY` 并重启。

## 调用方式

使用 `scripts/call-sec-llm.sh` 脚本，或直接用 `curl` 调用 Sec-LLM API，请求头需包含：

```
X-Skill-Api-Key: ${SEC_LLM_SKILL_API_KEY}
```

## API 列表

### 1. 威胁情报富化

```bash
# 富化单个 IOC（IP/域名/MD5/SHA256）
curl -sS "${SEC_LLM_BASE_URL}/api/security-tools/threat-intel/enrich" \
  -H "X-Skill-Api-Key: ${SEC_LLM_SKILL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"ioc": "8.8.8.8", "ioc_type": "auto"}'
```

返回包含 `verdict`、`enrichment`、`source_status` 等。

### 2. 威胁情报研判报告

先调用 `enrich` 获取结构化结果，再调用 `report` 生成中文研判报告：

```bash
# 需要传入 enrich 的完整返回作为 enrichment
curl -sS "${SEC_LLM_BASE_URL}/api/security-tools/threat-intel/report" \
  -H "X-Skill-Api-Key: ${SEC_LLM_SKILL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"ioc": "8.8.8.8", "detected_type": "ip", "enrichment": {...}}'
```

返回为流式文本，需完整读取后汇总给用户。

### 3. 钓鱼邮件鉴定

```bash
curl -sS "${SEC_LLM_BASE_URL}/api/security-tools/phishing-analyzer" \
  -H "X-Skill-Api-Key: ${SEC_LLM_SKILL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"content": "邮件正文内容..."}'
```

### 4. 源码审计

```bash
curl -sS "${SEC_LLM_BASE_URL}/api/security-tools/code-audit" \
  -H "X-Skill-Api-Key: ${SEC_LLM_SKILL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"code": "代码内容...", "language": "python"}'
```

### 5. 蓝队规则生成

```bash
curl -sS "${SEC_LLM_BASE_URL}/api/security-tools/rule-generator" \
  -H "X-Skill-Api-Key: ${SEC_LLM_SKILL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"requirement": "检测 Cobalt Strike 心跳", "rule_type": "yara"}'
```

规则类型支持 `yara`、`suricata` 等。

### 6. 扫描报告解析

```bash
curl -sS "${SEC_LLM_BASE_URL}/api/security-tools/report-explainer" \
  -H "X-Skill-Api-Key: ${SEC_LLM_SKILL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"content": "Nmap/Nessus 报告原文..."}'
```

### 7. 安全对话（含 RAG）

```bash
curl -sS "${SEC_LLM_BASE_URL}/api/chat" \
  -H "X-Skill-Api-Key: ${SEC_LLM_SKILL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"message": "用户问题", "history": [], "rag_only": true}'
```

`rag_only: true` 时仅从知识库检索回答；`false` 时允许通用对话。

## 使用流程

1. **威胁情报**：用户提供 IOC → 调用 `enrich` → 调用 `report`（传入 enrich 结果）→ 将报告整理给用户
2. **其他工具**：用户提供输入 → 调用对应 API → 将 `result` 或响应正文整理给用户
3. **安全问答**：用户提问 → 调用 `chat`（`rag_only` 按需设置）→ 流式或非流式读取后回复

## 错误处理

- 401：检查 `SEC_LLM_SKILL_API_KEY` 是否与后端一致
- 连接失败：检查 `SEC_LLM_BASE_URL` 和网络
- 400：检查请求体格式（如 `ioc`、`content` 等字段）
