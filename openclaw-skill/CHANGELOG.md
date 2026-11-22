# OpenClaw Skill 更新日志

## 1.0.0 (2026-03)

- 初始版本：Sec-LLM 作为 OpenClaw Skill
- 支持威胁情报、钓鱼鉴定、源码审计、规则生成、报告解析、RAG 对话
- Skill API Key 认证（X-Skill-Api-Key）
- 辅助脚本 `call-sec-llm.sh`

### 安全检查（2026-03 修订）

- 后端：API Key 校验改为 `secrets.compare_digest`，防止时序攻击
- 脚本：enrich/rule 等参数使用 jq 构建 JSON，避免特殊字符注入
