# Sec-LLM OpenClaw Skill

将 [Sec-LLM](https://github.com/yusichen396/Sec-LLM-3.0) 网络安全平台的能力暴露为 OpenClaw 技能，使智能体可在 Telegram、Discord 等渠道调用威胁情报、RAG 对话、钓鱼鉴定、源码审计等功能。

## 前置条件

1. **Sec-LLM 后端**已部署并可访问
2. **OpenClaw** 已安装并运行
3. 后端已配置 `SEC_LLM_SKILL_API_KEY`（见下方）

## 配置步骤

### 1. 在 Sec-LLM 后端启用 Skill API Key

编辑 `backend/.env`，添加（或生成强随机字符串）：

```env
SEC_LLM_SKILL_API_KEY=your-secure-random-key-here
```

重启 Sec-LLM 后端使配置生效。

### 2. 安装 Skill 到 OpenClaw

将 `sec-llm` 目录复制到 OpenClaw 的 Skills 目录：

```bash
# 默认路径（按 OpenClaw 版本可能不同）
mkdir -p ~/.openclaw/workspace/skills
cp -r openclaw-skill/sec-llm ~/.openclaw/workspace/skills/

# 或若使用 ~/.openclaw/skills
mkdir -p ~/.openclaw/skills
cp -r openclaw-skill/sec-llm ~/.openclaw/skills/
```

### 3. 配置环境变量

在 OpenClaw 运行环境中设置：

```bash
export SEC_LLM_BASE_URL="http://localhost:8000"   # Sec-LLM 后端地址
export SEC_LLM_SKILL_API_KEY="your-secure-random-key-here"
```

若 OpenClaw 使用 `~/.openclaw/.env` 或系统 env，可在其中添加上述变量。

### 4. 刷新 Skill

- 让智能体执行「刷新 skills」
- 或重启 OpenClaw Gateway

## 能力说明

| 能力         | 触发场景                     | 对应 API                    |
|--------------|------------------------------|-----------------------------|
| 威胁情报     | 用户提供 IP/域名/MD5/SHA256  | `threat-intel/enrich` + `report` |
| 钓鱼鉴定     | 用户提供邮件内容             | `phishing-analyzer`          |
| 源码审计     | 用户提供代码或文件路径       | `code-audit`                 |
| 规则生成     | 用户描述检测需求             | `rule-generator`             |
| 报告解析     | 用户提供 Nmap/Nessus 报告    | `report-explainer`           |
| 安全问答/RAG | 用户提问                     | `chat`                      |

## 使用示例

用户在 OpenClaw 对话中可这样触发：

- 「分析 IP 8.8.8.8 的威胁情报」
- 「这封邮件是钓鱼吗：[邮件内容]」
- 「审计这段 Python 代码的安全问题」
- 「生成一个检测 Cobalt Strike 的 YARA 规则」
- 「把这段 Nmap 报告翻译成管理层能懂的摘要」
- 「根据知识库回答：什么是 XSS？」

## 目录结构

```
openclaw-skill/
├── README.md           # 本说明
└── sec-llm/
    ├── SKILL.md        # OpenClaw Skill 定义与使用说明
    └── scripts/
        └── call-sec-llm.sh  # 调用 Sec-LLM 的辅助脚本
```

## 故障排查

- **401 Unauthorized**：检查 `SEC_LLM_SKILL_API_KEY` 是否与后端 `.env` 一致
- **Connection refused**：检查 `SEC_LLM_BASE_URL` 和 Sec-LLM 是否已启动
- **Skill 未加载**：确认路径为 `~/.openclaw/workspace/skills/sec-llm`（或当前 OpenClaw 文档要求的路径），并重启 Gateway
