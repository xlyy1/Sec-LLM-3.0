# 仓库配置说明

本文档说明如何在 GitHub 网页端完成仓库右侧栏的配置。

---

## 1. About 配置

点击仓库名称旁的 **齿轮图标**，填写：

| 字段 | 建议值 |
|------|--------|
| **Description** | 面向网络安全场景的本地/云端 LLM 平台，集成 RAG、日志分析、威胁情报、流式对话 |
| **Website** | `https://github.com/Mengxun326/Sec-LLM-3.0`（或你的演示地址） |
| **Topics** | `cybersecurity` `llm` `fastapi` `nextjs` `rag` `threat-intelligence` `ollama` `deepseek` `langchain` `chroma` |

---

## 2. 创建首次 Release

1. 点击 **Releases** → **Create a new release**
2. **Tag**：输入 `v1.0.0`，选择 "Create new tag"
3. **Release title**：`v1.0.0`
4. **Description** 示例：

```markdown
## Sec-LLM 3.0

面向网络安全场景的本地/云端 LLM 平台。

### 功能特性

- RAG 知识库、日志分析、威胁情报、流式对话
- 本地 Ollama / 云端 DeepSeek 切换
- 用户认证、数据隔离
```

5. 点击 **Publish release**

**或使用命令行**（需先 `gh auth login`）：

```bash
git tag v1.0.0
git push origin v1.0.0
# 会自动触发 .github/workflows/release.yml 创建 Release
```

---

## 3. Packages（可选）

当前项目为私有应用，通常无需发布 npm/PyPI 包。若需发布：

- **后端**：可配置 `pyproject.toml` 并发布到 PyPI
- **前端**：`package.json` 中 `"private": true`，一般不予发布

---

## 4. Contributors / Languages

- **Contributors**：随提交自动更新，无需配置
- **Languages**：GitHub 自动统计，无需配置

---

## 5. Suggested Workflows

已添加 `.github/workflows/ci.yml` 和 `release.yml`：

- **CI**：每次 push 到 main 时运行后端检查与前端构建
- **Release**：推送 `v*` 标签时自动创建 Release
