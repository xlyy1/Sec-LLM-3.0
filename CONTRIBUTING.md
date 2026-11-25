# Contributing

## 本地开发

```bash
# 后端（Python 3.12+）
cd backend
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn main:app --reload --port 8000

# 前端
cd frontend
npm ci
npm run dev
```

只想把整套栈跑起来时用 Docker：

```bash
cp .env.compose.example .env
docker compose up -d --build --wait
```

## 提交前

- 后端：`python -m pytest tests/ -q`（真实 MySQL/Docker/浏览器用例默认跳过）
- 前端：`npx tsc --noEmit`、`npm run lint`、`npm run build`
- 依赖：修改 `backend/requirements.txt` 后同步更新 `backend/requirements.lock.txt`
  （锁文件按宿主环境 `pip freeze` 生成，Docker 用 `--no-deps` 安装）

## Pull Request

- 一个 PR 只做一件事，说明**改了什么、为什么、怎么验证**。
- 涉及扫描/利用能力时，必须说明授权边界与失败时的降级行为；不要提交真实目标数据。
- 新增对外接口请补 README 的 API 表格与最小验证命令。
- 安全问题不要开公开 issue，按 [SECURITY.md](SECURITY.md) 私下报告。

## 代码风格

- 后端保持类型注解与现有目录结构（`agents/`、`tools/`、`core/`、`api/`）。
- 前端沿用现有 Tailwind + 函数组件；不要引入第二套状态管理。
- 日志优先用 `logging`（JSON 行），避免新增 `print()`。
