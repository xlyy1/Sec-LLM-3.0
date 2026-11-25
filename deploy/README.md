# 部署层（Nginx / TLS）

开发用 `docker compose up` 仍然直接暴露 `3000/8000`。需要 TLS 或做 staging 验收时，用 `proxy` profile 在前面加一层 Nginx：

```bash
# 1. 生成自签名证书（生产替换为正式证书）
python scripts/gen-dev-cert.py

# 2. 启动带 TLS 的入口
docker compose --profile proxy up -d nginx

# 3. 验收（自签证书用 -k）
curl -k https://localhost/healthz
curl -k https://localhost/readyz
curl -k https://localhost/api/agent/sessions   # 预期 401
curl -k https://localhost/                     # 前端页面
```

访问入口：`https://localhost/`。HTTP 会自动 301 到 HTTPS。

## 生产替换项

- `deploy/certs/server.crt` / `server.key` 换成正式证书（Let's Encrypt / 企业 CA），不要把私钥提交到仓库。
- 前端镜像的 `NEXT_PUBLIC_API_URL` 改成 `https://<你的域名>` 后重建：
  `docker compose build --build-arg NEXT_PUBLIC_API_URL=https://example.com frontend`
- 关闭直连端口：生产编排中删除 backend 的 `8000:8000` 与 frontend 的 `3000:3000`，只保留 Nginx 的 80/443。
- `/metrics` 已在 Nginx 层 `deny all`，只允许内网 Prometheus 抓取。
- 镜像/配置变更后先在有 staging 域名的环境跑一轮 smoke，再切生产 DNS。

## 当前边界

- Nginx 只负责 TLS、路由、请求体大小、SSE 不缓冲和基础安全头；限流/配额仍在应用层。
- 自签名证书只用于本地验证，浏览器会提示不受信任。
