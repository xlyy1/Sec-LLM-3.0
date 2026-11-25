COMPOSE ?= docker compose

.PHONY: up down logs ps config smoke sandbox rebuild

up:
	$(COMPOSE) up -d --build --wait

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=200

ps:
	$(COMPOSE) ps

config:
	$(COMPOSE) config

smoke:
	curl -fsS http://localhost:8000/ >/dev/null && echo "backend OK"
	curl -fsS http://localhost:3000/ >/dev/null && echo "frontend OK"

sandbox:
	$(COMPOSE) --profile sandbox build sandbox

rebuild:
	$(COMPOSE) build --no-cache
