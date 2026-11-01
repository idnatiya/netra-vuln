MYSQL_COMPOSE := docker compose -f compose.dev.yml
TEST_MYSQL_DSN ?= root:test@tcp(127.0.0.1:3317)/
CENTRAL_DSN ?= root:test@tcp(127.0.0.1:3317)/vuln
# The laptop's Tailscale IP when available (so tailnet VMs can report), else local only.
# Uncommon port: 8080/8090 are often taken by other projects.
CENTRAL_ADDR ?= $(or $(shell ip=$$(tailscale ip -4 2>/dev/null) && printf '%s\n' "$$ip" | awk 'NR == 1 && /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$$/ { print; exit }'),127.0.0.1):18080
DEV_ADMIN_USER ?= admin
# Agent release that the dev /install.sh downloads.
CENTRAL_AGENT_VERSION ?= v0.2.0
DEV_ADMIN_PASSWORD_FILE := dev-out/admin-password

.DEFAULT_GOAL := help
.PHONY: help dev dev-admin dev-down test mysql-up central central-dev \
	dashboard-deps dashboard-dev dashboard-test compose-up compose-down

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_\/-]+:.*## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# --- Local development -------------------------------------------------------

dev: mysql-up dist/central dashboard-deps ## Run MySQL + central + dashboard together (Ctrl+C stops all)
	@CENTRAL_DSN='$(CENTRAL_DSN)' dist/central migrate
	@$(MAKE) --no-print-directory dev-admin
	@echo ""
	@echo "  dashboard  http://localhost:11270   (user: $(DEV_ADMIN_USER), password: $(DEV_ADMIN_PASSWORD_FILE))"
	@echo "  central    http://$(CENTRAL_ADDR)   (agents: central_url)"
	@echo ""
	@# Stop both when either exits (e.g. central cannot bind its port), so the
	@# dashboard never keeps proxying to whatever else owns that port.
	@stopped=; trap 'stopped=1' INT TERM; trap 'kill $$(jobs -p) 2>/dev/null' EXIT; \
	CENTRAL_DSN='$(CENTRAL_DSN)' CENTRAL_ADDR='$(CENTRAL_ADDR)' CENTRAL_PUBLIC_URL='http://$(CENTRAL_ADDR)' \
	CENTRAL_AGENT_VERSION='$(CENTRAL_AGENT_VERSION)' dist/central serve & c=$$!; \
	CENTRAL_DEV_URL='http://$(CENTRAL_ADDR)' pnpm -C dashboard dev & v=$$!; \
	while [ -z "$$stopped" ] && kill -0 $$c 2>/dev/null && kill -0 $$v 2>/dev/null; do sleep 1; done; \
	[ -n "$$stopped" ] && { echo "stopped"; exit 0; }; \
	kill -0 $$c 2>/dev/null || echo "central exited; if the port is taken, run: make dev CENTRAL_ADDR=127.0.0.1:<free-port>" >&2; \
	exit 1

dev-admin: dist/central ## Create the dev admin once (password kept in dev-out/admin-password)
	@if CENTRAL_DSN='$(CENTRAL_DSN)' dist/central admin list | awk 'NR > 1 {print $$1}' | grep -qx '$(DEV_ADMIN_USER)'; then \
		echo "admin '$(DEV_ADMIN_USER)' exists"; \
	else \
		mkdir -p $(dir $(DEV_ADMIN_PASSWORD_FILE)); \
		[ -s $(DEV_ADMIN_PASSWORD_FILE) ] || (umask 077; openssl rand -base64 18 > $(DEV_ADMIN_PASSWORD_FILE)); \
		CENTRAL_DSN='$(CENTRAL_DSN)' dist/central admin create $(DEV_ADMIN_USER) < $(DEV_ADMIN_PASSWORD_FILE); \
	fi

dev-down: ## Stop the dev MySQL (its data is on tmpfs and is lost)
	$(MYSQL_COMPOSE) down

mysql-up: ## Start the dev/test MySQL on 127.0.0.1:3317
	$(MYSQL_COMPOSE) up -d --wait

# Fixed output path so the macOS firewall approval sticks (go run uses a new temp path each time).
dist/central: FORCE
	@go build -o dist/central ./core/cmd/central

central: dist/central ## Admin CLI on the dev DB, e.g. make central ARGS="client create acme"
	CENTRAL_DSN='$(CENTRAL_DSN)' dist/central $(ARGS)

central-dev: mysql-up dist/central ## Run central only (no dashboard), e.g. for the VM loop
	CENTRAL_DSN='$(CENTRAL_DSN)' dist/central migrate
	CENTRAL_DSN='$(CENTRAL_DSN)' CENTRAL_ADDR='$(CENTRAL_ADDR)' dist/central serve

FORCE:

# --- Dashboard ---------------------------------------------------------------

dashboard-deps:
	@pnpm -C dashboard install --frozen-lockfile --silent

dashboard-dev: dashboard-deps ## Dashboard dev server only (proxies /api to CENTRAL_ADDR)
	CENTRAL_DEV_URL='http://$(CENTRAL_ADDR)' pnpm -C dashboard dev

dashboard-test: dashboard-deps ## Dashboard unit tests + typecheck
	pnpm -C dashboard test
	pnpm -C dashboard typecheck

# --- Tests & builds ----------------------------------------------------------

test: dashboard-test mysql-up ## Dashboard tests + Go vet + Go tests (core/test against the dev MySQL)
	go vet ./...
	TEST_MYSQL_DSN='$(TEST_MYSQL_DSN)' go test -count=1 ./...

# --- Production stack (.env must exist; see .env.example) -----

COMPOSE := docker compose

compose-up: ## Build and start the production stack
	$(COMPOSE) up -d --build

compose-down: ## Stop the production stack (volumes are kept)
	$(COMPOSE) down
