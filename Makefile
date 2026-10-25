VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
ANSIBLE_DIR := deploy/ansible

MYSQL_COMPOSE := docker compose -f deploy/dev/mysql.compose.yml
TEST_MYSQL_DSN ?= root:test@tcp(127.0.0.1:3317)/
CENTRAL_DSN ?= root:test@tcp(127.0.0.1:3317)/vuln
# Tailscale IP of this laptop; the sample VM pushes here.
CENTRAL_ADDR ?= 100.77.238.106:8080

.PHONY: test test-integration mysql-up build-linux fakecentral central central-dev deploy-dev scan-dev

test:
	go vet ./...
	go test ./...

mysql-up:
	$(MYSQL_COMPOSE) up -d --wait

# Runs all tests, including the MySQL ones that `make test` skips.
test-integration: mysql-up
	TEST_MYSQL_DSN='$(TEST_MYSQL_DSN)' go test -count=1 ./...

build-linux:
	@for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" \
			-o dist/vuln-agent-linux-$$arch ./agent/cmd/vuln-agent || exit 1; \
	done

# Extra flags via ARGS, e.g. make fakecentral ARGS=-fail-reports
fakecentral:
	go run ./deploy/dev/fakecentral $(ARGS)

deploy-dev: build-linux
	cd $(ANSIBLE_DIR) && ansible-playbook site.yml $(ARGS)

scan-dev: build-linux
	cd $(ANSIBLE_DIR) && ansible-playbook site.yml -e vuln_agent_run_scan=true $(ARGS)

# Fixed output path so the macOS firewall approval sticks (go run uses a new temp path each time).
dist/central: FORCE
	go build -o dist/central ./central/cmd/central

# Admin CLI against the dev database, e.g. make central ARGS="client create dev"
central: dist/central
	CENTRAL_DSN='$(CENTRAL_DSN)' dist/central $(ARGS)

# Real central for the VM dev loop (replaces fakecentral on the same address).
central-dev: mysql-up dist/central
	CENTRAL_DSN='$(CENTRAL_DSN)' dist/central migrate
	CENTRAL_DSN='$(CENTRAL_DSN)' CENTRAL_ADDR='$(CENTRAL_ADDR)' dist/central serve

FORCE:
