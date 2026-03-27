# Deploysapp.com Security Test Suite
# Usage: make <target>
# Full audit: make full-audit

COMPOSE         = docker compose
COMPOSE_ATTACK  = docker compose --profile attack
REPORTS_DIR     = reports

.PHONY: all setup targets-up wait \
        scan-network scan-containers scan-docker-socket scan-proxy \
        scan-auth scan-api scan-secrets scan-dos scan-ssrf \
        scan-privesc scan-network-seg scan-tls scan-db scan-images \
        full-audit report clean help

help:
	@echo ""
	@echo "Deploysapp Security Test Suite"
	@echo "================================"
	@echo "  make setup           Generate certs + create report dirs"
	@echo "  make targets-up      Start platform + target services"
	@echo "  make wait            Wait for services to be healthy"
	@echo "  make full-audit      Run ALL scans in sequence (~100 min)"
	@echo "  make report          Generate HTML report from raw results"
	@echo "  make clean           Tear down everything + delete reports"
	@echo ""
	@echo "Individual scan targets:"
	@echo "  make scan-network    Category 01: port scanning"
	@echo "  make scan-containers Category 02+03: container escape"
	@echo "  make scan-proxy      Category 04: reverse proxy"
	@echo "  make scan-auth       Category 05: authentication"
	@echo "  make scan-api        Category 06: OWASP Top 10"
	@echo "  make scan-secrets    Category 07+14: secrets leakage"
	@echo "  make scan-dos        Category 08: DoS/rate limits"
	@echo "  make scan-ssrf       Category 09: SSRF (CRITICAL)"
	@echo "  make scan-privesc    Category 10: privilege escalation"
	@echo "  make scan-network-seg Category 11: inter-service isolation"
	@echo "  make scan-tls        Category 12: TLS/SSL"
	@echo "  make scan-db         Category 13: database exposure"
	@echo "  make scan-images     Trivy CVE + secrets image scan"
	@echo ""

setup:
	@echo "[setup] Generating TLS certificates..."
	bash scripts/setup-certs.sh
	@echo "[setup] Creating report directories..."
	mkdir -p $(REPORTS_DIR)/raw $(REPORTS_DIR)/html
	@echo "[setup] Pulling scanner images (may take a few minutes)..."
	$(COMPOSE) pull traefik 2>/dev/null || true
	@echo "[setup] Done."

targets-up:
	@echo "[up] Starting platform + target services..."
	$(COMPOSE) up -d --build
	@echo "[up] Services starting. Use 'make wait' to poll readiness."

wait:
	@echo "[wait] Polling service health..."
	$(COMPOSE) run --rm -e BASE_URL=http://traefik:80 \
		--entrypoint bash network-tester -c "bash /checks/wait.sh" 2>/dev/null || \
	bash scripts/wait-for-targets.sh

scan-network:
	@echo "[scan] 01 — Network port scanning..."
	mkdir -p $(REPORTS_DIR)/raw
	$(COMPOSE_ATTACK) run --rm nmap-scanner

scan-containers:
	@echo "[scan] 02+03 — Container escape + Docker socket..."
	mkdir -p $(REPORTS_DIR)/raw
	$(COMPOSE_ATTACK) run --rm container-escape
	$(COMPOSE_ATTACK) run --rm -v $(PWD)/$(REPORTS_DIR)/raw:/reports \
		--entrypoint bash network-tester /checks/socket-exposure-test.sh 2>/dev/null || \
	$(COMPOSE_ATTACK) run --rm container-escape bash /checks/02-docker-socket.sh

scan-proxy:
	@echo "[scan] 04 — Reverse proxy security..."
	mkdir -p $(REPORTS_DIR)/raw
	$(COMPOSE_ATTACK) run --rm \
		-e BASE_URL=http://traefik:80 \
		--entrypoint bash network-tester \
		-c "apk add -q curl && bash /tests/04-reverse-proxy/header-injection.sh" 2>/dev/null || \
	docker run --rm --network deploysapp-security-test_attacker-net \
		-v $(PWD)/tests:/tests \
		-v $(PWD)/$(REPORTS_DIR)/raw:/reports \
		-e BASE_URL=http://traefik:80 \
		alpine sh -c "apk add -q curl bash && bash /tests/04-reverse-proxy/header-injection.sh"

scan-auth:
	@echo "[scan] 05 — Authentication tests..."
	mkdir -p $(REPORTS_DIR)/raw
	docker run --rm --network deploysapp-security-test_platform-net \
		-v $(PWD)/tests:/tests \
		-v $(PWD)/$(REPORTS_DIR)/raw:/reports \
		-e BASE_URL=http://traefik:80 \
		alpine sh -c "apk add -q curl bash python3 && bash /tests/05-authentication/jwt-tests.sh"

scan-api:
	@echo "[scan] 06 — API security (OWASP Top 10 + ZAP)..."
	mkdir -p $(REPORTS_DIR)/raw
	$(COMPOSE_ATTACK) run --rm nuclei-scanner
	docker run --rm --network deploysapp-security-test_attacker-net \
		-v $(PWD)/tests:/tests \
		-v $(PWD)/$(REPORTS_DIR)/raw:/reports \
		-e BASE_URL=http://traefik:80 \
		alpine sh -c "apk add -q curl bash python3 && bash /tests/06-api-security/owasp-top10.sh"

scan-secrets:
	@echo "[scan] 07+14 — Secrets leakage tests..."
	mkdir -p $(REPORTS_DIR)/raw
	docker run --rm --network deploysapp-security-test_attacker-net \
		-v $(PWD)/tests:/tests \
		-v $(PWD)/$(REPORTS_DIR)/raw:/reports \
		-e BASE_URL=http://traefik:80 \
		alpine sh -c "apk add -q curl bash && bash /tests/07-secrets/env-var-leak.sh && bash /tests/14-logs-leakage/sensitive-data-in-logs.sh"

scan-dos:
	@echo "[scan] 08 — DoS / rate limiting tests..."
	@echo "WARNING: This will generate significant traffic. Ctrl+C to abort."
	mkdir -p $(REPORTS_DIR)/raw
	$(COMPOSE_ATTACK) run --rm dos-tester || true
	docker run --rm --network deploysapp-security-test_attacker-net \
		-v $(PWD)/tests:/tests \
		-v $(PWD)/$(REPORTS_DIR)/raw:/reports \
		-e BASE_URL=http://traefik:80 \
		alpine sh -c "apk add -q curl bash && bash /tests/08-dos/rate-limit-verify.sh"

scan-ssrf:
	@echo "[scan] 09 — SSRF tests (CRITICAL)..."
	mkdir -p $(REPORTS_DIR)/raw
	docker run --rm \
		--network deploysapp-security-test_attacker-net \
		--network deploysapp-security-test_tenant-net \
		-v $(PWD)/tests:/tests \
		-v $(PWD)/$(REPORTS_DIR)/raw:/reports \
		-e BASE_URL=http://traefik:80 \
		alpine sh -c "apk add -q curl bash python3 && bash /tests/09-ssrf/ssrf-internal-network.sh"

scan-privesc:
	@echo "[scan] 10 — Privilege escalation tests..."
	mkdir -p $(REPORTS_DIR)/raw
	$(COMPOSE_ATTACK) run --rm \
		--entrypoint bash container-escape \
		/tests/10-privilege-escalation/suid-binaries.sh 2>/dev/null || \
	docker run --rm --network deploysapp-security-test_tenant-net \
		-v $(PWD)/tests:/tests \
		-v $(PWD)/$(REPORTS_DIR)/raw:/reports \
		alpine sh -c "apk add -q bash findutils && bash /tests/10-privilege-escalation/suid-binaries.sh"

scan-network-seg:
	@echo "[scan] 11 — Inter-service network segmentation..."
	mkdir -p $(REPORTS_DIR)/raw
	$(COMPOSE_ATTACK) run --rm network-tester

scan-tls:
	@echo "[scan] 12 — TLS/SSL configuration..."
	mkdir -p $(REPORTS_DIR)/raw
	docker run --rm --network deploysapp-security-test_attacker-net \
		-v $(PWD)/tests:/tests \
		-v $(PWD)/$(REPORTS_DIR)/raw:/reports \
		-e BASE_HOST=traefik \
		-e BASE_PORT=443 \
		alpine sh -c "apk add -q curl bash openssl && bash /tests/12-tls-ssl/ssl-scan.sh"

scan-db:
	@echo "[scan] 13 — Database exposure tests..."
	mkdir -p $(REPORTS_DIR)/raw
	docker run --rm \
		--network deploysapp-security-test_attacker-net \
		--network deploysapp-security-test_tenant-net \
		-v $(PWD)/tests:/tests \
		-v $(PWD)/$(REPORTS_DIR)/raw:/reports \
		alpine sh -c "apk add -q bash netcat-openbsd && bash /tests/13-database/db-exposure.sh"

scan-images:
	@echo "[scan] Trivy — CVE + secrets scan on all images..."
	mkdir -p $(REPORTS_DIR)/raw
	$(COMPOSE_ATTACK) run --rm trivy sh /config/scan-all.sh

full-audit: setup targets-up
	@echo "Waiting 30s for services to start..."
	sleep 30
	$(MAKE) scan-network
	$(MAKE) scan-containers
	$(MAKE) scan-proxy
	$(MAKE) scan-auth
	$(MAKE) scan-api
	$(MAKE) scan-secrets
	$(MAKE) scan-ssrf
	$(MAKE) scan-privesc
	$(MAKE) scan-network-seg
	$(MAKE) scan-tls
	$(MAKE) scan-db
	$(MAKE) scan-images
	$(MAKE) scan-dos
	$(MAKE) report
	@echo ""
	@echo "============================================================"
	@echo "Full audit complete. Open reports/html/security-report.html"
	@echo "============================================================"

report:
	@echo "[report] Generating HTML security report..."
	python3 scripts/generate-html-report.py
	@echo "[report] Done: reports/html/security-report.html"

clean:
	@echo "[clean] Tearing down all containers and removing data..."
	bash scripts/cleanup.sh
