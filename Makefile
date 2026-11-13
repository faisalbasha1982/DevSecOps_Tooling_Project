.DEFAULT_GOAL := all
include config/images.env

.PHONY: help all secrets sast triage baseline pull test clean

help: ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

# GNU make exits 2 whenever a recipe fails, so it cannot pass 1 (findings) vs
# 2 (error) through. Each recipe prints the real code; use ./run.sh for exact codes.
all: ## All tasks: secrets, sast, triage
	@./run.sh all || { rc=$$?; echo "run.sh exit code: $$rc" >&2; exit $$rc; }

secrets: ## Task 1: secrets scan with baseline
	@./run.sh secrets || { rc=$$?; echo "exit code: $$rc" >&2; exit $$rc; }

sast: ## Task 2: SAST (MIN_SEVERITY=INFO|LOW|MEDIUM|HIGH|CRITICAL, default HIGH)
	@./run.sh sast || { rc=$$?; echo "exit code: $$rc" >&2; exit $$rc; }

triage: ## Task 3: artifacts/triage.md from existing scan output
	@./run.sh triage

baseline: ## Task 1: add current secret findings to baseline.json as UNREVIEWED
	./run.sh secrets -- --update-baseline

pull: ## Pre-pull the pinned scanner images (optional; first run pulls them anyway)
	docker pull $(GITLEAKS_IMAGE)
	docker pull $(SEMGREP_IMAGE)

test: ## Smoke tests covering every acceptance criterion
	./tests/test_smoke.sh

clean: ## Remove generated artifacts
	rm -f artifacts/*.json artifacts/*.sarif artifacts/*.md

