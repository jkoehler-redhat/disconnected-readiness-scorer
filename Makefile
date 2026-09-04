.PHONY: help
help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: skillsaw
skillsaw: ## Run skillsaw linter on skills and plugins
	@echo "Running skillsaw..."
	@if [ -n "$${SKILLSAW_BIN:-}" ]; then \
		"$${SKILLSAW_BIN}"; \
	else \
		uvx skillsaw; \
	fi

.PHONY: skillsaw-fix
skillsaw-fix: ## Auto-fix fixable skillsaw issues
	@echo "Fixing skillsaw issues..."
	@if [ -n "$${SKILLSAW_BIN:-}" ]; then \
		"$${SKILLSAW_BIN}" fix; \
	else \
		uvx skillsaw fix; \
	fi

.PHONY: ruff-check
ruff-check: ## Check Python code with ruff
	@echo "Running ruff check..."
	@uv run ruff check .
	@uv run ruff format --check .

.PHONY: ruff-fix
ruff-fix: ## Auto-fix ruff violations
	@echo "Fixing ruff issues..."
	@uv run ruff check . --fix

.PHONY: ruff-format
ruff-format: ## Format Python code with ruff
	@echo "Formatting Python code..."
	@uv run ruff format .

.PHONY: ruff-format-check
ruff-format-check: ## Check Python formatting (no changes)
	@echo "Checking Python formatting..."
	@uv run ruff format --check .

.PHONY: test
test: ## Run tests
	@uv run python -m pytest tests/ -v

.PHONY: lint
lint: ## Run all linters (matches CI)
	@$(MAKE) skillsaw
	@$(MAKE) ruff-check
	@$(MAKE) ruff-format-check

.PHONY: ci
ci: lint test ## Run full CI check (lint + test)

ARCH_ANALYZER_VERSION ?= v0.2.4
ARCH_ANALYZER_REPO := ugiordan/architecture-analyzer
ARCH_ANALYZER_SHA256_darwin_arm64 := 7c0ead34aeb379e46a181dec671bb3eb556fae6de9b33c1595d3e36d5e771397
ARCH_ANALYZER_SHA256_linux_amd64  := 80af99072aad942c898e8b9ef026b0b26a82d7bfeb0428b40c0fdda28d9d26c2

_OS   := $(shell uname -s | tr '[:upper:]' '[:lower:]')
_ARCH := $(shell uname -m)
_ARCH := $(subst x86_64,amd64,$(_ARCH))
_ARCH := $(subst aarch64,arm64,$(_ARCH))
_BINARY := arch-analyzer-$(_OS)-$(_ARCH)
_EXPECTED := $(ARCH_ANALYZER_SHA256_$(_OS)_$(_ARCH))

.PHONY: install-arch-analyzer
install-arch-analyzer: ## Download arch-analyzer binary to bin/
	@if [ -z "$(_EXPECTED)" ]; then \
		echo "ERROR: no pinned checksum for $(_OS)-$(_ARCH)"; exit 1; \
	fi
	@mkdir -p bin
	@echo "Downloading $(_BINARY) $(ARCH_ANALYZER_VERSION)..."
	@curl -fsSL "https://github.com/$(ARCH_ANALYZER_REPO)/releases/download/$(ARCH_ANALYZER_VERSION)/$(_BINARY)" -o bin/arch-analyzer
	@ACTUAL=$$(sha256sum bin/arch-analyzer | awk '{print $$1}'); \
	if [ "$(_EXPECTED)" = "$$ACTUAL" ]; then \
		chmod +x bin/arch-analyzer; \
		echo "OK: bin/arch-analyzer (sha256:$$ACTUAL)"; \
	else \
		echo "ERROR: checksum mismatch"; \
		echo "  expected: $(_EXPECTED)"; \
		echo "  got:      $$ACTUAL"; \
		rm -f bin/arch-analyzer; exit 1; \
	fi

.PHONY: update-repo-mappings
update-repo-mappings: ## Refresh .github/config/repo_mappings.json from software-catalog
	@python .github/scripts/update_repo_mappings.py

.DEFAULT_GOAL := help
