.PHONY: help install demo gate test serve docker-demo down clean

PY ?= python
COMPOSE ?= docker compose

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Install the package with dev extras
	$(PY) -m pip install -e ".[dev]"

demo: ## One command: crypto + mTLS self-check, run the corpus, print the scoreboard
	$(PY) -m aegis.cli demo

gate: ## CI gate: fail if defenses block less than the threshold of the corpus
	$(PY) -m aegis.cli gate --threshold 0.95

test: ## Run tests + coverage gate
	$(PY) -m pytest --cov=aegis --cov-report=term-missing --cov-fail-under=90

serve: ## Run the command-authority service locally (port 8600)
	uvicorn aegis.service:app --reload --port 8600

docker-demo: ## Build the image and run the demo inside the container
	$(COMPOSE) build authority
	$(COMPOSE) run --rm authority python -m aegis.cli demo
	$(COMPOSE) up -d authority
	@echo "  command-authority API: http://localhost:8600/health"

down: ## Stop the service
	$(COMPOSE) down

clean: ## Remove run artifacts
	rm -rf runs .pytest_cache .coverage htmlcov src/*.egg-info
