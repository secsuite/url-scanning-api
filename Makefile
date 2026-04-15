VENV ?= .venv
PYTHON := $(VENV)/bin/python
BLACK := $(VENV)/bin/black
RUFF := $(VENV)/bin/ruff
MYPY := $(VENV)/bin/mypy
PYTEST := $(VENV)/bin/pytest
PRE_COMMIT := $(VENV)/bin/pre-commit
PYTEST_WORKERS ?= 1

.PHONY: install-dev quality quality-fast quality-fix test-fast test-integration precommit

install-dev:
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"
	$(PRE_COMMIT) install --hook-type pre-commit --hook-type pre-push

quality:
	$(BLACK) --check app tests
	$(RUFF) check app tests
	$(MYPY) app tests
	$(MAKE) test-fast

quality-fast:
	$(BLACK) --check app tests
	$(RUFF) check app tests
	$(MYPY) app tests
	$(PYTEST) -q --maxfail=1 -n auto -m "not (requires_safe_browsing_key or requires_virustotal_key)"

quality-fix:
	$(BLACK) app tests
	$(RUFF) check app tests --fix
	$(MYPY) app tests
	$(MAKE) test-fast

test-fast:
	$(PYTEST) -q --maxfail=1 $(if $(filter 1,$(PYTEST_WORKERS)),,-n $(PYTEST_WORKERS)) -m "not (requires_safe_browsing_key or requires_virustotal_key)"

test-integration:
	$(PYTEST) -q --maxfail=1 -m "requires_safe_browsing_key and requires_virustotal_key"

precommit:
	$(PRE_COMMIT) run --all-files
