VENV ?= .venv
PYTHON := $(VENV)/bin/python
BLACK := $(VENV)/bin/black
RUFF := $(VENV)/bin/ruff
MYPY := $(VENV)/bin/mypy
PYTEST := $(VENV)/bin/pytest
PRE_COMMIT := $(VENV)/bin/pre-commit
PYTEST_WORKERS ?= 1

.PHONY: install-dev quality quality-fast quality-fix precommit

install-dev:
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"
	$(PRE_COMMIT) install --hook-type pre-push

quality:
	$(BLACK) --check app tests
	$(RUFF) check app tests
	$(MYPY) app tests
	$(PYTEST) -q --maxfail=1 $(if $(filter 1,$(PYTEST_WORKERS)),,-n $(PYTEST_WORKERS))

quality-fast:
	$(BLACK) --check app tests
	$(RUFF) check app tests
	$(MYPY) app tests
	$(PYTEST) -q --maxfail=1 -n auto

quality-fix:
	$(BLACK) app tests
	$(RUFF) check app tests --fix
	$(MYPY) app tests
	$(PYTEST) -q --maxfail=1 $(if $(filter 1,$(PYTEST_WORKERS)),,-n $(PYTEST_WORKERS))

precommit:
	$(PRE_COMMIT) run --all-files
