VENV ?= .venv
PYTHON := $(VENV)/bin/python
BLACK := $(VENV)/bin/black
RUFF := $(VENV)/bin/ruff
MYPY := $(VENV)/bin/mypy
PYTEST := $(VENV)/bin/pytest
PRE_COMMIT := $(VENV)/bin/pre-commit

.PHONY: install-dev quality quality-fix precommit

install-dev:
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"
	$(PRE_COMMIT) install

quality:
	$(BLACK) --check app tests
	$(RUFF) check app tests
	$(MYPY) app tests
	$(PYTEST) -q --maxfail=1

quality-fix:
	$(BLACK) app tests
	$(RUFF) check app tests --fix
	$(MYPY) app tests
	$(PYTEST) -q --maxfail=1

precommit:
	$(PRE_COMMIT) run --all-files
