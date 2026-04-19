VENV ?= .venv
PYTHON := $(VENV)/bin/python
TRAIN_VENV ?= .venv-train
TRAIN_PYTHON := $(TRAIN_VENV)/bin/python
BLACK := $(VENV)/bin/black
RUFF := $(VENV)/bin/ruff
MYPY := $(VENV)/bin/mypy
PYTEST := $(VENV)/bin/pytest
PRE_COMMIT := $(VENV)/bin/pre-commit
PYTEST_WORKERS ?= 1

.PHONY: install-runtime install-train quality quality-fast quality-fix test-fast test-integration precommit

install-runtime:
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m playwright install chromium

install-train:
	python3 -m venv $(TRAIN_VENV)
	$(TRAIN_PYTHON) -m pip install --upgrade pip
	$(TRAIN_PYTHON) -m pip install -r requirements-train.txt

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
