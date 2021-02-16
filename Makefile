.PHONY: clean clean-test clean-pyc clean-build docs help
.DEFAULT_GOAL := help

TESTS_DIR := tests
FIXTURES_DIR := $(TESTS_DIR)/fixtures
SCRIPTS_DIR := scripts

RESULTS_FIXTURE_ARCHIVE := $(FIXTURES_DIR)/report_results.zip

BROWSER := xdg-open

define PRINT_HELP_PYSCRIPT
import re, sys
for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . \( -path ./env -o -path ./venv -o -path ./.env -o -path ./.venv \) -prune -o -name '*.egg-info' -exec rm -fr {} +
	find . \( -path ./env -o -path ./venv -o -path ./.env -o -path ./.venv \) -prune -o -name '*.egg' -exec rm -f {} +

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache

lint: ## check style
	-mypy
	-flake8 polyunite tests
	-yapf -p -r -d polyunite
	-isort --recursive --diff polyunite

format:  ## format code in Polyswarm style
	yapf -p -r -i polyunite tests
	isort --recursive polyunite tests

test: ## run tests
	python3 setup.py test

test-quick:
	pytest --cache-clear tests/quicktest.py

.PHONY: patterns-report
report:  ## Show colorized results report
	@$(SCRIPTS_DIR)/colorize

.PHONY: patterns-report
patterns-report:  ## Show all engine's full regex patterns
	@$(SCRIPTS_DIR)/vocabs

.PHONY: result-fixtures
result-fixtures: $(RESULTS_FIXTURE_ARCHIVE) ## save the current engine's results to the test fixtures archive

$(RESULTS_FIXTURE_ARCHIVE): FORCE
	rm $@
	$(SCRIPTS_DIR)/make_fixtures | zip $@ -
	printf "@ -\n@=report_results.json\n" | zipnote -w $@

FORCE:

dist: clean ## builds source and wheel package
	python setup.py sdist
	python setup.py bdist_wheel
	ls -l dist
