.PHONY: clean clean-test clean-pyc clean-build docs help
.DEFAULT_GOAL := help

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
	py.test

coverage: ## check code coverage
	coverage run --source polyunite -m pytest
	coverage report -m
	coverage html
	$(BROWSER) htmlcov/index.html

backup-frames: ## backup frame cache entries
	tar -a -cvf frame_cache.tar.gz .cache/frames/*

docs: ## generate documentation, including API docs
	rm -f docs/polyunite.rst
	rm -f docs/modules.rst
	sphinx-apidoc -o docs/ polyunite
	$(MAKE) -C docs clean
	$(MAKE) -C docs html
	$(BROWSER) docs/_build/html/index.html

servedocs: docs ## compile the docs watching for changes
	watchmedo shell-command -p '*.rst' -c '$(MAKE) -C docs html' -R -D .

dist: clean ## builds source and wheel package
	python setup.py sdist
	python setup.py bdist_wheel
	ls -l dist
