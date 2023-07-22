.PHONY: format check pyment

format:
	@echo "Running isort..."
	@poetry run isort --profile black .
	@echo "Running black..."
	@poetry run black .

check:
	@echo "Running bandit..."
	@poetry run bandit --configfile pyproject.toml -r .

pyment:
	poetry run pyment .

all: format check