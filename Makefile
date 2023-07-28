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
	@echo "Running pyment..."
	@poetry run pyment .
	
pytest:
	@echo "Running pytest..."
	@poetry run pytest
    
cov:
	@echo "Running pytest html coverage..."
	@poetry run pytest test/test_ise.py --cov="." --cov-report=html 
	@echo "Running pytest xml coverage..."
	@poetry run pytest test/test_ise.py --cov="." --cov-report=xml

codecov:
	@echo "Uploading coverage to codecov.."
	@codecov -t $(token)
	
all: format check