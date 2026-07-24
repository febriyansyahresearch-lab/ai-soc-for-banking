.PHONY: setup test clean

setup:
	pip install -r requirements.txt

test:
	python -m pytest tests/ -v --tb=short

test-cov:
	python -m pytest tests/ --cov=src --cov-report=term-missing

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; find . -type f -name "*.pyc" -delete 2>/dev/null; find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null
