run:
	venv/bin/python manage.py runserver 127.0.0.1:8100

tools:
	npm ci --prefix tools
	tools/node_modules/.bin/playwright install --only-shell chromium
	python3 -m venv tools/checkov-venv && tools/checkov-venv/bin/pip install -q checkov

test:
	venv/bin/pytest -q

lint:
	venv/bin/ruff check core tests codewatch

.PHONY: run tools test lint
