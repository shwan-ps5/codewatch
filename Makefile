run:
	venv/bin/python manage.py runserver 127.0.0.1:8100

test:
	venv/bin/pytest -q

lint:
	venv/bin/ruff check core tests codewatch
