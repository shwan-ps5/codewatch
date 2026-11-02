run:
	venv/bin/python manage.py runserver 127.0.0.1:8100

# Analyzers at the versions and hashes in tools/*.lock and tools/package-lock.json.
tools:
	npm ci --prefix tools
	tools/node_modules/.bin/playwright install --only-shell chromium
	venv/bin/pip install -q --require-hashes -r tools/analyzers.lock
	for t in semgrep checkov; do python3 -m venv tools/$$t-venv && tools/$$t-venv/bin/pip install -q --require-hashes -r tools/$$t.lock; done

# New analyzer versions: review the diff, re-run the benchmarks, commit. eslint stays on 9 until its plugins support 10.
lock:
	printf 'ruff\nbandit\nradon\nlizard\npip-audit\ncomplexipy\nbasedpyright\ndetect-secrets\n' | uv pip compile - --upgrade --generate-hashes --no-header -q -o tools/analyzers.lock
	for t in semgrep checkov; do echo $$t | uv pip compile - --upgrade --generate-hashes --no-header -q -o tools/$$t.lock; done
	cd tools && npm outdated || true   # then set new exact versions in tools/package.json and run npm install

test:
	venv/bin/pytest -q -n auto

lint:
	venv/bin/ruff check core tests codewatch

.PHONY: run tools lock test lint
