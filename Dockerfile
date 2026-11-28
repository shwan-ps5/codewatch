# codewatch with every analyzer at its pinned version, for `codewatch check` on a mounted repository or for the
# server. Live-page accessibility checks (axe in Chromium) are left out to keep the image small.
#
#   docker build -t codewatch .
#   docker run --rm -v "$PWD:/src" codewatch check --all            # every analyzer over the repository
#   docker run -d -p 8100:8100 -v codewatch-data:/data --entrypoint /opt/codewatch/docker-serve.sh codewatch
FROM python:3.14-slim-trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends git nodejs npm cppcheck \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system safe.directory '*' \
    && useradd --create-home --uid 10001 codewatch \
    && install -d -o codewatch /src \
    && install -d -o codewatch -m 1777 /data   # writable when run as the caller's uid (pre-commit does)

WORKDIR /opt/codewatch
COPY --chown=codewatch . .
USER codewatch
RUN python -m venv venv \
    && venv/bin/pip install -q --no-cache-dir -e . \
    && venv/bin/pip install -q --no-cache-dir --require-hashes -r tools/analyzers.lock \
    && for t in semgrep checkov; do python -m venv "tools/$t-venv" \
       && "tools/$t-venv/bin/pip" install -q --no-cache-dir --require-hashes -r "tools/$t.lock"; done \
    && npm ci --prefix tools --omit=optional --no-audit --no-fund \
    && rm -rf ~/.npm

ENV PATH=/opt/codewatch/venv/bin:$PATH \
    CODEWATCH_DB=/data/db.sqlite3 \
    HOME=/data
WORKDIR /src
HEALTHCHECK --interval=60s --timeout=5s CMD ["codewatch", "--help"]
ENTRYPOINT ["codewatch"]
CMD ["check", "--all"]
