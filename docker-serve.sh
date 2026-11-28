#!/bin/sh
# The server in the container: migrate the database on /data, then serve on port 8100. The first admin password
# is written to /data/.cache/codewatch/admin-password.txt unless CODEWATCH_ADMIN_PASSWORD is set.
set -e
cd /opt/codewatch
venv/bin/python manage.py migrate --noinput
exec venv/bin/python manage.py runserver 0.0.0.0:8100
