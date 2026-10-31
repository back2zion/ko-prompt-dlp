#!/usr/bin/env sh
set -e
# Apply DB migrations when a database URL is configured (safe no-op if already current).
if [ -n "${AXFILTER_DATABASE_URL:-}" ]; then
  echo "[entrypoint] running migrations..."
  alembic upgrade head
fi
exec "$@"
