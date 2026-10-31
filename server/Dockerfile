# AX Filter API image. Runs migrations then serves behind a TLS-terminating proxy.
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY axfilter ./axfilter
RUN pip install --no-cache-dir ".[postgres]" alembic

COPY alembic.ini ./
COPY alembic ./alembic
COPY main.py seed_demo.py ./
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Run as a non-root user.
RUN useradd -r -u 10001 axfilter && mkdir -p /data && chown axfilter /data /app
USER axfilter
ENV AXFILTER_DATA_DIR=/data
EXPOSE 8000
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["axfilter", "serve", "--host", "0.0.0.0", "--port", "8000"]
