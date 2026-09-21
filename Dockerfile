# Pure standard-library Python: no language runtime needed on the host.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DB_PATH=/data/dns.db

WORKDIR /app

COPY app/ ./app/
COPY migrations/ ./migrations/
COPY tests/ ./tests/
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && mkdir -p /data

EXPOSE 8080 53
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["edge"]
