FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    OSINT_DATA_DIR=/data \
    OSINT_DATABASE=/data/osint.db

WORKDIR /app

COPY pyproject.toml README.md ./
COPY projectosint ./projectosint
RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 osint \
    && mkdir -p /data && chown -R osint:osint /data /app
USER osint

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3)"

CMD ["uvicorn", "projectosint.web.app:app", "--host", "0.0.0.0", "--port", "8080"]
