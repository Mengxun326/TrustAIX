FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY trustaix ./trustaix
RUN pip install --no-cache-dir ".[postgres]"

COPY config ./config

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN addgroup --system trustaix && adduser --system --ingroup trustaix trustaix \
    && mkdir /data && chown -R trustaix:trustaix /app /data
USER trustaix
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

CMD ["uvicorn", "trustaix.main:app", "--host", "0.0.0.0", "--port", "8000"]
