FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY trustaix ./trustaix
RUN pip install --no-cache-dir .

COPY config ./config

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

CMD ["uvicorn", "trustaix.main:app", "--host", "0.0.0.0", "--port", "8000"]
