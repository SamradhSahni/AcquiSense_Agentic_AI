# syntax=docker/dockerfile:1
FROM python:3.11-slim AS production
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    EXECUTION_MODE=deterministic \
    DEPLOY_TARGET=none

RUN groupadd -r acquisense && useradd -r -g acquisense acquisense
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY acquisense /app/acquisense
COPY app.py /app/app.py
COPY deploy.py /app/deploy.py
COPY pyproject.toml /app/pyproject.toml
COPY .env.example /app/.env.example

RUN mkdir -p /tmp/acquisense_prod_runtime && \
    chown -R acquisense:acquisense /app /tmp/acquisense_prod_runtime
USER acquisense
EXPOSE 8080
CMD ["uvicorn", "app:acquisense_cloud_app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
