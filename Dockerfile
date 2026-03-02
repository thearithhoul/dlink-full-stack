FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

COPY pyproject.toml uv.lock ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    "fastapi[standard]>=0.128.0" \
    "sqlalchemy>=2.0.37" \
    "psycopg[binary]>=3.2.3" \
    "pydantic-settings>=2.7.0" \
    "sqlmodel>=0.0.32" \
    "alembic>=1.18.4" \
    "sentry-sdk>=2.50.0"

COPY src ./src

EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]

