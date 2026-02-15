# FastAPI + SQLAlchemy + PostgreSQL

This project now includes SQLAlchemy wired into FastAPI with PostgreSQL in Docker.

## Run with Docker

```bash
docker compose up --build
```

API docs: `http://localhost:8000/swagger`

## SQLAlchemy flow in this project

1. Configure `DATABASE_URL` in `src/app/core/config.py`.
2. Create engine/session in `src/app/core/database.py`.
3. Define models in `src/app/models/`.
4. Use `get_db` dependency in routes.
5. Create tables on startup with `Base.metadata.create_all(...)`.

## Example endpoints

Create item:

```bash
curl -X POST http://localhost:8000/items \
  -H "Content-Type: application/json" \
  -d "{\"title\":\"Learn SQLAlchemy\"}"
```

List items:

```bash
curl http://localhost:8000/items
```

Toggle done:

```bash
curl -X PATCH http://localhost:8000/items/1/toggle
```
