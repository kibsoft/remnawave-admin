# Reuse the tested upstream runtime; only application sources change.
FROM ghcr.io/case211/remnawave-admin-web-backend:e161aaae2409589657745d3889e851871acb9310
COPY shared/ /app/shared/
COPY web/backend/ /app/web/backend/
COPY alembic/ /app/alembic/
COPY alembic.ini /app/alembic.ini
