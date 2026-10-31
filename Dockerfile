# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.12.8 /uv /uvx /bin/

RUN apt-get update \
    && apt-get install --yes --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable \
    && rm -rf /root/.cache/uv

FROM python:3.12-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends bubblewrap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/.venv ./.venv
COPY alembic.ini ./
COPY migrations ./migrations
COPY fixtures ./fixtures
COPY conformance ./conformance
COPY scripts ./scripts

RUN useradd --create-home --uid 10001 dinkster \
    && mkdir --parents /data/objects \
    && chown --recursive dinkster:dinkster /data

ENV PATH="/app/.venv/bin:${PATH}" \
    DINKSTER_OBJECT_STORE_ROOT="/data/objects" \
    PYTHONUNBUFFERED=1

USER dinkster
EXPOSE 8000
VOLUME ["/data"]
CMD ["dinkster-registry", "serve", "--host", "0.0.0.0", "--port", "8000"]
