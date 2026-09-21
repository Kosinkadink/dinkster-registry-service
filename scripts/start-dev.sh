#!/bin/sh
set -eu

mode="${1:-all}"

prepare_database() {
    case "${DINKSTER_DATABASE_URL:-}" in
        sqlite:*) ;;
        *) alembic upgrade head ;;
    esac
    if [ "${DINKSTER_SEED_FIXTURES:-1}" = "1" ]; then
        dinkster-registry seed
    fi
}

if [ "$mode" = "serve" ]; then
    prepare_database
    exec dinkster-registry serve --host 0.0.0.0 --port 8000
fi

if [ "$mode" = "scanner" ]; then
    exec dinkster-registry scanner
fi

if [ "$mode" != "all" ]; then
    echo "usage: $0 [all|serve|scanner]" >&2
    exit 2
fi

prepare_database
dinkster-registry scanner &
scanner_pid=$!
trap 'kill "$scanner_pid" 2>/dev/null || true; wait "$scanner_pid" 2>/dev/null || true' EXIT
dinkster-registry serve --host 0.0.0.0 --port 8000
