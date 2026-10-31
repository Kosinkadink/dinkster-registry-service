#!/usr/bin/env bash
set -euo pipefail

# Host networking avoids veth events that interrupt browsers on the shared runner.
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
name="registry-test-postgres-$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
docker run --detach --rm --network host --name "$name" \
  --env POSTGRES_DB=dinkster_test --env POSTGRES_PASSWORD=postgres \
  postgres:16-alpine -c listen_addresses=127.0.0.1 -c port="$port" >/dev/null
trap 'docker rm --force "$name" >/dev/null' EXIT
trap 'exit 130' INT TERM

ready=false
for attempt in $(seq 1 30); do
  if docker exec "$name" pg_isready --host 127.0.0.1 --port "$port" \
    --username postgres --dbname dinkster_test >/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
if [ "$ready" != true ]; then
  docker logs "$name"
  echo "Disposable loopback PostgreSQL did not become ready" >&2
  exit 1
fi

TEST_POSTGRES_URL="postgresql+psycopg://postgres:postgres@127.0.0.1:$port/dinkster_test" \
DINKSTER_DATABASE_URL="postgresql+psycopg://postgres:postgres@127.0.0.1:$port/dinkster_test" \
  "$@"
