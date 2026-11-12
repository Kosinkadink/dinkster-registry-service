#!/bin/bash
set -euo pipefail

pids=()
cleanup() {
    trap - EXIT INT TERM
    if [ "${#pids[@]}" -gt 0 ]; then
        kill "${pids[@]}" 2>/dev/null || true
        wait "${pids[@]}" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

dinkster-registry deliver &
pids+=("$!")
dinkster-registry serve --host "${HTTP_HOST:-::}" --port "${HTTP_PORT:-8000}" &
pids+=("$!")

# An unexpected clean exit is also a failure: both services must stay alive.
set +e
wait -n "${pids[@]}"
status=$?
set -e
if [ "$status" -eq 0 ]; then
    status=1
fi
exit "$status"
