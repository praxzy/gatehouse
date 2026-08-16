#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ ! -f .env ]]; then
    echo "Missing .env. Run: cp .env.example .env"
    exit 1
fi

set -a
source .env
set +a

required_variables=(
    DATABASE_URL
    MFA_ENCRYPTION_KEY_ID
    MFA_ENCRYPTION_KEY_BASE64
    EMAIL_DELIVERY_MODE
    WEB_APP_URL
)

for variable in "${required_variables[@]}"; do
    if [[ -z "${!variable:-}" ]]; then
        echo "Missing required variable in .env: $variable"
        exit 1
    fi
done

echo "Starting development PostgreSQL..."
docker compose up -d --wait postgres

echo "Applying database migrations..."
(
    cd backend
    go tool goose -dir migrations postgres "$DATABASE_URL" up
)

api_pid=""
web_pid=""

cleanup() {
    exit_code=$?

    trap - EXIT INT TERM

    if [[ -n "$api_pid" ]]; then
        kill "$api_pid" 2>/dev/null || true
    fi

    if [[ -n "$web_pid" ]]; then
        kill "$web_pid" 2>/dev/null || true
    fi

    wait "$api_pid" "$web_pid" 2>/dev/null || true

    exit "$exit_code"
}

trap cleanup EXIT INT TERM

echo "Starting Gatehouse API..."
(
    cd backend
    exec go run ./cmd/api
) &
api_pid=$!

echo "Starting Gatehouse web app..."
(
    cd web
    exec pnpm dev
) &
web_pid=$!

echo
echo "Gatehouse development environment is running."
echo "API: http://localhost:8080"
echo "Web: http://localhost:5173"
echo "Press Ctrl+C to stop the API and web app."
echo

wait -n "$api_pid" "$web_pid"
