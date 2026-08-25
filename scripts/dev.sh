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
    OIDC_ISSUER
    OIDC_SIGNING_KEY_ID
    OIDC_SIGNING_PRIVATE_KEY_FILE
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
portal_pid=""

cleanup() {
    exit_code=$?

    trap - EXIT INT TERM

    for process_id in "$api_pid" "$web_pid" "$portal_pid"; do
        if [[ -n "$process_id" ]]; then
            kill "$process_id" 2>/dev/null || true
        fi
    done

    for process_id in "$api_pid" "$web_pid" "$portal_pid"; do
        if [[ -n "$process_id" ]]; then
            wait "$process_id" 2>/dev/null || true
        fi
    done

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

process_ids=("$api_pid" "$web_pid")

if [[ -n "${EMPLOYEE_PORTAL_OIDC_CLIENT_ID:-}" &&
      -n "${EMPLOYEE_PORTAL_OIDC_CLIENT_SECRET:-}" ]]; then
    echo "Starting Employee Portal OIDC client..."
    (
        cd examples/employee-portal
        exec go run ./cmd/server
    ) &
    portal_pid=$!
    process_ids+=("$portal_pid")
fi

echo
echo "Gatehouse development environment is running."
echo "API: http://localhost:8080"
echo "Web: http://localhost:5173"
if [[ -n "$portal_pid" ]]; then
    echo "Employee Portal: http://localhost:8090"
else
    echo "Employee Portal: disabled until its client credentials are set in .env"
fi
echo "Press Ctrl+C to stop the API and web app."
echo

wait -n "${process_ids[@]}"
