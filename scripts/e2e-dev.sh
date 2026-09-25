#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/gatehouse-e2e.XXXXXX")"

api_pid=""
web_pid=""
portal_pid=""

cleanup() {
    exit_code=$?

    trap - EXIT INT TERM

    for process_id in "$portal_pid" "$web_pid" "$api_pid"; do
        if [[ -n "$process_id" ]]; then
            kill "$process_id" 2>/dev/null || true
        fi
    done

    for process_id in "$portal_pid" "$web_pid" "$api_pid"; do
        if [[ -n "$process_id" ]]; then
            wait "$process_id" 2>/dev/null || true
        fi
    done

    rm -r -- "$runtime_dir"
    exit "$exit_code"
}

trap cleanup EXIT INT TERM

wait_for_url() {
    name=$1
    url=$2
    process_id=$3

    for _ in {1..120}; do
        if curl --fail --silent --show-error "$url" >/dev/null 2>&1; then
            return
        fi

        if ! kill -0 "$process_id" 2>/dev/null; then
            echo "$name stopped before becoming ready"
            return 1
        fi

        sleep 0.25
    done

    echo "Timed out waiting for $name at $url"
    return 1
}

export POSTGRES_TEST_PORT="${POSTGRES_TEST_PORT:-5433}"
export DATABASE_URL="postgres://gatehouse:gatehouse_test@localhost:${POSTGRES_TEST_PORT}/gatehouse_test?sslmode=disable"

export HTTP_ADDR="127.0.0.1:8080"
export SESSION_COOKIE_SECURE="false"

export MFA_ENCRYPTION_KEY_ID="e2e-v1"
export MFA_ENCRYPTION_KEY_BASE64
MFA_ENCRYPTION_KEY_BASE64="$(openssl rand -base64 32 | tr -d '\n')"

export CSRF_HMAC_KEY_BASE64
CSRF_HMAC_KEY_BASE64="$(openssl rand -base64 32 | tr -d '\n')"

export ADMIN_ALLOWED_ORIGINS="http://localhost:5173"

export EMAIL_DELIVERY_MODE="log"
export WEB_APP_URL="http://localhost:5173"

export OIDC_ISSUER="http://localhost:5173"
export OIDC_SIGNING_KEY_ID="e2e-rs256-v1"
export OIDC_SIGNING_PRIVATE_KEY_FILE="$runtime_dir/oidc-signing-key.pem"

export EMPLOYEE_PORTAL_HTTP_ADDR="127.0.0.1:8090"
export EMPLOYEE_PORTAL_OIDC_ISSUER="http://localhost:5173"
export EMPLOYEE_PORTAL_OIDC_CLIENT_ID="ghc_e2e_employee_portal_client_00001"
export EMPLOYEE_PORTAL_OIDC_CLIENT_SECRET="ghs_e2e_employee_portal_secret_0000000000000000"
export EMPLOYEE_PORTAL_OIDC_REDIRECT_URI="http://localhost:8090/oauth/callback"
export EMPLOYEE_PORTAL_COOKIE_SECURE="false"

echo "Starting E2E PostgreSQL..."
docker compose --profile test up -d --wait postgres-test

echo "Resetting E2E database..."
docker compose exec -T postgres-test \
    psql \
    --username gatehouse \
    --dbname gatehouse_test \
    --set ON_ERROR_STOP=1 \
    --command 'DROP SCHEMA public CASCADE' \
    --command 'CREATE SCHEMA public'

echo "Applying E2E migrations..."
(
    cd backend
    go tool goose \
        -dir migrations \
        postgres \
        "$DATABASE_URL" \
        up
)

echo "Seeding Alice, Bob, roles, and Employee Portal..."
(
    cd backend
    go run ./cmd/e2e-seed
)

echo "Generating ephemeral OIDC signing key..."
openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out "$OIDC_SIGNING_PRIVATE_KEY_FILE" \
    >/dev/null 2>&1

echo "Starting Gatehouse API..."
(
    cd backend
    exec go run ./cmd/api
) &
api_pid=$!

wait_for_url \
    "Gatehouse API" \
    "http://localhost:8080/healthz" \
    "$api_pid"

echo "Starting Gatehouse web app..."
(
    cd web
    exec pnpm dev --host 127.0.0.1 --strictPort
) &
web_pid=$!

wait_for_url \
    "Gatehouse web app" \
    "http://localhost:5173/.well-known/openid-configuration" \
    "$web_pid"

echo "Starting Employee Portal..."
(
    cd examples/employee-portal
    exec go run ./cmd/server
) &
portal_pid=$!

wait_for_url \
    "Employee Portal" \
    "http://localhost:8090" \
    "$portal_pid"

echo "E2E environment is ready"
wait -n "$api_pid" "$web_pid" "$portal_pid"
