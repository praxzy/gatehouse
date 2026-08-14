.PHONY: dev api web db-up test-db-up migrate test check generate stop

dev:
	@./scripts/dev.sh

db-up:
	@docker compose up -d --wait postgres

test-db-up:
	@docker compose --profile test up -d --wait postgres-test

migrate: db-up
	@bash -c 'set -a; source .env; set +a; cd backend; go tool goose -dir migrations postgres "$$DATABASE_URL" up'

api: migrate
	@bash -c 'set -a; source .env; set +a; cd backend; go run ./cmd/api'

web:
	@cd web && pnpm dev

test: test-db-up
	@bash -c 'set -a; source .env; set +a; cd backend; go test ./...'
	@cd web && pnpm test

check: test-db-up
	@bash -c 'set -a; source .env; set +a; cd backend; go test ./...'
	@cd backend && go vet ./...
	@cd web && pnpm format:check
	@cd web && pnpm lint
	@cd web && pnpm typecheck
	@cd web && pnpm test
	@cd web && pnpm build

generate:
	@cd backend && go tool sqlc generate

stop:
	@docker compose stop postgres postgres-test
