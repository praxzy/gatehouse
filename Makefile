.PHONY: dev api web portal audit-export-worker db-up test-db-up migrate test test-e2e check terraform-init terraform-check generate stop

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

portal:
	@bash -c 'set -a; source .env; set +a; cd examples/employee-portal; go run ./cmd/server'

audit-export-worker:
	@bash -c 'set -a; source .env; set +a; cd backend; go run ./cmd/audit-export-worker'

test: test-db-up
	@bash -c 'set -a; source .env; set +a; cd backend; go test ./...'
	@cd web && pnpm test
	@cd examples/employee-portal && go test ./...

test-e2e:
	@cd web && pnpm test:e2e

check: test-db-up
	@bash -c 'set -a; source .env; set +a; cd backend; go test ./...'
	@cd backend && go vet ./...
	@cd web && pnpm format:check
	@cd web && pnpm lint
	@cd web && pnpm typecheck
	@cd web && pnpm test
	@cd web && pnpm build
	@cd examples/employee-portal && go test ./...
	@cd examples/employee-portal && go vet ./...

terraform-init:
	@terraform -chdir=infra/terraform/modules/network-rds init -backend=false -input=false
	@terraform -chdir=infra/terraform/modules/audit-exports init -backend=false -input=false
	@terraform -chdir=infra/terraform/modules/ecs-runtime init -backend=false -input=false
	@terraform -chdir=infra/terraform/environments/dev init -backend=false -input=false
	@terraform -chdir=infra/terraform/environments/prod init -backend=false -input=false

terraform-check: terraform-init
	@terraform fmt -check -recursive infra/terraform
	@terraform -chdir=infra/terraform/modules/network-rds validate
	@terraform -chdir=infra/terraform/modules/audit-exports validate
	@terraform -chdir=infra/terraform/modules/ecs-runtime validate
	@terraform -chdir=infra/terraform/environments/dev validate
	@terraform -chdir=infra/terraform/environments/prod validate
	@terraform -chdir=infra/terraform/modules/network-rds test
	@terraform -chdir=infra/terraform/modules/audit-exports test
	@terraform -chdir=infra/terraform/modules/ecs-runtime test

generate:
	@cd backend && go tool sqlc generate

stop:
	@docker compose stop postgres postgres-test
