set dotenv-load := true

bind := env_var_or_default("SOLAND_BIND", "127.0.0.1:8698")
database_url := env_var_or_default("DATABASE_URL", "")
local_database_url := env_var_or_default("SOLAND_LOCAL_DATABASE_URL", "postgres://soland:soland@localhost:5432/soland")
postgres_container := env_var_or_default("SOLAND_POSTGRES_CONTAINER", "soland-postgres")
postgres_image := env_var_or_default("SOLAND_POSTGRES_IMAGE", "postgres:16")
postgres_port := env_var_or_default("SOLAND_POSTGRES_PORT", "5432")
postgres_user := env_var_or_default("SOLAND_POSTGRES_USER", "soland")
postgres_password := env_var_or_default("SOLAND_POSTGRES_PASSWORD", "soland")
postgres_db := env_var_or_default("SOLAND_POSTGRES_DB", "soland")
export DATABASE_URL := database_url
export SOLAND_DEVELOPMENT_MODE := env_var_or_default("SOLAND_DEVELOPMENT_MODE", "true")
export RUST_LOG := env_var_or_default("RUST_LOG", "soland=info")

# List available recipes.
default:
    @just --list

# Create a local .env from .env.example if it does not already exist.
init-env:
    @if test -f .env; then echo ".env already exists"; else cp .env.example .env && echo "created .env"; fi

# Run soland locally. Uses DATABASE_URL from .env when set; otherwise uses memory storage.
dev:
    cargo run -- --bind {{ bind }}

# Alias for `dev`.
start: dev

# Start a local Postgres container, wait for it, then run soland against it.
dev-db: db-up db-ready
    just --set database_url "{{ local_database_url }}" dev

# Alias for `dev-db`.
start-db: dev-db

# Start the local Postgres container, creating it on first use.
db-up:
    docker start {{ postgres_container }} >/dev/null 2>&1 || docker run --name {{ postgres_container }} -e POSTGRES_USER={{ postgres_user }} -e POSTGRES_PASSWORD={{ postgres_password }} -e POSTGRES_DB={{ postgres_db }} -p {{ postgres_port }}:5432 -d {{ postgres_image }}

# Wait until the local Postgres container is accepting connections.
db-ready:
    @until docker exec {{ postgres_container }} pg_isready -U {{ postgres_user }} -d {{ postgres_db }} >/dev/null 2>&1; do sleep 1; done

# Stop the local Postgres container.
db-down:
    docker stop {{ postgres_container }}

# Follow local Postgres logs.
db-logs:
    docker logs -f {{ postgres_container }}

# Open psql inside the local Postgres container.
db-shell:
    docker exec -it {{ postgres_container }} psql -U {{ postgres_user }} -d {{ postgres_db }}

# Print the local development DATABASE_URL.
db-url:
    @echo "{{ local_database_url }}"

# Format Rust sources.
fmt:
    cargo fmt --all

# Check Rust formatting.
fmt-check:
    cargo fmt --all -- --check

# Run clippy with the repository's CI settings.
check:
    cargo clippy --all-targets --locked -- -D warnings

# Run the Rust test suite.
test:
    cargo test --locked

# Query the default health endpoint.
health:
    curl -fsS http://{{ bind }}/health
