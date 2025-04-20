.PHONY: format clippy docker-up

TEST_THREADS ?= 4

check: format clippy
	cargo check

format:
	cargo fmt

clippy:
	cargo clippy

build-debug: format
	cargo build

build-release: format
	cargo build --release

run-debug: docker-up format
	cargo run

run-release: docker-up format
	cargo run --release

test-verbose: docker-up format
	cargo test -- --test-threads=$(TEST_THREADS) --nocapture --color=always

test: docker-up format
	cargo test -- --test-threads=$(TEST_THREADS) --color=always

docker-up:
	docker-compose -f docker-compose.yml up -d

docker-down:
	docker-compose -f docker-compose.yml down
