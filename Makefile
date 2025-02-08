.PHONY: format clippy docker-up

check: format clippy
	cargo check

format:
	cargo fmt

clippy:
	cargo clippy

build-debug: format
	cargo build

run-debug: docker-up format
	cargo run

test-verbose: docker-up format
	cargo test -- --test-threads=1 --nocapture --color=always

test: docker-up format
	cargo test -- --test-threads=1 --color=always

docker-up:
	docker-compose -f docker-compose.yml up -d

docker-down:
	docker-compose -f docker-compose.yml down
