.PHONY: format

check: format
	cargo check

format:
	cargo fmt

clippy:
	cargo clippy

build-debug: format
	cargo build

run-debug: format
	cargo run

test-nocapture: format
	cargo test -- --test-threads=1 --nocapture --color=always

test: format
	cargo test -- --test-threads=1 --color=always
