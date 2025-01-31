build:
	cargo build

test:
	cargo test -- --test-threads=1 --nocapture --color=always
