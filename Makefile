.PHONY: build test check lint leaktest

CARGO ?= cargo

build:
	$(CARGO) build --release

test:
	$(CARGO) test
	python3 tests/leak/test_l8.py

lint:
	$(CARGO) fmt --check
	$(CARGO) clippy --all-targets -- -D warnings

# Host capability report (exit 2 if a required capability is missing).
check: build
	./target/release/hisn check

# Leak suite L1-L11. Needs unprivileged user namespaces: run on a real host,
# not inside a seccomp-restricted container. Never reports a pass it did not run.
leaktest: build
	$(CARGO) build --release --example leakprobe
	bash tests/leak/run.sh ./target/release/hisn
