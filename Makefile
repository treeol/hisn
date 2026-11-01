.PHONY: build test check lint leaktest leaktest-log

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

# Leak suite (L1-L23). Needs unprivileged user namespaces: run on a real host,
# not inside a seccomp-restricted container. Never reports a pass it did not run.
# Exit non-zero on any FAIL; one line per check: L<n>[<sub>] PASS|FAIL|SKIP|WEAK — <reason>.
leaktest: build
	$(CARGO) build --release --example leakprobe
	bash tests/leak/run.sh ./target/release/hisn

# Leak suite with a timestamped log tee'd to docs/leaktest-host-YYYY-MM-DD.log.
leaktest-log: leaktest
	$(MAKE) leaktest 2>&1 | tee docs/leaktest-host-$$(date +%F).log
