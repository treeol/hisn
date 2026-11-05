SHELL := /bin/bash
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

# Leak suite (L1-L41, L25-L41). Needs unprivileged user namespaces: run on a real host,
# not inside a seccomp-restricted container. Never reports a pass it did not run.
# Exit non-zero on any FAIL; one line per check: L<n>[<sub>] PASS|FAIL|SKIP|WEAK — <reason>.
# The probe is built statically: it also runs inside an imported rootfs (L43/L46)
# whose libc may be older than the host's.
PROBE_TARGET := $(shell rustc -vV | sed -n 's/^host: //p')
PROBE_BIN := target/probe/$(PROBE_TARGET)/release/examples/leakprobe

leaktest: build
	RUSTFLAGS="-C target-feature=+crt-static" $(CARGO) build --release --example leakprobe --target $(PROBE_TARGET) --target-dir target/probe
	PROBE=$(CURDIR)/$(PROBE_BIN) bash tests/leak/run.sh ./target/release/hisn

# Leak suite with a log at docs/leaktest-host-YYYY-MM-DD.log. The first lines
# are a header (commit, tree state -- ignoring the log files themselves -- date, hostname, kernel, hisn version); the
# suite output follows. Exit status is the suite's (pipefail), not tee's.
leaktest-log: build
	@set -o pipefail; \
	f=docs/leaktest-host-$$(date +%F).log; \
	{ echo "# hisn leaktest host log"; \
	  echo "commit:  $$(git rev-parse HEAD)"; \
	  echo "tree:    $$(if [ -n "$$(git status --porcelain --untracked-files=no -- . ':!docs/leaktest-host-*.log')" ]; then echo dirty; else echo clean; fi)"; \
	  echo "date:    $$(date -u +%FT%TZ)"; \
	  echo "host:    $$(hostname)"; \
	  echo "kernel:  $$(uname -r)"; \
	  echo "hisn:    $$(./target/release/hisn --version)"; \
	  echo "---"; } > "$$f"; \
	$(MAKE) leaktest 2>&1 | tee -a "$$f"
