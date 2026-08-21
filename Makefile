PROJECT_NAME  ?= cashttpd
PROJECT_ORG   ?= casapps
PROJECT_IMAGE ?= casjaysdev/rust:latest
VERSION       := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

CARGO_CACHE   ?= $(HOME)/.cargo
RUSTUP_CACHE  ?= $(HOME)/.rustup
SCCACHE_CACHE ?= $(HOME)/.cache/sccache
CARGO_TARGET  ?= $(HOME)/.cache/cargo-target/$(PROJECT_NAME)

# Every cargo invocation names the musl target explicitly rather than relying
# on the toolchain image's default host target. `.cargo/config.toml` applies
# `-C target-feature=+crt-static` to the musl targets, and when the requested
# target *is* the host target cargo also applies those rustflags to host build
# artifacts — which makes proc-macro crates (`tokio-macros`, `futures-macro`,
# `thiserror-impl`, and the rest of the async stack's build-time dependencies)
# unbuildable, since a statically linked CRT cannot produce the dynamic
# library a proc-macro is. Naming the target explicitly keeps `+crt-static` on
# the shipped binary (PART 0 "Single Static Binary") while letting host-side
# proc-macros build normally.
CARGO_TARGET_TRIPLE ?= $(shell uname -m)-unknown-linux-musl

RUN           := docker run --rm \
	--name "$(PROJECT_NAME)-$$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
	-v $(PWD):/work -w /work \
	-e CARGO_BUILD_TARGET=$(CARGO_TARGET_TRIPLE) \
	-v $(CARGO_CACHE):/root/.cargo \
	-v $(RUSTUP_CACHE):/root/.rustup \
	-v $(SCCACHE_CACHE):/root/.cache/sccache \
	-v $(CARGO_TARGET):/root/.cache/cargo-target \
	$(PROJECT_IMAGE)

.PHONY: help fmt fmt-check lint test build build-release release doc run deny about clean

help:
	@echo "$(PROJECT_NAME) v$(VERSION)"
	@echo ""
	@echo "Targets:"
	@echo "  fmt            Format code"
	@echo "  fmt-check      Check formatting"
	@echo "  lint           Run clippy"
	@echo "  test           Run cargo fmt --check and cargo test"
	@echo "  build          Build debug binary"
	@echo "  build-release  Build release binary"
	@echo "  release        Alias for build-release"
	@echo "  doc            Build documentation"
	@echo "  run            Run the server locally"
	@echo "  deny           Run cargo deny checks"
	@echo "  about          Generate LICENSE.generated.md"
	@echo "  clean          Clean build artifacts"

fmt:
	@mkdir -p $(CARGO_CACHE) $(RUSTUP_CACHE) $(SCCACHE_CACHE) $(CARGO_TARGET)
	$(RUN) cargo fmt --all

fmt-check:
	@mkdir -p $(CARGO_CACHE) $(RUSTUP_CACHE) $(SCCACHE_CACHE) $(CARGO_TARGET)
	$(RUN) cargo fmt --all --check

lint:
	@mkdir -p $(CARGO_CACHE) $(RUSTUP_CACHE) $(SCCACHE_CACHE) $(CARGO_TARGET)
	$(RUN) cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	@mkdir -p $(CARGO_CACHE) $(RUSTUP_CACHE) $(SCCACHE_CACHE) $(CARGO_TARGET)
	$(RUN) sh -c 'cargo fmt --all --check && cargo test --workspace --all-features'

build:
	@mkdir -p $(CARGO_CACHE) $(RUSTUP_CACHE) $(SCCACHE_CACHE) $(CARGO_TARGET)
	$(RUN) cargo build

build-release:
	@mkdir -p $(CARGO_CACHE) $(RUSTUP_CACHE) $(SCCACHE_CACHE) $(CARGO_TARGET)
	$(RUN) cargo build --release

release: build-release

doc:
	@mkdir -p $(CARGO_CACHE) $(RUSTUP_CACHE) $(SCCACHE_CACHE) $(CARGO_TARGET)
	$(RUN) cargo doc --workspace --no-deps

run:
	@mkdir -p $(CARGO_CACHE) $(RUSTUP_CACHE) $(SCCACHE_CACHE) $(CARGO_TARGET)
	docker run --rm \
		--name "$(PROJECT_NAME)-$$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
		-p 127.0.0.1:59123:59123 \
		-v $(PWD):/work -w /work \
		-v $(CARGO_CACHE):/root/.cargo \
		-v $(RUSTUP_CACHE):/root/.rustup \
		-v $(SCCACHE_CACHE):/root/.cache/sccache \
		-v $(CARGO_TARGET):/root/.cache/cargo-target \
		$(PROJECT_IMAGE) cargo run -- --listen ::1 --port 59123 --dir /work

deny:
	@mkdir -p $(CARGO_CACHE) $(RUSTUP_CACHE) $(SCCACHE_CACHE) $(CARGO_TARGET)
	$(RUN) cargo deny check licenses advisories bans sources

about:
	@mkdir -p $(CARGO_CACHE) $(RUSTUP_CACHE) $(SCCACHE_CACHE) $(CARGO_TARGET)
	$(RUN) cargo about generate about.hbs -o LICENSE.generated.md

clean:
	@mkdir -p $(CARGO_CACHE) $(RUSTUP_CACHE) $(SCCACHE_CACHE) $(CARGO_TARGET)
	$(RUN) cargo clean
