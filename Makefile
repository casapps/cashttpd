PROJECT_NAME ?= cashttpd
IMAGE        ?= casjaysdev/rust:latest
RUN          := docker run --rm \
	--name "$(PROJECT_NAME)-$$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
	-v $(PWD):/work -w /work \
	$(IMAGE)

.PHONY: fmt fmt-check lint test build build-release doc run deny about clean

fmt:
	$(RUN) cargo fmt --all

fmt-check:
	$(RUN) cargo fmt --all --check

lint:
	$(RUN) cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	$(RUN) cargo test --workspace --all-features

build:
	$(RUN) cargo build

build-release:
	$(RUN) cargo build --release

doc:
	$(RUN) cargo doc --workspace --no-deps

run:
	docker run --rm \
		--name "$(PROJECT_NAME)-$$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
		-p 127.0.0.1:59123:59123 \
		-v $(PWD):/work -w /work \
		$(IMAGE) cargo run -- --listen ::1 --port 59123 --dir /work

deny:
	$(RUN) cargo deny check licenses advisories bans sources

about:
	$(RUN) cargo about generate about.hbs -o LICENSE.generated.md

clean:
	$(RUN) cargo clean
