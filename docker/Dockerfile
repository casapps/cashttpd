# syntax=docker/dockerfile:1
# Production runtime image for cashttpd — two-stage build.
# Builder stage uses the maintained casjaysdev/rust:latest toolchain image;
# no docker/Dockerfile.build is used (AI.md PART 5 "Toolchain Image").

ARG PROJECT_ORG
ARG PROJECT_NAME

# The builder runs under the target platform itself (QEMU-emulated for a
# foreign arch, same as the runtime stage) rather than cross-compiling: the
# casjaysdev/rust:latest image has no aarch64-linux-musl-cross linker
# installed, so `FROM --platform=$BUILDPLATFORM` + `--target
# aarch64-unknown-linux-musl` fails building `ring`'s C dependencies. Native
# per-platform build with `cargo build` (no explicit --target — musl is
# already the image's default target) keeps this correct even though it is
# slower than a genuine cross-compile.
FROM casjaysdev/rust:latest AS builder
# Build metadata (AI.md PART 6 "Build Metadata" / PART 5 "Build-Time
# Metadata Args"): the caller captures BUILD_EPOCH once and derives
# BUILD_DATE from it for the OCI-annotation build step; only BUILD_EPOCH
# and COMMIT_ID are exported here, for build.rs to embed into the binary.
ARG BUILD_EPOCH
ARG COMMIT_ID
ENV BUILD_EPOCH=${BUILD_EPOCH}
ENV COMMIT_ID=${COMMIT_ID}
WORKDIR /work
COPY . .
RUN set -eu; \
    case "$(uname -m)" in \
      x86_64) RUST_TARGET="x86_64-unknown-linux-musl" ;; \
      aarch64) RUST_TARGET="aarch64-unknown-linux-musl" ;; \
      *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;; \
    esac; \
    cargo build --release --target "${RUST_TARGET}"; \
    mkdir -p /out; \
    cp "target/${RUST_TARGET}/release/cashttpd" /out/cashttpd

FROM alpine:latest AS runtime
ARG PROJECT_ORG
ARG PROJECT_NAME

RUN apk add --no-cache tini ca-certificates

COPY --from=builder /out/cashttpd /usr/local/bin/cashttpd
COPY docker/rootfs/usr/local/bin/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/cashttpd

# No USER directive and no group/user creation here (AI.md PART 5
# "Container Runtime Rules" -> "Privilege drop, not Dockerfile users").
# The container starts as root; cashttpd itself creates its own dedicated
# user/group, sets directory permissions, then drops privileges once
# initialization completes.

STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/cashttpd", "--version"]

ENTRYPOINT [ "tini", "-p", "SIGTERM", "--", "/usr/local/bin/entrypoint.sh" ]
CMD [ "cashttpd" ]
