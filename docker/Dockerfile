# syntax=docker/dockerfile:1
# Production runtime image for cashttpd — two-stage build.
# Builder stage uses the maintained casjaysdev/rust:latest toolchain image;
# no docker/Dockerfile.build is used (AI.md PART 5 "Toolchain Image").

ARG PROJECT_ORG
ARG PROJECT_NAME

FROM casjaysdev/rust:latest AS builder
WORKDIR /work
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest AS runtime
ARG PROJECT_ORG
ARG PROJECT_NAME

RUN apk add --no-cache tini ca-certificates \
  && addgroup -S cashttpd \
  && adduser -S -G cashttpd cashttpd

COPY --from=builder /work/target/x86_64-unknown-linux-musl/release/cashttpd /usr/local/bin/cashttpd
COPY docker/rootfs/usr/local/bin/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/cashttpd

USER cashttpd

STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/cashttpd", "--version"]

ENTRYPOINT [ "tini", "-p", "SIGTERM", "--", "/usr/local/bin/entrypoint.sh" ]
CMD [ "cashttpd" ]
