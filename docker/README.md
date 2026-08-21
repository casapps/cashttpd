# Docker

`cashttpd` is built and run exclusively inside Docker — never on the host
(AI.md PART 0 "No Host Toolchain or Binary Execution").

## Build the toolchain image

The toolchain image is `casjaysdev/rust:latest` — pulled directly for every
day-to-day command.

```bash
docker pull casjaysdev/rust:latest
```

`docker/Dockerfile.build` is a narrow extension of that same image (see its
header comment): it adds `cargo-about` and `cargo-cyclonedx`, which the base
image does not ship, and is used only by the CI license-compliance and SBOM
steps.

## Build the runtime image

Run from the repository root. BuildKit is required — the builder stage is
`FROM --platform=$BUILDPLATFORM`, which the legacy builder cannot parse.

```bash
DOCKER_BUILDKIT=1 docker build -f docker/Dockerfile \
  --build-arg PROJECT_ORG=casapps --build-arg PROJECT_NAME=cashttpd \
  -t cashttpd:latest .
```

## Run the server with the port published

```bash
PROJECT_NAME="$(basename "$(git rev-parse --show-toplevel)")"
PROJECT_IMAGE="cashttpd:latest"

docker run --rm \
  --name "${PROJECT_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
  -p 127.0.0.1:59123:59123 \
  -v "$PWD":/srv/www:ro \
  "$PROJECT_IMAGE" --listen ::1 --port 59123 --dir /srv/www
```

Then from the host:

```bash
curl -v http://localhost:59123/
```

## Development image

```bash
docker compose -f docker/docker-compose.dev.yml up --build
```

## Publish the runtime image

Publishing is CI-driven; there is no manual publish step. Every provider
(GitHub Actions, Gitea Actions, Forgejo Actions, GitLab CI, Jenkins) runs
the same pipeline:

- a tag push builds `docker/Dockerfile` and pushes `:latest` and
  `:{version}`, where `{version}` comes from `release.txt` when that file is
  present and from the tag name otherwise
- a push to the default branch builds `docker/Dockerfile.dev` and pushes
  `:devel`

Both are multi-arch (`linux/amd64,linux/arm64`) manifest lists built with
`docker buildx`. The Rust compile always runs natively on the build host and
cross-compiles to the target's musl triple; only the small Alpine runtime
stage is QEMU-emulated.

The registry and image name are never hardcoded — they are derived from the
provider context, so a fork publishes to the fork's own registry:
`ghcr.io/{owner}/{repo}` on GitHub, `{instance-host}/{owner}/{repo}` on
Gitea and Forgejo, `$CI_REGISTRY_IMAGE` on GitLab, and the host parsed out
of `${GIT_URL}` on Jenkins.

OCI metadata is attached as manifest annotations only — the images carry no
`LABEL` instructions.

Credentials: GitHub, Gitea, and Forgejo use the built-in job token; GitLab
uses `$CI_REGISTRY_USER` / `$CI_REGISTRY_PASSWORD`. Jenkins is the only
provider needing manual setup — define a username/password credential with
the ID `container-registry` holding a registry account and its token.

## Tests

Prefer the `tests/` scripts over running `docker/docker-compose.test.yml`
directly.
