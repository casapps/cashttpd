# Docker

`cashttpd` is built and run exclusively inside Docker — never on the host
(AI.md PART 0 "No Host Toolchain or Binary Execution").

## Build the toolchain image

The toolchain image is `casjaysdev/rust:latest` — pulled directly, never
built from a project-local `Dockerfile.build`.

```bash
docker pull casjaysdev/rust:latest
```

## Build the runtime image

```bash
docker build -f docker/Dockerfile --build-arg PROJECT_ORG=casapps \
  --build-arg PROJECT_NAME=cashttpd -t cashttpd:latest ..
```

## Run the server with the port published

```bash
docker run --rm \
  --name "cashttpd-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
  -p 127.0.0.1:59123:59123 \
  -v "$PWD":/srv/www:ro \
  cashttpd:latest --listen ::1 --port 59123 --dir /srv/www
```

Then from the host:

```bash
curl -v http://localhost:59123/
```

## Development image

```bash
docker compose -f docker/docker-compose.dev.yml up --build
```

## Tests

Prefer the `tests/` scripts over running `docker/docker-compose.test.yml`
directly.
