# cashttpd

[![CI](https://github.com/casapps/cashttpd/actions/workflows/ci.yml/badge.svg)](https://github.com/casapps/cashttpd/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/casapps/cashttpd)](https://github.com/casapps/cashttpd/releases)
[![License](https://img.shields.io/github/license/casapps/cashttpd)](LICENSE.md)

## About

`cashttpd` is a local-development HTTP/HTTPS web server — the same niche as
`php -S`, Python's `http.server`, or `busybox httpd`, but RFC-compliant and
closer to Apache `httpd` in behavior. Point it at a directory and get a real
HTTP/1.1-and-newer server with `.htaccess`/`.htpasswd` compatibility, CGI
support, multi-language script execution, and dev-framework reverse
proxying — no Apache/Nginx install or configuration required. It is a
developer convenience tool, not a production server.

## Features

- Single statically linked binary, zero configuration required to start
- RFC-compliant HTTP/1.1 (status codes, conditional/range requests, headers)
- `.htaccess` / `.htpasswd` compatibility
- CGI (`cgi-bin/`) and extension-based multi-language script execution
  (PHP, Python, Perl, Lua, Ruby, and more via the interpreter already on
  the host)
- Optional TLS with automatic certificate resolution
  (Let's Encrypt live certs → request a new one → self-signed fallback)
- Dev-framework reverse-proxying
- `/server-info` diagnostics dashboard
- TUI (foreground) and CLI-style (`--daemon`) presentation, no GUI

## Installation

Download the appropriate binary for your platform from the
[releases page](https://github.com/casapps/cashttpd/releases) and run it —
no installer, no runtime dependencies beyond the kernel.

## Usage

```bash
cashttpd --dir ./my-project
```

By default this binds to a loopback address on a random unused port in
59000–59999. See `cashttpd --help` for the full flag reference.

## TUI/CLI-style mode behavior

- Foreground on a capable terminal → TUI (default)
- `--daemon` → CLI-style output, always
- Non-interactive/piped/`TERM=dumb`/`CI` contexts → automatic CLI-style
  fallback

## Configuration

Settings resolve in this order, highest wins: CLI flag > environment
variable > per-project config (`--config {file}`) > global config >
built-in default. See `IDEA.md` → "Configuration file" for the full schema.

## Development

All toolchain commands run inside Docker — never on the host.

```bash
make fmt-check
make lint
make test
make build
```

Equivalent raw Docker invocation:

```bash
docker run --rm \
  --name "cashttpd-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
  -v "$PWD":/work -w /work \
  casjaysdev/rust:latest cargo build
```

## Testing

```bash
make test
```

Server smoke test:

```bash
docker run --rm \
  --name "cashttpd-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
  -p 127.0.0.1:59123:59123 \
  -v "$PWD":/work -w /work \
  casjaysdev/rust:latest cargo run -- --listen ::1 --port 59123 --dir /work

curl -v http://localhost:59123/
```

## License

MIT — see [LICENSE.md](LICENSE.md).
