## Project description

`cashttpd` is a local-development HTTP/HTTPS web server — the same niche as `php -S`, Python's
`http.server`, or `busybox httpd`, but RFC-compliant and closer to Apache `httpd` in behavior.
It is aimed at developers who want a single static binary they can point at a project directory
and get a real HTTP/1.1, HTTP/2, and HTTP/3 server with `.htaccess`/`.htpasswd` compatibility, CGI support,
and multi-language script execution (PHP/Python/Perl/Lua/Ruby/etc. via the interpreter already
installed on the host) — without installing or configuring a full Apache/Nginx stack. It is not a
production server; it is a developer convenience tool for running a directory as a website during
local development.

## Project variables

    project_name:  cashttpd
    project_org:   casapps
    # FROZEN — set once at first-time setup, never edit
    internal_name: cashttpd
    # FROZEN — set once at first-time setup, never edit
    internal_org:  casapps
    app_name:      CasApps HTTPd
    crate_name:    cashttpd
    default_listen_v4: 127.0.0.1
    default_listen_v6: ::1
    default_port_range_min: 59000
    default_port_range_max: 59999

## Business logic

### App surfaces in scope

- No GUI, ever.
- TUI is the default presentation when run in the foreground (no `--daemon`) on a capable
  interactive terminal.
- `--daemon` runs the process in the background and always uses CLI-style plain output instead of
  the TUI (a backgrounded process has no interactive terminal to draw a TUI into).
- CLI-style plain output is also the automatic fallback in the foreground whenever the terminal
  isn't capable of a TUI, per the smart-detect rules (`TERM=dumb`, non-TTY, `CI=true`, `--quiet`,
  etc. — see AI.md → "Runtime Mode Selection" for the full generic trigger list).
- TUI and CLI-style output show the same underlying log content — only the presentation differs.
- `--quiet` is one of the generic CLI-style-fallback triggers (AI.md → "Smart Detect Rules") — it
  forces CLI-style output, never TUI — and additionally has a project-specific effect layered on
  top: it suppresses ongoing access/error log-line output, leaving only the startup banner; see
  "Logging".

### Core behavior

- Serves a directory tree over HTTP and HTTPS, RFC-compliant (HTTP/1.1, HTTP/2, and HTTP/3;
  conditional requests, range requests, correct status codes, correct header semantics).
- `--dir {dir}` sets the base directory to serve; defaults to `.` (current working directory).
- **The server changes its working directory to `base_dir` before anything else happens** — before
  reading any config, starting any framework child process, or handling any request — so every
  relative-path operation the process performs from that point on (config resolution, framework
  auto-detection markers, script/CGI/framework child-process working directory, relative paths in
  `.htaccess` targets, etc.) is always anchored at the same, correct directory. This runs before
  auto-detection in "Framework dev-server proxying" and before any exec in "Multi-language script
  execution."
- **All routes resolve relative to base_dir. No path traversal outside base_dir is permitted under
  any circumstances** — `..`, symlink escapes, encoded traversal sequences (`%2e%2e`, double
  encoding, etc.), and absolute-path tricks must all be rejected/normalized before touching the
  filesystem.
- `--listen {address}` sets the bind address; accepts IPv4 or IPv6. Default bind address is `::1`
  (dual-stack — also accepts IPv4 connections) when IPv6 is available on the host, else `127.0.0.1`.
- `--port {port}` sets the listen port. If omitted, a random unused port in the 59000–59999 range
  is selected at runtime. If `--port {port}` is explicitly given and that port is already in use,
  the process fails fast with a non-zero exit code and a clear error message — it must NOT silently
  fall back to a different port.
- Serves either plain HTTP or HTTPS on `--port` — never both at once, and never a redirect between
  them. Which protocol `--port` speaks is controlled by `tls.enabled` in the config file (see
  "Configuration file" below): `tls.enabled: false` (default) serves plain HTTP on `--port`;
  `tls.enabled: true` serves HTTPS on that same `--port` using the certificate resolution order
  defined below, and plain HTTP is not served at all — there is no separate HTTP listener and no
  automatic `http://` → `https://` redirect.
- **Protocol version negotiation:**
  - `tls.enabled: false` (plain HTTP on `--port`): HTTP/1.1 is always available; HTTP/2 is also
    offered via h2c (RFC 9113 §3.2, the cleartext upgrade — either the `Upgrade: h2c` request
    header or direct prior-knowledge connection preface), so HTTP/2 behavior can be exercised
    without setting up a local TLS certificate. HTTP/3 is never available without TLS — it
    requires QUIC, which mandates TLS 1.3.
  - `tls.enabled: true` (HTTPS on `--port`): HTTP/1.1 and HTTP/2 are both negotiated over the one
    TCP listener on `--port` via TLS ALPN (`http/1.1`, `h2`). HTTP/3 is additionally served over
    QUIC on a UDP listener bound to that **same** port number (TCP and UDP namespaces don't
    collide), advertised to HTTP/1.1 and HTTP/2 clients via an `Alt-Svc: h3=":{port}"` response
    header so browsers upgrade to HTTP/3 automatically. There is no separate `--http3-port` flag.
  - The client always picks the highest protocol version it and the server both support for the
    given transport (ALPN for TCP, Alt-Svc discovery for the QUIC upgrade) — this project never
    forces a specific version.
- **`{derived_name}`**: several features below (autogenerated per-project config filename,
  `--log {dir}` log filenames, generated TLS certificate storage) need a name unique to the project
  being served. That name is always derived the same way: take the full resolved (absolute,
  symlink-resolved) path of `base_dir`, replace each path separator (`/`) with `_`. E.g. a
  `base_dir` resolving to `/my/dev/server/web` derives `my_dev_server_web`. Every later reference
  to `{derived_name}` in this file means this value.
- **`{config_dir}` / `{data_dir}`**: the per-user platform-standard config and data directories
  this project reads/writes outside `base_dir` — see AI.md → PART 4 "Path Rule" for the exact
  per-OS paths (anchored on this project's frozen `internal_name`/`internal_org`). This project
  never invents its own path scheme; it always uses AI.md's standard locations.

### CLI flags (full reference)

Every flag below is also a settable key in the configuration schema (see "Configuration file"
below) except where noted as CLI-only. **Precedence for any given setting, highest wins: CLI flag
> environment variable > per-project config > global config > built-in default** (matching AI.md's
generic configuration-layering rule).

| Flag | Config key | Default | Meaning |
|------|-----------|---------|---------|
| `--dir {dir}` | `base_dir` | `.` | Directory to serve; see "Core behavior". |
| `--listen {address}` | `listen` | `::1` (or `127.0.0.1` if no IPv6) | Bind address, IPv4 or IPv6. |
| `--port {port}` | `port` | random unused port in 59000–59999 | Listen port; explicit value fails fast (non-zero exit) if in use. |
| `--fqdn {fqdn}` | `fqdn` | none | Hostname for TLS cert matching/issuance; required when `tls.enabled: true`. |
| `--log {dir}` | `log_dir` | AI.md → PART 4 "Path Rule" Logs directory | Overrides where access/error log files are written; see "Logging". |
| `--config {file}` | — (CLI-only) | autogenerated per-project path | Path to the per-project config file to load/create; see "Configuration file". |
| `--debug` | `debug` | `false` | Enables debug/tracing mode; see "Error pages and debug mode". |
| `--daemon` | — (CLI-only) | `false` | Run in background; forces CLI-style output instead of TUI; see "App surfaces in scope". |
| `--quiet` | — (CLI-only) | `false` | Forces CLI-style output (AI.md → "Smart Detect Rules") and, project-specifically, startup banner only — suppresses ongoing access/error log-line output; see "Logging". Independent of `--log {dir}`. |
| `--config-test` / `-t` | — (CLI-only) | `false` | Parses and validates the effective config, prints errors to stderr, exits 0 (valid) or 1 (invalid); never binds sockets or starts the server (AI.md → PART 14 "Signals & Lifecycle", required because this project is an RFC-compliant HTTP/1.1, HTTP/2, and HTTP/3 server). |

- Flags marked CLI-only control *how this invocation runs*, not a persisted server setting — they
  are never written into an autogenerated config file, even though `--config`/`--debug`-adjacent
  behavior interacts with config (`--debug` itself IS persisted as `debug`, since a developer would
  reasonably want debug mode to stick for a project; `--config`/`--daemon`/`--quiet` are not, since
  they describe the current process invocation, not the project).
- This table lists only project-specific flags (business logic per this file) plus `--quiet`,
  which needs a project-specific definition on top of AI.md's generic behavior. The universal
  flags every CasApps CLI tool gets (`--help`/`-h`, `--version`/`-v`, `--debug`, `--color`,
  `--licenses`/`--credits`) and the generic TUI/CLI-style mode-selection flags/triggers
  (`--daemon`, `TERM=dumb`, `NO_COLOR`, `CI`, piped output, etc.) are defined once in AI.md →
  "Standard CLI Flags" / "Runtime Mode Selection" and are not redefined here — there is no
  `--plain`/`--json` flag in this project; machine-readable output is not offered.
  not restated here.

### TLS certificate resolution

- **TLS is disabled by default** (`tls.enabled: false`) — it adds complexity (certificate
  discovery/acquisition/generation) that a plain local-dev HTTP server shouldn't pay for unless
  asked. When `tls.enabled` is false, none of the steps below run and `--port` serves plain HTTP.
- When `tls.enabled: true`, `--port` serves HTTPS on that same port (see "Core behavior" above).
- **`--fqdn {fqdn}` is required whenever `tls.enabled: true`.** The server fails fast at startup
  with a non-zero exit code and a clear error if TLS is enabled but no `{fqdn}` is set — `{fqdn}`
  is needed both to find/match the right Let's Encrypt live cert and to request or generate one.
  There is no certless/hostnameless HTTPS mode.

Given `tls.enabled: true` and a valid `{fqdn}`, certificate source is chosen automatically, in this
order, first match wins:

1. **Let's Encrypt live certs on the host**: scan `/etc/letsencrypt/live/**`, resolving symlinks
   (the `live/` entries are themselves symlinks into `archive/`) — if a cert+key matching `{fqdn}`
   there is readable and currently valid (not expired, not before its not-before date), use it.
2. **Request a new Let's Encrypt cert**: if step 1 finds nothing usable, and the effective
   `--listen` address is a valid public (routable, non-loopback, non-private) address, attempt to
   obtain a certificate from Let's Encrypt for `{fqdn}` via the ACME HTTP-01 challenge. This is
   builtin — no module, no separate tool/dependency the user has to install or configure.
   - The HTTP-01 challenge is validated by Let's Encrypt over plain HTTP on the standard port 80,
     regardless of what `--port`/`--listen` are configured to — this is a constraint of the ACME
     protocol itself (Let's Encrypt's validators only ever check port 80 for HTTP-01), not a choice
     this project makes. The server binds a **temporary** plain-HTTP listener on port 80 solely to
     serve `/.well-known/acme-challenge/{token}` for the duration of this one request, then closes
     it — this is a narrow, one-shot bootstrapping step, not a standing second listener, so it does
     not conflict with "Serves either plain HTTP or HTTPS on `--port`... never both" (see "Core
     behavior"), which governs the steady-state server, not certificate acquisition.
   - Binding port 80 requires elevated privileges on most platforms; if that bind fails (permission
     denied, port already in use), this step is treated the same as any other failure of step 2 —
     it falls through to step 3, it never fails startup outright.
   - Requests to `/.well-known/acme-challenge/**` at any other time (no cert request in flight) are
     handled as ordinary requests against `base_dir` — this project does not reserve the whole
     `/.well-known/` namespace, only the challenge path while a request is actually in progress.
3. **Self-signed fallback**: if neither of the above produces a usable certificate (listen address
   isn't public, or the Let's Encrypt request fails), generate a self-signed certificate for
   `{fqdn}` valid for 10 years.
- **Generated cert storage**: any certificate this project generates itself (self-signed, or a
  Let's Encrypt cert it obtained) is saved under `{data_dir}/certs/{derived_name}/` (see
  "Core behavior" for both placeholders). Certs found on the host under
  `/etc/letsencrypt/live/**` are used in place, never copied.
- This resolution/storage never touches `base_dir` (consistent with the never-writes-into-
  served-dirs rule).

### Configuration file (`--config {file}`)

- `--config {file}` points at a per-server config file that holds the actual server setup — at
  minimum `listen`, `port`, `log_dir`, `base_dir`, and any other flag-equivalent setting — so a
  user gets the same setup every time without having to repeat CLI flags.
- If a matching per-project config does not yet exist, it is **autogenerated on first run** from
  whatever settings were actually used for that run (CLI flags and/or defaults).
- **Naming convention**: uses `{derived_name}` (see "Core behavior"), stored at
  `{config_dir}/projects/{derived_name}.yaml` (or `.yml`). Example: a `base_dir` resolving to
  `/my/dev/server/web` produces `{config_dir}/projects/my_dev_server_web.yaml`.
- There are two config layers: a **global** YAML config (defaults shared across every served
  project) and the **per-project** YAML config described above. Per-project settings always take
  precedence — any setting present in the per-project config overwrites the same setting from the
  global config. The global config only fills in values the per-project config doesn't set.
- The server (the binary itself) is responsible for ensuring every config/log directory and file
  it needs — `{config_dir}`, `{config_dir}/projects/`, the global config file, and any
  autogenerated per-project config file — exists and is created with proper permissions if
  missing. This never touches `base_dir` (consistent with the never-writes-into-served-dirs rule).
- **Live reload**: both the global config file and the active per-project config file are watched
  for changes while the server is running. A saved change takes effect immediately, without
  requiring a restart — including settings such as `tls.enabled`, `directory_listing`, and log
  format overrides. A change that requires rebinding the listener (e.g. `listen`/`port` changing
  while running, or `tls.enabled` flipping) re-binds the listener without dropping the process;
  a change that cannot be applied live (if any) is logged as a warning rather than silently
  ignored or crashing the server.

**Full schema** (every key optional; unset keys fall through global → built-in default, per the
precedence rule above). `base_dir` is meaningful only in a per-project config — the global config
has no single `base_dir` since it applies across every project.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `base_dir` | path | `.` | Same as `--dir`. Per-project config only. |
| `listen` | string | `::1` / `127.0.0.1` | Same as `--listen`. |
| `port` | integer | random 59000–59999 | Same as `--port`. |
| `log_dir` | path | AI.md → PART 4 "Path Rule" Logs directory | Same as `--log`; overrides the default platform log location only, never disables file logging. |
| `debug` | bool | `false` | Same as `--debug`. |
| `fqdn` | string | none | Same as `--fqdn`; required when `tls.enabled: true`. |
| `tls.enabled` | bool | `false` | Enables HTTPS on `port` per "TLS certificate resolution". |
| `directory_listing` | bool | `false` | Enables auto-generated directory listings when no index file is found; see "Default index and directory listing". |
| `mime_types` | map\<extension, content-type\> | `{}` | Overrides the built-in `Content-Type` for specific extensions only — not a way to add new extensions; see "MIME types". |
| `script_handlers` | map\<extension, interpreter command\> | built-in table (php-cgi/python3/perl/lua/ruby) | Merges with the built-in extension → interpreter table: overrides a built-in extension, adds a new one, or (empty/`null` value) disables a built-in one; see "Multi-language script execution". |
| `ssi_extensions` | list\<extension\> | `[".shtml"]` | Extensions that get Server-Side Includes processing; empty list disables SSI entirely; see "Server-Side Includes (SSI)". |
| `security_headers` | map\<header name, value\> | built-in defaults (see "Default security headers") | Overrides/adds/removes (empty/`null` value) a default security response header; see "Default security headers". |
| `server_tokens` | enum: `Full` \| `OS` \| `Minor` \| `Major` \| `Min` \| `Prod` | `Full` | Controls the `Server` response header's verbosity, matching Apache's `ServerTokens` option set; see "Default security headers". |
| `cors` | map\<header name, value\> \| `false` | permissive default (see "Default security headers") | Overrides/replaces the default CORS response headers, or `false` to disable CORS headers entirely; see "Default security headers". |
| `proxy.enabled` | bool | auto-detected | Explicitly enable/disable framework proxying; see "Framework dev-server proxying". |
| `proxy.type` | string | auto-detected | Built-in framework profile to use (`node`, `bun`, `deno`, `rails`, `django`, `vite`, etc.). |
| `proxy.command` | string | profile default | Custom command to start the framework dev server, overriding the profile default. |
| `proxy.upstream` | string | profile default/detected | Upstream address to proxy to. |
| `proxy.path_prefix` | string | `/` | Path prefix routed to the framework; see "Framework dev-server proxying". |
| `logging.access.format` | string | `combined` (Apache combined) | Access log line format; see "Logging". |
| `logging.access.rotate` | string | `daily` | Access log rotation schedule (AI.md rotate vocabulary); see "Logging" → "Log rotation and retention". |
| `logging.access.keep` | string | `30d` | Access log retention (AI.md keep vocabulary); see "Logging" → "Log rotation and retention". |
| `logging.error.format` | string | `standard` (Apache-style error log) | Error log line format; see "Logging". |
| `logging.error.rotate` | string | `daily` | Error log rotation schedule (AI.md rotate vocabulary); see "Logging" → "Log rotation and retention". |
| `logging.error.keep` | string | `30d` | Error log retention (AI.md keep vocabulary); see "Logging" → "Log rotation and retention". |

- Nested keys (`tls.enabled`, `proxy.*`, `logging.*`) follow standard YAML nesting
  (`tls:\n  enabled: true`), not literal dotted keys in the file.
- Any key not listed here that a future revision of this project needs is added to this table when
  it's introduced — the config schema is not open-ended/undocumented.

### MIME types

- Every standard/registered MIME type (the full IANA media type registry, not a hand-picked
  subset) is fully supported for both detection and response behavior — this is not limited to a
  handful of common web extensions.
- The server sets the correct `Content-Type` (including `charset` for text types) for every served
  file based on its detected type, and behaves appropriately for that type where HTTP semantics
  differ by type (e.g. text types are eligible for compression; binary types are served as-is;
  types are never misreported as `application/octet-stream` when a real type is known).
- Unknown/undetectable file types fall back to `application/octet-stream` rather than guessing.
- The built-in table (full IANA registry) is the only source of MIME mappings — there is no
  separate "add a new extension" mechanism. The `mime_types` config key (global or per-project)
  exists strictly to **override the built-in `Content-Type` the server would otherwise return for
  a given extension**, for the rare case where a project needs a specific extension served as
  something other than the server's built-in default. Any extension not listed in `mime_types`
  uses the built-in table's result unchanged.

### Response compression

- Builtin, always on — no config toggle, no module to enable, matching this project's "everything
  is builtin, there is no module system" model (see "Constraints / non-negotiables").
- Negotiated per request via the standard `Accept-Encoding` request header; the server picks the
  best encoding the client advertises, in this preference order: `br` (Brotli), then `gzip`. If the
  client advertises neither, the response is sent uncompressed — never forced.
- Only MIME types classified as compressible in the built-in MIME table (text types — HTML, CSS,
  JS, JSON, XML, SVG, plain text, and similar — see "MIME types") are eligible. Already-compressed
  binary types (images, video, audio, archives, fonts) are always served as-is, uncompressed,
  regardless of what the client advertises — compressing already-compressed data wastes CPU for no
  size benefit and is not how a real server behaves either.
- A successful compressed response always sets `Content-Encoding` to the chosen encoding and adds
  `Vary: Accept-Encoding` so caches don't serve the wrong encoding to a different client.
- Range requests (see "Core behavior") are never combined with compression on the same response —
  a `Range` request always gets an uncompressed, byte-accurate response, matching standard server
  behavior (compression changes byte offsets, so the two are mutually exclusive).
- CGI/script/proxied responses are compressed the same way as static file responses whenever their
  declared `Content-Type` is eligible and they don't already set their own `Content-Encoding`.

### Default index and directory listing

- **Index resolution**: when a request resolves to a directory, the server looks for a default
  index file (`index.html`, `index.htm`, and any equivalents `.htaccess`'s `DirectoryIndex`
  configures — see the `.htaccess` section) and serves it if present, same as Apache's default
  behavior.
- **Directory listing**: if no index file is found, the server does NOT show a directory listing
  by default — it returns the same "no index" outcome Apache does with directory listing off
  (403, unless `.htaccess`/config says otherwise).
- Directory listing can be turned on via the config file (global or per-project — global sets the
  default, per-project overrides it, following the same precedence rule as the rest of the config
  system). When enabled, an unresolved directory request without an index file gets an
  auto-generated listing of that directory's contents instead of a 403.
- Auto-generated directory listings must respect the same trust boundaries as everything else:
  never list or link outside `base_dir`, never list or reveal `.htaccess`/`.htpasswd` as
  navigable entries, and (per PART on error pages) should be legible/mobile-first, not a bare
  `<pre>` dump.

### `.htaccess` / `.htpasswd` compatibility

Behavior must match Apache `httpd` — same directive set, same discovery scope, same per-request
merge/evaluation order — not just an approximation. This project effectively runs as if Apache's
`AllowOverride All` were set everywhere under `base_dir`: any directory may carry its own
`.htaccess`/`.htpasswd`, with no server-level restriction on what a `.htaccess` is allowed to
configure (there is no `httpd.conf` in this project to impose one).

**Discovery scope**: every directory anywhere under `base_dir` may have its own `.htaccess` and/or
`.htpasswd` — recursively, arbitrarily deep (`base_dir/**/.htaccess`, `base_dir/**/.htpasswd`), not
just top-level. This includes `base_dir/.htaccess` itself.

**Cascade order (root-most to most-specific, same as Apache)**: for a request resolving to a file
or directory at some path under `base_dir`, the server reads the `.htaccess` in `base_dir`, then in
each path segment's directory moving toward the resource, ending with the `.htaccess` in the
resource's own containing directory. Directives merge in that order: a directive set closer to the
resource overrides/extends the same directive set further up, exactly as Apache merges per-
directory context — a subdirectory's `.htaccess` is layered on top of, not a replacement for, its
parents' directives.

**Directives supported (at minimum), matching Apache semantics for each**:
- **Authentication** (`mod_auth_basic`/`mod_authn_file`-equivalent): `AuthType Basic`,
  `AuthName`, `AuthUserFile` (pointing at a `.htpasswd`), `AuthGroupFile`.
- **Authorization**: `Require valid-user`, `Require user {name} [...]`, `Require group {name}
  [...]`, plus the legacy `Order allow,deny` / `Order deny,allow` with `Allow from` / `Deny from`
  (host/IP/CIDR), evaluated with Apache's classic-syntax precedence rules.
- **Error documents**: `ErrorDocument {code} {target}` (local path or absolute URL), per the
  "Error pages and debug mode" section above — a matching `ErrorDocument` always wins over the
  embedded default for requests under that directory's scope.
- **Directory index**: `DirectoryIndex {file1} {file2} ...`, checked in the listed order, per the
  "Default index and directory listing" section above.
- **Options**: at minimum `Indexes` (enable/disable directory listing for that scope — merges with,
  and can override, the config-file `directory_listing` setting for that directory subtree) and
  `FollowSymLinks` (whether symlinks under that directory are resolved/served at all — default-deny
  posture still applies: a followed symlink can never resolve outside `base_dir`, this option only
  controls whether symlinks are followed inside `base_dir` at all).
- **Rewrite/redirect**: `RewriteEngine`, `RewriteCond`, `RewriteRule` (`mod_rewrite` semantics —
  pattern matching, flags such as `[R]`, `[L]`, `[NC]`), and `Redirect` / `RedirectMatch`
  (`mod_alias` semantics) for simple path-to-path or path-to-URL redirects.

**Per-request evaluation order (matching Apache's phase order)**:
1. Rewrite/redirect rules (`mod_rewrite`/`mod_alias`) are applied first — they can change which
   path/resource the rest of the phases below evaluate.
2. Access control (`Order`/`Allow`/`Deny`) is evaluated against the (possibly rewritten) target.
3. Authentication (`AuthType`/`AuthUserFile`) runs next if the scope requires it — invalid/missing
   credentials short-circuit here with `401`.
4. Authorization (`Require valid-user`/`Require user`/`Require group`) runs after successful
   authentication — a valid user who doesn't satisfy the requirement gets `403`.
5. If the resolved target is a directory: `DirectoryIndex` resolution runs, falling through to
   directory listing (only if `Indexes`/`directory_listing` allows it) or `403` per the "Default
   index and directory listing" section.
6. If any phase above (or the content handler itself, e.g. a CGI/script failure) produces an
   error status, `ErrorDocument` mapping for that scope applies before falling back to the
   embedded default error page.

**`.htpasswd` file format support**: must read every password hash format Apache's `htpasswd` tool
produces — bcrypt, and at minimum legacy MD5-crypt (`apr1`) and SHA1 (`{SHA}`) for reading existing
files — never require a user to regenerate an existing `.htpasswd` to make it work with this
server.

**Trust boundary (non-negotiable)**: `.htaccess` and `.htpasswd` files themselves must never be
servable as static content, at any depth under `base_dir` — the same default-deny rule Apache
applies to dotfiles matching `.ht*`. This holds regardless of any `.htaccess`/config setting; it
cannot be turned off from within a `.htaccess` file.

### Error pages and debug mode

- Default error pages for every standard HTTP status code the server returns (4xx/5xx at minimum)
  are embedded in the binary — no dependency on any file existing in `base_dir` to render an error.
  This follows the same self-contained-assets rule as the rest of the binary and the
  never-writes-into-served-dirs rule: default error pages are never read from or written into
  `base_dir`.
- Default error pages MUST be **mobile-first responsive design** and **visually polished ("pretty"),
  not a bare text dump** — legible on a phone-width viewport first, scaling up cleanly to desktop.
- Default error pages MUST be **informative**: at minimum, the numeric status code, the standard
  reason phrase, the request method and path, and (for 5xx) a short human-readable explanation of
  what went wrong. Exactly which additional detail is safe to show is governed by `--debug` below.
- `.htaccess`'s `ErrorDocument` directive (see below) overrides the embedded default for the
  directory scope it applies to — a custom error document, when present, always wins over the
  embedded default.
- **`--debug` flag**: enables debug/tracing mode. This is off by default.
  - When `--debug` is NOT set (default): error pages never include interpreter/script stack traces,
    file paths, or other internal detail beyond the informative summary above — this is a trust
    boundary (untrusted HTTP clients must not learn internal implementation detail from a normal
    run).
  - When `--debug` IS set: the server forwards {lang} script/CGI errors and stack traces (PHP,
    Python, Perl, Lua, Ruby, etc. interpreter errors, and CGI subprocess failures) into the
    rendered error page, so a developer can see exactly what failed and why, in addition to
    whatever additional request tracing/logging `--debug` enables generally.
  - `--debug` is a local development convenience switch, not a production mode — it must never be
    implied by default and must always be an explicit, visible opt-in.

### Multi-language script execution

**Two execution paths, matching Apache's two conventions:**

1. **`cgi-bin/` (Apache `ScriptAlias`-equivalent)**: if a `cgi-bin` directory exists under
   `base_dir` (or a configured alias location), every file under it is treated as a CGI executable
   and run — regardless of extension — never served as static content. The file must be marked
   executable and either have a shebang (`#!/usr/bin/env python3`, etc.) that the OS can exec
   directly, or be a compiled/native executable. This matches Apache's classic `cgi-bin`
   behavior exactly.
2. **Extension-based auto-execution (Apache `AddHandler`/`mod_php`-equivalent, and the behavior
   users expect from `php -S`/`python -m http.server`-style tools)**: anywhere else under
   `base_dir`, a request for a file whose extension is a recognized scripting-language extension
   (per `script_handlers`, built-in or configured) is executed via that language's interpreter
   rather than served as static source code. Files with unrecognized/no extension are served as
   static content as normal.

**Scripts do not need to live under `cgi-bin/` to be executed.** Path 2 above works anywhere
under `base_dir` for any recognized extension — `cgi-bin/` (path 1) is not a prerequisite for CGI
execution, it's a separate, Apache-compatible convention for a different case (see comparison
below). A project can have zero `.htaccess`, no `cgi-bin/` directory at all, and still get full
`.php`/`.py`/etc. execution anywhere in the tree purely from the extension table — matching what a
developer expects from `php -S`/`python -m http.server`-style tools.

| | `cgi-bin/` (path 1) | Extension-based (path 2) |
|---|---|---|
| Where it applies | Only inside `cgi-bin/` (or configured alias) | Anywhere else under `base_dir` |
| What triggers execution | Any file in that directory, any extension | File extension matches a `script_handlers` entry |
| Executable bit required | Yes — the OS execs the file directly | No — the server invokes the mapped interpreter command itself |
| Shebang required | Yes | No — `script_handlers` supplies the command; the script is passed as an argument, not exec'd itself |
| Interpreter source | Whatever the file's own shebang/native binary is | The matching `script_handlers` command |
| CGI 1.1 protocol (env vars, stdin/stdout) | Yes | Yes — identical protocol either way |

- **Precedence when both could apply**: a file physically located inside `cgi-bin/` is always
  handled by path 1 (location wins) — even if it also has a recognized extension like `.php`, it
  must be independently executable with its own shebang; it is never dispatched through
  `script_handlers` while inside `cgi-bin/`. Outside `cgi-bin/`, only path 2 (extension table)
  ever applies — an executable file with a shebang but an unrecognized extension is just served as
  static content, since executable-bit/shebang is not, by itself, a trigger outside `cgi-bin/`.

**`script_handlers` config key** — the extension → interpreter mapping that drives execution path
2 above (never path 1, `cgi-bin/`, which always execs by shebang/executable-bit regardless of
extension and ignores `script_handlers` entirely).

- **Built-in table** (always present, no config needed to get standard behavior):

  | Extension | Default interpreter command |
  |-----------|------------------------------|
  | `.php` | `php-cgi` |
  | `.py` | `python3` |
  | `.pl` | `perl` |
  | `.lua` | `lua` |
  | `.rb` | `ruby` |
  | `.cgi` | *(exec directly — treated like a one-off `cgi-bin/` file: requires its own executable bit + shebang/native binary, no interpreter command)* |

  The `.cgi` row is the one built-in entry that behaves like path 1 rather than path 2 — it lets a
  single script anywhere under `base_dir` opt into "exec me directly" behavior by extension alone,
  without needing a whole `cgi-bin/` directory. Every other built-in/custom extension in this table
  is dispatched through its interpreter command (path 2 proper).

  Unlike `mime_types`/the IANA registry, this table is **not** a closed, complete standard — new
  scripting languages and extensions exist outside any fixed registry, so `script_handlers`
  supports both overriding a built-in entry and adding an entirely new one, unlike the
  override-only `mime_types` key.
- **Overriding a built-in entry**: setting `script_handlers.py: "/opt/venv/bin/python3"` (for
  example) replaces the command used for `.py` project-wide (or globally), without needing to
  touch `PATH` — useful for pinning a specific interpreter version or a virtualenv/version-manager
  binary.
- **Adding a new mapping**: setting `script_handlers.ts: "ts-node"` (for example) makes `.ts`
  files under `base_dir` auto-execute via `ts-node`, the same as any built-in extension — there is
  no distinction in behavior between a built-in and a config-added entry once resolved.
- **Disabling a built-in mapping**: setting a built-in extension's value to an empty string/`null`
  in config removes it from auto-execution — matching files are then served as static content
  instead (e.g. a project that wants `.pl` files downloadable as plain text rather than executed).
- **Value format**: a command string — first token is the interpreter binary (resolved via `PATH`
  unless given as an absolute path), any remaining tokens are fixed arguments always prepended
  before the script path when invoking (e.g. `"python3 -u"` for unbuffered output). The reserved
  value `exec` (same behavior as the built-in `.cgi` entry) opts a custom extension into
  exec-directly mode instead of an interpreter command — the matching file must be independently
  executable with its own shebang/native binary, exactly like a `cgi-bin/` file.
- **Resolution/precedence**: same as the rest of the config system — CLI has no per-extension flag
  for this, so it's environment variable > per-project config > global config > built-in table,
  merged key-by-key (not wholesale replacement: setting one extension in config doesn't drop the
  built-in entries for every other extension).
- **Missing interpreter behavior is unchanged by source**: whether an extension's handler came
  from the built-in table or from `script_handlers` config, a command whose binary can't be found
  produces the same `503 Service Unavailable` / `{lang} is not installed` response defined above —
  `{lang}` is filled in from the configured/extension name either way.

**Interpreter discovery**: at request time, the server looks up the interpreter binary for the
target language on the host (`$PATH`, or an explicit interpreter path from config). Discovery
happens per-request (not just once at startup), so installing/removing an interpreter while the
server is running takes effect on the next request without a restart.

- **Interpreter binary not found at all**: respond `503 Service Unavailable` with a body/error
  message stating `{lang} is not installed` (`{lang}` filled in, e.g. `python3 is not installed`).
  This status is reserved strictly for "the interpreter itself is missing" — it is a server-level
  condition, not a script-level one.
- **Interpreter found, script runs, but the language/script itself errors** (syntax error,
  uncaught exception, missing language module/extension such as a PHP extension not being
  installed, a Python `ImportError`, etc.): this is expected, normal operation, not a server
  fault. The server executes the script and returns whatever the interpreter actually produced —
  it does not detect, intercept, or re-map language-level errors into a different status code.
  Whether that appears to the client as the language's own error page/text, a raw traceback, or a
  partial response depends entirely on the language and script, exactly as it would running that
  same script under a real Apache/PHP-FPM/mod_wsgi setup.

**CGI 1.1 protocol semantics** (applies to both execution paths):
- Standard CGI environment variables are set for every execution: `REQUEST_METHOD`,
  `QUERY_STRING`, `CONTENT_TYPE`, `CONTENT_LENGTH`, `SCRIPT_NAME`, `SCRIPT_FILENAME`, `PATH_INFO`,
  `PATH_TRANSLATED`, `SERVER_NAME`, `SERVER_PORT`, `SERVER_PROTOCOL`, `SERVER_SOFTWARE`,
  `GATEWAY_INTERFACE`, `REMOTE_ADDR`, `REMOTE_PORT`, `DOCUMENT_ROOT` (`base_dir`), `HTTPS` (set
  when `tls.enabled`), and one `HTTP_{HEADER_NAME}` variable per incoming request header.
- Request body (for methods that carry one, e.g. `POST`/`PUT`) is streamed to the script's stdin
  exactly as CGI 1.1 specifies; the script's stdout is parsed as CGI output — response headers
  first (blank-line-terminated), then body — falling back to `Content-Type: text/html` and
  `200 OK` if the script emits a body with no header block at all.
- The script's working directory is set to the directory containing the script (matching Apache's
  CGI convention), and its `argv`/query-string handling follows the same CGI 1.1 rules.
- No execution timeout — see "No artificial resource limits" in the Security section. A hung
  script just hangs that request; it never crashes or blocks the rest of the server.

**Debug/error forwarding** (see "Error pages and debug mode" above): whatever the script itself
writes to its own stdout (its own error output/page) is always shown to the client — that's the
script's own choice, not something this server filters. What `--debug` additionally controls is
whether the *server's own* view into the failure — interpreter stderr, non-zero exit status
detail, internal stack trace of the exec attempt itself — is also surfaced into the rendered error
page when the script produces no usable output at all (e.g. it crashes before writing anything).

### Server-Side Includes (SSI)

- Builtin, matching `mod_include`'s classic directive set — no module to enable, per this
  project's "everything is builtin" model (see "Constraints / non-negotiables").
- Applies to files served with extension `.shtml` by default; the `ssi_extensions` config key
  (global or per-project, a list of extensions) adds more extensions to the set that get SSI
  processing — empty list disables SSI entirely for a project.
- Supported directives: `#include virtual="..."` (path relative to `base_dir`, subject to the same
  path-traversal containment as every other request) and `#include file="..."` (path relative to
  the including file's own directory); `#echo var="..."` for the standard CGI environment variables
  (see "CGI 1.1 protocol semantics" above) plus the SSI-standard `DATE_LOCAL`/`DATE_GMT`/
  `LAST_MODIFIED`; `#set var="..." value="..."` and `#if`/`#elif`/`#else`/`#endif` conditionals over
  those variables — matching Apache's core SSI directive set closely enough that existing
  `.shtml` files from an Apache-oriented project work unmodified.
- `#exec cmd="..."` / `#exec cgi="..."` (arbitrary shell/CGI execution from within SSI) are
  intentionally **not** supported — Apache itself disables this by default (`IncludesNOEXEC`) for
  the same reason: unrestricted shell exec from template content is a well-known injection vector,
  and there is no config knob to turn it on. This is a deliberate security decision, not a gap —
  see "Security / access control model."
- An SSI-processed response is served with `Content-Type: text/html` (matching Apache's
  `AddOutputFilter INCLUDES` behavior) and is eligible for "Response compression" like any other
  compressible text response, applied after SSI processing completes.
- SSI processing failures (missing `#include` target, malformed directive) render inline as an
  HTML comment error marker in the output, matching Apache's default `[an error occurred while
  processing this directive]` behavior — they do not abort the whole response or change the status
  code, matching how a real SSI-capable server degrades.

### Framework dev-server proxying

Supports running as a front end for real framework dev servers — Node.js, Bun, Deno, Ruby on
Rails, Python frameworks (Django/Flask/FastAPI/etc.), Vue/Vite/webpack-dev-server, and similar —
rather than serving `base_dir` as flat files, when that's what the project actually is.

- **Auto-detection (default, zero-config)**: the server inspects `base_dir` for known project
  markers (`package.json` with a dev/start script, `Gemfile` + `config.ru`, `manage.py`,
  `pyproject.toml`/`requirements.txt` with a known framework, etc.), matches it to a built-in
  framework profile, and if matched, starts that framework's own dev server as a child process and
  proxies matching requests to it instead of serving files directly.
- **Config override**: the config file (global or per-project, same precedence as elsewhere) can
  set an explicit `type` (which built-in framework profile to use — e.g. `node`, `bun`, `deno`,
  `rails`, `django`, `vite`, etc.), a fully custom `command` to execute in place of that profile's
  default command, an `upstream` address, and a `path_prefix` for proxying — any of which override
  the corresponding auto-detected value. Setting `type` alone reuses that profile's built-in
  command/upstream defaults; setting `command` overrides only the execution command while still
  using the given/detected `type`'s upstream-detection behavior unless `upstream` is also set.
  Proxying can also be explicitly disabled for that project so it's always served as flat files
  regardless of what markers are present.
- **Path scoping**: proxying applies to whatever `path_prefix` the profile/config defines (`/` for
  a full SPA/framework front end, or a narrower prefix like `/api` when only part of the tree is
  framework-backed) — requests outside that prefix are still served/executed by cashttpd itself
  (static files, CGI, scripts) under all the same rules defined elsewhere in this file.
- **Process/PID management**: cashttpd tracks the PID of every framework child process it starts.
  When cashttpd itself is stopped (normal shutdown, `--daemon` stop, or killed via a terminating
  signal), it stops every child process it started — no orphaned framework processes left running
  after cashttpd exits, under any exit path.
- **Startup / not-ready handling**: while the framework child process is starting and its upstream
  isn't reachable yet, requests to the proxied path immediately get a lightweight embedded
  "framework is starting…" page (auto-refreshing) rather than the connection being held open —
  the client's own reload picks up the real response once the upstream becomes reachable. This
  page follows the same mobile-first/pretty/informative rules as the other embedded pages (see
  "Error pages and debug mode").
- **Error handling/forwarding**: once proxying, an error from the upstream framework (connection
  reset, non-2xx response, upstream process crash) is forwarded to the client the same way a
  script/CGI error is — the upstream's own response/output is relayed as-is; `--debug` additionally
  surfaces cashttpd's own view of the failure (e.g. "upstream process exited with code 1") when the
  upstream produced no usable response at all, consistent with "Multi-language script execution"
  above.
- **No proxy limits.** Same "No artificial resource limits" policy as CGI/scripts (see the
  Security section) applies identically to proxied requests: no response/idle timeout on a
  proxied request, no body/header size caps, no rate limiting/connection caps beyond the OS — a
  slow hot-recompile or long-running upstream request is never cut short by cashttpd. The only
  timing-related behavior in this section is the startup-readiness probe above (deciding whether
  to show the "starting…" page or proxy the request), which is a liveness check for routing, not
  a cap on how long a request may take once the upstream is reachable. The child process and its
  proxy connections are expected to run for the full lifetime of the cashttpd session.
- **Request fidelity — the upstream framework must receive a faithful, complete copy of the
  original client request, not a reconstructed/lossy one:**
  - **Method, path, and query string** are forwarded exactly as the client sent them (after the
    same canonicalization/trust-boundary rules as any other request — see "Security"), including
    query strings the framework itself is responsible for parsing.
  - **All request headers** are forwarded, not a curated subset — including custom/non-standard
    headers a frontend framework's dev tooling relies on (HMR/websocket upgrade headers, custom
    auth headers, `Cookie`, `Content-Type`, `Accept`, conditional-request headers, etc.). The
    `Host` header is forwarded as sent by the client (frameworks that generate absolute URLs or
    do host-based routing depend on seeing the real requested host).
  - **Standard proxy-identification headers are added** (never silently omitted), so the
    framework can see the original client identity/protocol even though the TCP connection it
    sees is from cashttpd: original client IP/address chain and the original request protocol
    (HTTP vs HTTPS) are always communicated to the upstream via the conventional forwarding
    headers, appending to (never overwriting) any such header already present from a further
    upstream hop.
  - **Request body is forwarded byte-for-byte and streamed**, not buffered-then-replayed where
    avoidable — large uploads, chunked-encoded bodies, and streaming request bodies (e.g. a file
    upload to a framework dev API) all reach the upstream as the client sent them.
  - **WebSocket / `Upgrade` connections are supported end-to-end** — this matters concretely for
    framework dev-server hot-module-reload (HMR) sockets (Vite, webpack-dev-server, etc.), which
    silently break if the proxy doesn't forward the upgrade handshake and then relay the raw
    bidirectional stream afterward.
  - **The upstream's response is relayed back equally faithfully**: status code, all response
    headers, and body (streamed, not buffered) are returned to the client as the upstream framework
    produced them — cashttpd does not rewrite, strip, or reinterpret them beyond what's already
    described in "Error handling/forwarding" above.

### `/server-info` diagnostics dashboard

A built-in route, `/server-info`, gives a developer a live view of the server and the project it's
serving — combining a Traefik/Caddy-admin/Apache-`server-status`-style overview with active error
diagnostics, so problems are visible without digging through log files.

- **Overview**: current config in effect (listen/port/tls/base_dir/proxy target), request/response
  stats (see "Request/response stats tracking" below), (when framework proxying is active) the
  proxied child process's status and PID, and the current best-effort-sandboxing/child-lifecycle-
  protection posture for this platform (see "Sandboxing" and "Child process lifecycle" — the same
  active/unavailable indicator described there surfaces here).
- **Request/response stats tracking**:
  - **Totals since start**: total requests served, broken down by HTTP method, by response status
    code (both the exact code and the 2xx/3xx/4xx/5xx class), and by handler type (static file,
    directory listing, script/CGI, `cgi-bin/`, framework proxy, `.htaccess`-denied).
  - **Throughput**: total bytes sent (response bodies) and total bytes received (request bodies),
    plus a live current-rate figure (requests/sec) derived from a short rolling window — not a
    stored history of every request's timestamp.
  - **Latency**: response-time distribution (min/average/max, plus a rough percentile view such as
    p50/p95) tracked per handler type, since a static file, a CGI script, and a proxied framework
    request have meaningfully different expected latencies and lumping them together would hide
    that.
  - **Concurrency**: current in-flight/active request count and, when framework proxying is
    active, active upstream connections.
  - **Hot paths**: a top-N most-requested-paths view, and a top-N most-error-prone-paths view,
    each cross-referencing into the error/issue list above where applicable.
  - **Uptime**: process start time and elapsed uptime for the current run.
  - **Scope and lifecycle**: stats are aggregate counters for *this* cashttpd process/project, not
    a full per-request record — the access log remains the authoritative per-request record, and
    stats never substitute for it. Stats are in-memory only and reset to zero on every restart,
    consistent with "no persisted state across restarts" elsewhere in this spec — there is no
    historical/cross-run stats view.
  - **Trust boundary**: aggregate counts and paths only — never request bodies, header values,
    cookies, or credentials, matching the same trust-boundary posture as the rest of
    `/server-info`.
- **Error/issue list — what counts as a tracked issue**: every one of the following is collected
  and listed here as it happens, not just buried in the error log:
  - **Broken static references** — a served page requests another URL under this project
    (stylesheet, script, image, fetch/XHR target) that resolves to a 404.
  - **Script/CGI failures** — a script exits non-zero, writes to stderr, or otherwise signals an
    error per "Multi-language script execution" (this includes the script's own stderr output,
    not just the fact that it failed).
  - **Missing-interpreter 503s** — the configured interpreter binary for a `script_handlers`
    extension isn't installed on this host.
  - **Missing-language-module failures** — the interpreter ran, but the script itself reported a
    missing capability (e.g. `db.php` needs a MySQL module that isn't loaded/installed).
  - **Framework proxy errors** — upstream connection reset, non-2xx response, or upstream process
    crash/exit, per "Framework dev-server proxying."
  - **Access-control denials** — `.htaccess`/`.htpasswd` 401/403 results, shown for visibility
    into *that a rule fired and on what path*, never including the credential value that was
    submitted or the `.htpasswd` hash itself.
  - **TLS/certificate issues** — an LE request failure, an expired/about-to-expire cert, or
    falling back to the self-signed cert, per "TLS certificate resolution."
- **Tracing / correlation**: an entry is not just a bare error — where the information exists,
  cashttpd links it to *where it came from*: a broken `/css/main.css` 404 is shown alongside the
  referring page (from the request's `Referer` header) so the developer sees "`main.css` is
  missing, requested from `/my_page.html`" rather than an isolated 404 with no context. Every
  entry also carries its own request context: timestamp, method, requested path, resolved
  filesystem path (or upstream target for proxied requests), and response status.
- **Grouping and lifecycle**: repeated occurrences of the same underlying issue (same path, same
  cause) are grouped into a single entry with an occurrence count and a last-seen timestamp,
  rather than flooding the list with duplicates on every page reload during development. The list
  is in-memory only, tied to the current cashttpd process — it resets on restart, consistent with
  "no persisted state across restarts" elsewhere in this spec; the on-disk error log remains the
  durable record if that history is needed.
- **Click-through detail**: clicking an entry shows the full detail for that issue — every
  occurrence's request context from the grouped entry, and, for a missing capability, what's
  actually missing and what to do about it (e.g. "`db.php` requires the `mysqli` PHP extension —
  it is not loaded; install or enable `{module}`" rather than just a generic 500); for script/CGI
  failures, the script's own captured stderr/output is shown in full, the same content `--debug`
  would otherwise show a client, but here always visible regardless of `--debug`.
- **Always-on, not `--debug`-gated**: `/server-info` itself is a diagnostic surface for the
  developer running the server, distinct from the public-facing error pages controlled by
  `--debug` (see "Error pages and debug mode") — those two are not the same audience: `--debug`
  controls what a requesting *client* sees in error responses; `/server-info` is what the
  *developer operating cashttpd* sees, and always shows full detail regardless of `--debug`.
- **Same trust-boundary posture as everything else**: `/server-info` only exposes information about
  this cashttpd instance and the project it's serving — never filesystem content outside
  `base_dir`, never `.htpasswd` credentials, never TLS private key material.

### Logging

- The server MUST NEVER write anything (logs, cache, state, temp files, generated content) into
  any directory it is serving (`base_dir` or any path under it). Served directories are read-only
  as far as the server's own writes are concerned — this holds regardless of logging mode.
- Two log streams exist: **access log** and **error log**, matching AI.md's `logging.app` /
  `logging.error` split (this project's access log takes the place of AI.md's generic `app` log).
  There is no combined "app.log" — access and error are always tracked and stored separately.
- **File logging is unconditional, matching AI.md's default app behavior — it is never purely
  opt-in.** By default (no `--log {dir}` given), access and error log files are written
  automatically to the platform-standard Logs directory (AI.md → PART 4 "Path Rule"), under
  `{derived_name}`-prefixed filenames (see "Log file naming" below) so multiple projects served
  from the same install don't collide in that shared directory — a departure from AI.md's generic
  single-app `app.log`/`error.log` naming, required because this project can serve many different
  `base_dir` projects over its lifetime, not just one.
- **`--log {dir}` / `log_dir`** overrides *where* those files are written — a location independent
  of `base_dir` — it does not toggle file logging on or off; file logging is always active.
- **TUI / CLI-style live display** happens independently and simultaneously alongside file
  writing, never as an alternative to it: via the TUI (foreground) or as CLI-style plain lines to
  stdout/stderr (foreground fallback or `--daemon`). Log files are never written into `base_dir`
  under any configuration.
- **`--quiet`**: forces CLI-style output (per AI.md → "Smart Detect Rules") and, project-
  specifically, suppresses ongoing access/error log-line output to that display — the startup
  banner (listen address/port, TLS status, base_dir, config file in use) is still shown, so the
  developer still gets confirmation the server started and where it's listening, but no further
  per-request lines follow it.
  - `--quiet` never affects file logging — access and error log files are always written in full
    (default platform Logs directory or `--log {dir}` override) regardless of `--quiet`; the flag
    only controls what reaches the live TUI/CLI display.
  - `--quiet` never affects `/server-info`'s error/issue tracking or stats — that dashboard keeps
    collecting and displaying everything per "`/server-info` diagnostics dashboard," independent of
    what's echoed to the terminal.
  - `--quiet` is a CLI-only invocation flag (see "CLI flags"), not a persisted project setting — it
    describes how this run's terminal output behaves, not something written into the config file.
- **Error log format**: standard error-log format (Apache `httpd`-style error log line: timestamp,
  log level, client, message).
- **Access log format**: Apache "combined" log format —
  `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`.
- The global config file MAY override the on-disk format used for both the access log and the error
  log (e.g., switching to JSON lines) — the Apache-combined/standard-error formats above are the
  defaults, not the only permitted formats.
- **Log file naming**: the log filename uses `{derived_name}` (see "Core behavior"), suffixed with
  `_access.log` / `_error.log`, written into `{log_dir}` — the default platform Logs directory
  (AI.md → PART 4 "Path Rule") unless `--log {dir}`/`log_dir` overrides it. Example: if `--dir ./`
  is given and resolves to `/my/dev/server/www`, the log files are:
  - `{log_dir}/my_dev_server_www_access.log`
  - `{log_dir}/my_dev_server_www_error.log`

**Log rotation and retention** — uses AI.md's generic `logging.*` rotation/retention schema (same
`rotate`/`keep` option vocabulary — see AI.md → "Logging & Log Rotation"), configured under
`logging.access` and `logging.error` (this project's two log streams, in place of AI.md's generic
single `app` stream) instead of flat `log_format.*`/`log_retention_days` keys:
- Applies unconditionally, since file logging itself is unconditional (default platform Logs
  directory or `--log {dir}` override) — there is no logging mode where rotation doesn't apply.
  The TUI/CLI live display has nothing to rotate; this section governs the file streams only.
- **Default: `rotate: daily`, `keep: 30d`** — a project-specific choice from AI.md's standard
  option menu (not AI.md's own generic defaults of `weekly,50MB`/`none`): this is a
  developer-facing dev tool where a full month of daily-rotated history is more useful than
  AI.md's zero-retention default, but rotated files still age out automatically rather than
  accumulating forever. Both `rotate` and `keep` accept any value from AI.md's standard vocabulary
  (`never`/`daily`/`weekly`/`monthly`/`yearly`/`NMB`/`NGB`/combined for `rotate`;
  `none`/`N`/`Nd`/`Nw`/`Nm`/`forever` for `keep`), configurable per stream, same precedence as
  elsewhere.
- The active file always stays at the plain name (`{derived_name}_access.log` /
  `{derived_name}_error.log`) so tools tailing it never need to reopen a moving target; at rotation
  time the previous period's content is renamed to a date-stamped file in the same directory
  (`{derived_name}_access.log-YYYY-MM-DD` / `{derived_name}_error.log-YYYY-MM-DD`, using the
  rotation date), and a fresh empty active file is started.
- Retention is checked at each rotation (and once at server startup, to catch files that aged out
  while the server wasn't running) — not via a separate always-running timer.
- Rotation/retention is configured independently per stream (`logging.access` / `logging.error`)
  but defaults identically for both.

### Graceful shutdown and signal handling

- **`SIGINT`/`SIGTERM` (or `--daemon` stop, or TUI quit action) → graceful shutdown**, always the
  same sequence regardless of trigger:
  1. Stop accepting new connections on the listening socket immediately.
  2. In-flight requests are allowed to finish naturally — including CGI/script requests and
     proxied framework requests — consistent with "No artificial resource limits": shutdown never
     forcibly cuts off a request that's still producing output. There is no shutdown grace-period
     timeout that kills a slow request; graceful shutdown waits for it exactly as it would if
     shutdown weren't happening.
  3. Every child process cashttpd started (CGI/script processes and framework dev-server
     processes, including their full process trees per "Sandboxing") is stopped once the
     requests depending on it have completed — no orphaned child processes survive cashttpd exit
     under any shutdown path, matching the process-lifecycle guarantee already stated in
     "Framework dev-server proxying."
  4. Buffered log output (access log, error log — file-backed or TUI/CLI-style) is flushed before
     the process exits, so no in-flight request's log line is lost on shutdown.
  5. Process exits with a standard success exit code once steps 1–4 complete.
- **A second `SIGINT`/`SIGTERM` while a graceful shutdown is already in progress forces immediate
  exit** — this is the developer's explicit override (the universal "I pressed Ctrl-C twice, stop
  now" convention) for the case where a request is hung and the developer doesn't want to wait;
  it is a manual escape hatch, not an automatic timeout, so it never fires on its own.
- **`SIGHUP`**: does not restart or reload the server — config reload is already handled by live
  file watching (see "Configuration file"), so `SIGHUP` is treated as an ordinary terminating
  signal (same graceful-shutdown sequence as `SIGINT`/`SIGTERM`), matching the common expectation
  that `SIGHUP` ends a process rather than silently no-op'ing.
- **Crash / non-graceful termination (`SIGKILL`, host power loss, OOM kill)**: cashttpd cannot
  intercept these by definition — but see "Child process lifecycle" below for what cashttpd does
  proactively, before any crash happens, to keep even this case from leaving orphans. On next
  startup cashttpd does not attempt to recover or replay anything — logs simply resume appending
  to the active file; there is no persisted child-PID state carried across restarts to reconcile.
- This sequence is identical in `--daemon` mode and foreground/TUI mode — the only difference is
  how the stop signal is delivered (process signal vs. TUI quit action vs. daemon-stop command),
  never the shutdown behavior itself.

### Child process lifecycle (no zombies, no orphans)

Every child process cashttpd ever starts — CGI scripts, extension-based scripts, `cgi-bin/`
executables, and framework dev-server processes — is covered by this section identically. Two
distinct failure modes are both explicitly out of scope for cashttpd to ever produce:

- **Zombies (exited but unreaped)**: cashttpd collects the exit status of every child process it
  starts as soon as that child exits, unconditionally — whether the exit was a normal CGI/script
  completion, a script crash, or a framework dev-server process dying mid-session. A child is
  never left in an exited-but-unreaped state while cashttpd itself keeps running; this holds
  regardless of whether the request that spawned it already finished, timed out, or was abandoned
  by the client.
- **Orphans (still running, no longer tracked/tied to cashttpd's lifecycle)**: covered under two
  scenarios, both of which must end with no surviving untracked process:
  - **Normal/graceful cashttpd shutdown or restart** (any trigger in "Graceful shutdown and
    signal handling" above): every child's full process tree — not just the direct child, since a
    framework's own start command may spawn further children of its own — is stopped as part of
    the shutdown sequence. This is a hard requirement, not best-effort, because cashttpd is still
    running and able to act when this path executes.
  - **Abnormal cashttpd termination** (`SIGKILL`/`kill -9`, crash, OOM kill — cases cashttpd
    cannot intercept by definition, since no signal handler ever runs for `SIGKILL`): cashttpd
    proactively arranges, at the time each child is spawned — not reactively when the signal
    arrives, since that path never executes for `kill -9` —
    for that child (and its process tree) to be tied to cashttpd's own process lifetime using
    whatever unprivileged "die together"/process-group-teardown mechanism the host OS exposes, so
    that children are cleaned up automatically even when cashttpd itself had no chance to run its
    own shutdown code. This is best-effort per platform (same posture as "Sandboxing" above) — on
    a host/kernel version without such a mechanism, an abruptly-killed cashttpd's children fall
    back to normal OS orphan handling (reparented to the OS's init/reaper) rather than being left
    permanently dangling and untracked; `/server-info` surfaces whether this protection is active
    for the current platform, same as the sandboxing posture indicator.
- No child PID is ever persisted to disk/config and reused across cashttpd restarts — every
  restart starts with zero tracked children, so there is no stale-PID reconciliation logic that
  could itself mis-signal an unrelated process that happens to reuse an old PID.

### Default security headers

- Builtin, on by default, no module to enable — matching this project's "everything is builtin"
  model (AI.md's security-by-design posture also applies in full to this project even though it is
  local-dev-only; see "Constraints / non-negotiables") and matching how a real hardened httpd/nginx
  deployment is configured.
- Set on every response (static, directory listing, script/CGI, SSI, proxied) unless already set by
  the response itself (a script/CGI/proxied upstream's own header always wins — the server never
  overwrites a header the response already provided):
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - `Referrer-Policy: no-referrer-when-downgrade`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains` — only added when
    `tls.enabled: true` (HSTS on a plain-HTTP response is meaningless and actively wrong).
- `Content-Security-Policy` and `X-XSS-Protection` are deliberately **not** set by default: CSP
  needs per-project tuning to avoid breaking dev-server content (inline scripts, framework dev
  tooling, hot-reload websockets) in ways a one-size-fits-all default can't anticipate safely, and
  `X-XSS-Protection` is a deprecated/removed browser feature with no effect in current browsers.
  Both can be added via `security_headers` (below) when a project wants them.
- The `security_headers` config key (global or per-project) overrides, adds, or removes (empty/
  `null` value) any of the above, or sets additional headers not in the built-in set — same
  override-merge pattern as `mime_types`/`script_handlers`.

**`Server` header (`server_tokens`).** Mirrors Apache's `ServerTokens` directive and its exact
option set, so the config value is immediately familiar to anyone who has run httpd: `Full` (the
default — `Server: cashttpd/{version} ({os}; {arch})`), `OS` (`Server: cashttpd/{version} ({os})`),
`Minor` (`Server: cashttpd/{major}.{minor}`), `Major` (`Server: cashttpd/{major}`), `Min`
(`Server: cashttpd/{version}`, no parenthetical), and `Prod` (`Server: cashttpd` — name only,
matching Apache's `ProductOnly` alias). Default is `Full`, matching Apache's own out-of-the-box
default — this is a local-dev-only tool, so there's no production-hardening reason to diverge from
the well-known default here. A project wanting a minimal header sets `server_tokens: Prod`. There
is no "omit the header entirely" mode built in — a project that wants that removes it via
`security_headers` (`Server: null`) since it uses the same override-merge mechanism.

**`Cache-Control`/`Expires` (no default).** Unlike the headers above, cashttpd sets **no** default
`Cache-Control` or `Expires` header on static responses — this is deliberately different from a
production httpd/nginx `mod_expires` setup, because a stale-cached asset actively fights the
edit-and-reload workflow this project exists for (see "One Coherent Product" / "Constraints /
non-negotiables"). A project that wants caching semantics sets `Cache-Control`/`Expires` explicitly
via `security_headers` (which, despite the name, is the one general per-header override/add
mechanism — it is not restricted to headers with security meaning).

**CORS (`cors`).** Permissive by default — `Access-Control-Allow-Origin: *` (and, when the request
includes `Access-Control-Request-Method`/`-Headers`, i.e. a CORS preflight, an
`Access-Control-Allow-Methods`/`Access-Control-Allow-Headers` response echoing what was requested) —
matching how most local framework dev servers already behave, so a frontend dev server on one port
can call a cashttpd-served API/static asset on another without the developer having to configure
anything first. `Access-Control-Allow-Credentials` is never set to `true` by default (that combined
with a wildcard origin is invalid per the Fetch spec and browsers reject it outright); a project
needing credentialed CORS must set both explicitly via `cors`. The `cors` config key (global or
per-project) is a map of the CORS header names it overrides/adds (same override-merge pattern as
`security_headers`), or the literal `false` to disable CORS headers entirely for that project.

### Security / access control model

**Trust boundaries — who and what is untrusted:**
- Every HTTP client (anyone who can reach `--listen`/`--port`) is untrusted. All request input —
  path, query string, headers, body, cookies — is untrusted and must be validated/canonicalized
  before it influences any filesystem, auth, or execution decision.
- The content under `base_dir` is untrusted input too: it may contain arbitrary files (including
  ones a malicious or careless user placed there), so serving/executing it must never let it
  reach outside `base_dir`, regardless of what the content itself contains or requests.
- Script/CGI execution is the highest-privilege operation the server performs — a malicious
  request must never be able to use CGI env vars, argv, or stdin to inject additional shell/script
  behavior beyond what CGI 1.1 semantics intend (no unsanitized shell interpolation of request
  data anywhere in the exec path).

**Path resolution — the single hardest requirement, overrides convenience whenever the two
conflict:**
- Every request path is canonicalized (percent-decoded once per the HTTP spec, `.`/`..` segments
  resolved, symlinks resolved) to an absolute filesystem path *before* any access-control,
  auth, or serve/execute decision is made against it — decisions are never made against the raw,
  un-canonicalized request path.
- After canonicalization, the resulting absolute path MUST be within `base_dir`, or the request is
  rejected (404, not a path-disclosing error) — no exceptions, including for symlinks: a symlink
  under `base_dir` that resolves outside it is never followed/served, even when `.htaccess`
  `Options FollowSymLinks` is set for that directory (`FollowSymLinks` only controls whether
  symlinks that stay inside `base_dir` are followed).
- Traversal/encoding tricks (`..`, encoded/double-encoded `%2e%2e`, backslash variants, absolute-
  path injection, null-byte tricks, etc.) are all normalized/rejected by the same canonicalization
  step above — there is no separate denylist of "known bad" patterns to maintain, because nothing
  bypasses canonicalize-then-check.

**Access control (`.htaccess`) evaluation:**
- `Order`/`Allow`/`Deny`, `Require valid-user`/`Require user`/`Require group`, and `AuthType
  Basic` are evaluated against the canonicalized path from above, in the phase order defined in
  the `.htaccess`/`.htpasswd` compatibility section — auth/authz decisions can never be bypassed
  by requesting an equivalent-but-differently-encoded path.
- `.htaccess` and `.htpasswd` files are never servable as static content at any depth under
  `base_dir`, unconditionally (defined in the `.htaccess`/`.htpasswd` section) — this is itself an
  access-control rule, not just a convenience one.

**Credential handling:**
- `.htpasswd` password verification uses constant-time comparison — timing must never leak how
  many leading characters of a submitted password were correct.
- Credentials (raw passwords, `Authorization` header values) are never written to any log (access
  log, error log, TUI/CLI-style output, `--debug` output) — the access log's `%u` field is the
  authenticated username only, never the password or the raw header.

**Execution privilege model:**
- Scripts/CGI/framework-proxy child processes never run with more privilege than the server process
  itself — no setuid, no privilege escalation for script execution under any circumstance. The one
  and only place this project ever elevates privileges is the explicit privileged-port bind case
  (`--port 80`/`443`/<1024), and that elevation applies solely to the act of binding the listening
  socket — never to request handling, script execution, or file access afterward.
- Beyond that ceiling, child execution is additionally *contained* wherever the host OS makes it
  possible — see "Sandboxing" below. Containment is a floor-raising addition on top of the
  same-or-lesser-privilege rule above, never a substitute for it.

**Sandboxing (script/CGI/framework child processes):**
- Every script/CGI/framework-dev-server child process is treated as a potentially hostile
  process, not a trusted extension of the server — the goal is to limit what a compromised or
  malicious script can do to the rest of the developer's machine, not just to `base_dir`.
- **Baseline hardening — required on every platform, no exceptions:**
  - Child processes receive a minimal, explicit environment: the defined CGI 1.1 variables (and,
    for framework dev-servers, whatever variables that framework's documented contract requires)
    only — never the full environment `cashttpd` itself was launched with. Secrets or tokens
    present in the host/parent environment must never leak into served content's scripts by
    default.
  - No request-derived data is ever interpolated into a shell string for execution — child
    processes are always started as a direct process invocation with an argument list, never
    "build a shell command line and hand it to a shell."
  - Process lifecycle is tracked by the *entire process tree* the child spawns, not just the
    direct child PID — when `cashttpd` stops or restarts a script/CGI/framework child, every
    descendant process it spawned is stopped too; nothing is allowed to survive as an orphan.
- **Best-effort OS-level sandboxing — applied when the host supports it, silently falls back to
  baseline-only when it doesn't (this project must keep working with zero config on every
  supported OS/kernel version, so sandboxing availability can never be a hard requirement to
  start the server or execute a script):**
  - Where the host OS exposes an unprivileged, no-setup-required mechanism for confining a child
    process's filesystem access, cashttpd uses it to restrict the child to `base_dir` (plus
    whatever scratch/temp location that language's runtime genuinely needs) rather than the full
    filesystem reachability of the OS user account.
  - Where the host OS exposes an unprivileged mechanism for restricting a child process's
    reachable syscalls/capabilities, cashttpd applies it to the child.
  - Where the host OS exposes a mechanism for constraining/tracking an entire child process tree
    as a unit (so teardown and any future containment apply to the whole tree, not just the
    immediate child), cashttpd uses it.
  - None of the above is a hard security boundary on a host/kernel version that lacks the
    corresponding mechanism — on such hosts, execution still proceeds, using baseline hardening
    only. `/server-info` surfaces whether OS-level sandboxing is active for the current platform,
    so the developer knows which posture they're running under.
- Sandboxing never substitutes for the path-traversal, auth, and credential rules elsewhere in
  this section — it is a second, independent layer, not a replacement for canonicalize-then-check.

**Generated-file permissions (the binary creates these — see "Configuration file" and "TLS
certificate resolution" sections):**
- Config files (global and per-project) and log files are created with permissions readable/
  writable only by the owning user (no group/world write; no world read for anything containing
  secrets).
- Generated TLS private keys are the most sensitive artifact this project creates: written with
  owner-only read/write permissions (no group/world access at all), same directory-creation rule
  (`{data_dir}/certs/...`) as defined in "TLS certificate resolution."

**No artificial resource limits.** This is a developer tool, not a hardened public server: no
request/body/header size caps, no script/CGI execution timeout, no rate limiting, no connection
caps beyond whatever the OS itself imposes. A script that never returns just hangs that request —
that's a bug in the developer's script/framework, not something cashttpd polices. This applies
identically to proxied requests under "Framework dev-server proxying" — no proxy-specific timeout,
size cap, or rate limit either. (This does not relax the path-traversal, auth, and credential
rules above — those are correctness/security guarantees, not "limits.")

This also does not relax standard HTTP/2 and HTTP/3 protocol-conformance defenses: mitigating the
HTTP/2 Rapid Reset attack pattern (CVE-2023-44487, e.g. bounding concurrent reset streams per
connection) and honoring QUIC's own RFC 9000 anti-amplification and flow-control limits are baseline
correctness for a conformant HTTP/2/HTTP/3 implementation, not an "artificial" policy layered on top
— no legitimate local-dev workflow depends on an unbounded stream-reset flood or an unthrottled QUIC
handshake, so there is nothing here for a developer to lose. These are the same category as the
path-traversal/auth/credential carve-out above: security/correctness guarantees, not "limits."

**Network exposure posture:**
- Default bind addresses are loopback-only (`::1` / `127.0.0.1` — see "Core behavior"); binding to
  a non-loopback/public address is only ever via explicit `--listen`, never a default.

### Constraints / non-negotiables

Everything in this section overrides convenience whenever the two conflict. Each item
cross-references the section that defines it in full — this list exists so the highest-order
commitments are visible in one place, not to restate their detail.

**Identity and surface:**
- Single static binary, zero feature gating, MIT licensed, first run works with zero
  configuration — pointing it at a directory and starting it must "just work" the same way
  `php -S`/`python -m http.server` do, with `.htaccess`/CGI/multi-language/TLS/proxying all
  layered on top as opt-in based on what's present or configured, never required up front.
- No GUI, ever; TUI/CLI-style output only — see "App surfaces in scope."
- RFC-compliant HTTP/1.1, HTTP/2, and HTTP/3 (correct status codes, conditional/range requests,
  header semantics) — see "Core behavior."

**Trust boundary and path safety — the hardest requirements in the project:**
- No path traversal outside `base_dir`, under any circumstance, for any request, script, symlink,
  or proxied path — canonicalize-then-check, no denylist, no exceptions — see "Security / access
  control model."
- Default bind is loopback-only; binding non-loopback/public requires an explicit `--listen` —
  never a default — see "Security / access control model."
- `.htaccess`/`.htpasswd` files are never servable as static content at any depth — see
  "`.htaccess`/`.htpasswd` compatibility."
- The server never writes into any directory it serves — no logs, cache, state, certs, or
  generated files land inside `base_dir` under any configuration — see "Logging."

**Protocol and TLS:**
- `--port` serves plain HTTP or HTTPS, never both, never a redirect between them — controlled
  solely by `tls.enabled` — see "Core behavior."
- TLS is off by default; `--fqdn` is required whenever `tls.enabled: true`, enforced by a fast
  non-zero-exit startup failure, never a silent certless mode — see "TLS certificate resolution."

**Execution and process safety:**
- Missing language interpreters are a runtime condition (HTTP 503 on the affected request), never
  a startup failure — the server must still start and serve static content and any
  languages/scripts that ARE available — see "Multi-language script execution."
- Script/CGI/framework child processes never run with more privilege than the server process
  itself; the only privilege elevation anywhere in this project is binding a privileged port —
  see "Security / access control model."
- No zombie processes and no orphaned processes, ever — including the `kill -9`/`SIGKILL` case,
  handled via a best-effort spawn-time "die together" mechanism rather than a signal handler that
  can never run — see "Child process lifecycle."
- Graceful shutdown never force-kills an in-flight request; the only way to force an immediate
  exit is an explicit second `SIGINT`/`SIGTERM` from the developer — see "Graceful shutdown and
  signal handling."
- Sandboxing is applied best-effort per platform, but its absence on a given host/kernel is never
  a reason to refuse to start or refuse to execute a script — zero-config startup always wins over
  unavailable sandboxing — see "Sandboxing."
- No artificial resource limits (timeouts, size caps, rate limits) on CGI/script execution or
  proxied requests — this does not relax any trust-boundary/credential rule above, those are
  correctness guarantees, not "limits" — see "Security / access control model" and "Framework
  dev-server proxying."

**Credentials and generated secrets:**
- `.htpasswd` verification is constant-time; credentials are never written to any log or
  `/server-info` output — see "Security / access control model."
- Generated TLS private keys, config files, and log files are created owner-only (no group/world
  access) — see "Security / access control model."

**Compatibility (must-match, not "inspired by"):**
- `.htaccess`/`.htpasswd` directive set, cascade order, and phase-evaluation order must match
  Apache `httpd` behavior — see "`.htaccess`/`.htpasswd` compatibility."
- CGI 1.1 protocol semantics (env vars, stdin/stdout, headers-then-body) apply identically to
  `cgi-bin/`-style and extension-based script execution — see "Multi-language script execution."
- Framework dev-server proxying must forward requests/responses with full fidelity (headers, body
  streaming, WebSocket/`Upgrade`, proxy-identification headers) — a framework must not be able to
  tell it's behind cashttpd except by the port it's reached on — see "Framework dev-server
  proxying."

**Configuration precedence — applies to every setting without exception:**
- CLI flag > environment variable > per-project config > global config > built-in default —
  matching AI.md's generic configuration-layering rule; see "CLI flags" and "Configuration file."
- `mime_types` is a closed, override-only registry (the built-in IANA table is complete);
  `script_handlers` is open — override, add, or disable — see "MIME types" and "Multi-language
  script execution."

**No persisted runtime state across restarts:**
- Child PIDs, `/server-info` stats and issue lists, and framework proxy child status are all
  in-memory only and reset on every restart — no stale-state reconciliation logic exists or is
  needed — see "Child process lifecycle" and "`/server-info` diagnostics dashboard."
