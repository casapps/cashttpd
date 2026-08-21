## [x] HTTP/1.1 core conformance, script/proxy/TLS/htaccess layers — closed
Read: AI.md PART 7, PART 14; IDEA.md "Business logic"
`src/server/mod.rs` now implements: full request-header parsing,
persistent (keep-alive) connections, conditional requests
(`If-Modified-Since`/`If-None-Match` → 304), single-range `Range` requests
(206/416), IANA-registry-backed `Content-Type` detection via `mime_guess`
(with `mime_types` config override), default-index resolution plus
opt-in directory listing (with human-readable file sizes), embedded
mobile-first dark-themed error pages (debug-gated detail), `.ht*` trust-
boundary denial (never served as static content), and unconditional
Apache-combined-format access logging plus Apache-style error logging to
`{log_dir}/{derived_name}_{access,error}.log`.

CGI/multi-language script execution is now implemented (IDEA.md
"Multi-language script execution"): `classify_script` routes a resolved
file to `cgi-bin/` exec-by-shebang (location-based, any extension, always
wins over `script_handlers` inside `cgi-bin/`) or to extension-based
`script_handlers` interpreter dispatch (built-in table —
`config::builtin_script_handlers` — merged under global/per-project
config, including the reserved `exec` value and per-request interpreter
discovery via `$PATH`/absolute path); `dispatch_script` builds the full
CGI 1.1 environment (`REQUEST_METHOD`…`HTTP_*`), streams the request body
(read per `Content-Length` or `Transfer-Encoding: chunked` in
`serve_connection` for any method — see below) to the child's stdin, and
`parse_cgi_output` splits stdout into the CGI header block (including a
`Status:` override) and body, falling back to `text/html`/`200 OK` when
the script emits no header block. A missing interpreter binary is
`503`/`"{lang} is not installed"`; a script that produces no output at
all surfaces the server's own stderr/exit-status view under `--debug`
(`error_page_with_trace`) — a script's own output is otherwise always
relayed as-is, never intercepted.

`serve_connection` now also decodes `Transfer-Encoding: chunked` request
bodies (RFC 7230 §4.1) via `read_chunked_body`, taking precedence over
any `Content-Length` present on the same message per RFC 7230 §3.3.3;
malformed chunk framing closes the connection the same way a failed
`Content-Length` read does. `PATH_INFO`/`PATH_TRANSLATED` are now
resolved per CGI 1.1 §4.1.5/§4.1.6 (Apache-compatible "longest
existing-file prefix" rule): when the full literal request path doesn't
exist on disk, `resolve_script_path_info` walks the path's ancestor
`/`-segment prefixes (never escaping `base_dir`) for the first one that
is a file `classify_script` recognizes as a script, and threads the
unconsumed trailing segments through `dispatch_script` into the CGI
environment; plain static-file resolution and the directory/default-index
branch are unaffected. This closes out item 1's "Still open" list.

`.htaccess`/`.htpasswd` Apache-compatible per-directory configuration is now
implemented in `src/server/htaccess.rs` (IDEA.md "`.htaccess`/`.htpasswd`
compatibility"): recursive discovery from `base_dir` down to each request's
resolved directory, root-most-to-leaf cascade merge (subdirectory
`.htaccess` layers on top of parent directives, not replaces them),
`AuthType Basic` + `AuthName`/`AuthUserFile`/`AuthGroupFile` authentication
against `.htpasswd` (bcrypt `$2y$`/`$2a$`/`$2b$` via the `bcrypt` crate,
classic `apr1`/md5crypt implemented natively against the `md-5` crate and
verified against a known Apache test vector, legacy `{SHA}` via `sha1` +
`base64`), `Require valid-user`/`Require user`/`Require group` plus legacy
`Order allow,deny`/`Order deny,allow` with `Allow`/`Deny from` (IP and CIDR,
both IPv4/IPv6), `ErrorDocument`, `DirectoryIndex`, `Options
Indexes`/`FollowSymLinks`, and a `mod_rewrite`/`mod_alias`-compatible engine
(`RewriteEngine`/`RewriteCond`/`RewriteRule` with `[R]`/`[R=NNN]`/`[NC]`
flags and per-directory-relative pattern matching, `Redirect`/
`RedirectMatch`), all wired into `server::handle_request` per the documented
6-phase per-request evaluation order (rewrite/redirect → access control →
authentication → authorization → directory-index/listing → ErrorDocument
mapping for any error status from any phase). `.htaccess`/`.htpasswd`
remain non-servable as static content at any depth (trust boundary
unaffected, not overridable from within a `.htaccess` file). Documented
gaps:
- Hostname-based `Allow`/`Deny from {host}` is parsed but never matches — no
  reverse-DNS lookup is performed.
- `.htpasswd` `crypt`-DES and other legacy formats beyond bcrypt/apr1/`{SHA}`
  are unsupported.
- `RewriteCond`/`RewriteRule`/`Redirect` variable expansion covers
  `%{REQUEST_URI}`, `%{QUERY_STRING}`, `%{HTTP_HOST}`, `%{REQUEST_METHOD}`,
  `%{REMOTE_ADDR}` only — not the full Apache variable set.
- Legacy `Order allow,deny`/`Order deny,allow` is implemented as the
  commonly-documented approximation (deny-always-wins-if-matched for
  `allow,deny`; allow-overrides-deny for `deny,allow`), not Apache's exact
  directive-by-directive last-match-wins evaluation.

The `/server-info` diagnostics dashboard is now implemented in
`src/server/info.rs` (IDEA.md "`/server-info` diagnostics dashboard"): a
`Stats` struct, constructed once in `run()` and shared via `Arc` into every
connection/request, tracks totals-since-start by method/status(exact and
class)/handler type, bytes sent/received, a 60-second rolling requests/sec
window (per-second bucket map, pruned, never a full timestamp history),
per-handler-type latency (min/avg/max plus p50/p95 over a bounded 256-sample
reservoir), in-flight request count and active-upstream-proxy-connection
count (both via RAII `InFlightGuard`/`UpstreamGuard` covering every early
return), bounded top-10 most-requested/most-error-prone paths, and process
uptime. A grouped `IssueList` records the full IDEA.md issue taxonomy
(broken static references, script/CGI failures with captured stderr,
missing interpreters, framework proxy errors, access-control denials) keyed
by `(kind, path, cause)` with an occurrence count, last-seen timestamp, and
per-occurrence request context, bounded to 200 groups/20 occurrences per
group with oldest-entry eviction. `render_dashboard` produces a dependency-
free HTML page styled consistently with the existing embedded error pages,
using `<details>`/`<summary>` for click-through issue detail. `GET`/`HEAD
/server-info` is dispatched as a built-in route in `handle_request`, before
the framework-proxy prefix check and before the `.htaccess` 6-phase
pipeline, always on (never `--debug`-gated) and never resolved against the
filesystem. Instrumentation is wired directly into the existing dispatch
call sites (`proxy::proxy_request`, `.htaccess` denial points, the 404
canonicalize-failure path, `serve_directory_listing`, `dispatch_script`,
`serve_file`) rather than restructuring return types across the codebase.
Documented gap: "missing-language-module" failures (e.g. a PHP script
needing an uninstalled `mysqli` extension) are not separately detected from
ordinary script failures — cashttpd has no language-aware parsing of
arbitrary script stderr/stdout to distinguish that specific cause, so such
failures are recorded as ordinary `ScriptFailure` issues with the script's
own captured stderr, not as a distinct `MissingLanguageModule` entry.

TLS termination and certificate resolution are now implemented in
`src/server/tls.rs` (IDEA.md "TLS certificate resolution"): `run()` fails
fast with a non-zero exit when `tls.enabled` is true and no `--fqdn`/`fqdn`
was provided. `build_server_config` resolves a certificate via 3-tier
fallthrough, first match wins — (1) scan `/etc/letsencrypt/live/**`,
resolving symlinks into `archive/`, for a live cert matching `{fqdn}` that
is readable and currently valid (validity window extracted via a hand-
rolled DER walk — `der_read_tlv`/`parse_validity`/`parse_asn1_time`/
`days_from_civil` — since the toolchain's musl-hosted `rustc` cannot
compile the proc-macro-based `x509-parser`); (2) if step 1 finds nothing
and `--listen` resolves to a public/routable address (`is_public_addr`),
attempt Let's Encrypt via a full hand-rolled ACME v2 (RFC 8555) HTTP-01
client (`mod acme` — directory discovery, JWS-signed newAccount/newOrder,
authorization + http-01 challenge with a temporary port-80 responder,
CSR via `rcgen`, finalize, and certificate download), falling back to
self-signed on any ACME failure rather than propagating a hard error; (3)
self-signed fallback valid 10 years (`generate_self_signed`). Certs/keys
are stored at `{data_dir}/certs/{derived_name}/`; host Let's Encrypt certs
are used in place, never copied. TLS termination is wired into the accept
loop in `server::mod` via a `Conn` enum (`Plain(TcpStream)` /
`Tls(Box<rustls::StreamOwned<...>>)`) so the existing plain-HTTP request
pipeline needs no further changes. Cert resolution runs before privilege
drop (it may need port 80 for ACME HTTP-01). Documented gap: live ACME
issuance against the real Let's Encrypt service cannot be exercised in
this sandboxed dev/CI environment (no real public FQDN, no guaranteed
port-80 reachability) — the client is implemented in full per RFC 8555
and falls back safely on failure, but genuine issuance against Let's
Encrypt's production or staging endpoints is a manual-verification-only
gap, not a stub.

Framework dev-server proxying is now implemented in `src/server/proxy.rs`
(IDEA.md "Framework dev-server proxying"): `resolve_proxy_target` layers
the resolved `proxy.*` config over a built-in profile table (`vite`,
`bun`, `deno`, `node`, `rails`, `django`, `flask`, `fastapi`), each with a
default spawn command/upstream address/path scope, auto-detected from
marker files in `base_dir` (`vite.config.*`/`package.json` "vite" dep,
`bun.lockb`, `deno.json[c]`, `package.json` `dev`/`start` script,
`Gemfile`+`config.ru`, `manage.py`, `pyproject.toml`/`requirements.txt`
mentioning `fastapi`/`flask`) when `proxy.type` is not set explicitly.
`enabled: false` always disables proxying regardless of any marker file
present; `type` alone reuses that profile's other defaults;
`command`/`upstream`/`path_prefix` each independently override the
selected profile's corresponding default; a fully explicit
`command`+`upstream` pair needs no `type` at all (`kind` then reports as
`"custom"`). `run()` spawns the resolved framework's child process once
at startup (never per-request) and hands its PID to
`support::signal::ShutdownState::track_child_process`, so a raw
`signal_hook::low_level::register` handler kills it on every
SIGINT/SIGTERM/SIGHUP delivery, including the "second signal forces an
immediate exit" escape hatch that bypasses ordinary `Drop`-based cleanup;
it is also killed and reaped on the ordinary graceful-shutdown path.
`handle_request` dispatches a request whose decoded path starts with
`path_prefix` to `proxy::proxy_request` ahead of the static/CGI/
`.htaccess` pipeline: until a bounded `TcpStream::connect_timeout`
readiness probe (the one timeout IDEA.md's "no artificial limits" policy
explicitly carves out) succeeds, the client receives an embedded
auto-refreshing dark-theme "starting…" page matching the existing error
page styling; once ready, every request header is forwarded verbatim
(`Host` unmodified, hop-by-hop `Connection` dropped and replaced),
`X-Forwarded-For`/`X-Forwarded-Proto` are appended to (never overwriting)
any existing value, and the response is relayed to the client honoring
the upstream's own framing (`Content-Length`, `Transfer-Encoding:
chunked`, or read-until-close) via true chunk-by-chunk streaming, not
full in-memory buffering. A `Connection: Upgrade`/`Upgrade: websocket`
request that receives a `101 Switching Protocols` response is relayed
bidirectionally after the handshake (RFC 6455) via a single-thread
short-timeout poll loop, chosen over one-thread-per-direction because the
TLS `Conn` variant cannot safely hand out two simultaneous `&mut`
handles across threads. Documented gap: exercising a live framework
dev-server child process (actually spawning `npm run dev`/`bundle exec
rails server`/etc. and proxying real traffic through it end-to-end)
cannot be run in this sandboxed dev/CI environment (no framework
toolchains installed, no guaranteed free upstream ports) — detection,
resolution precedence, header forwarding, and the WebSocket upgrade path
are covered by unit tests against real loopback sockets, but genuine
end-to-end proxying against a real framework process is a
manual-verification-only gap, not a stub.

Scheduled log rotation/retention is now implemented in
`src/support/rotation.rs` (`daily`/`weekly`/`monthly`/`yearly`, `NMB`/`NGB`,
and combined policies for `rotate`; `none`/`N`/`Nd`/`Nw`/`Nm`/`forever` for
`keep`) and wired into `server::LogStream`/`Logger`: each write
opportunistically checks whether the active file's rotate policy has fired
(time boundary crossed or size limit reached), renames it to a
date-stamped sibling, applies retention, and reopens a fresh active file at
the plain name; retention is also re-checked once at `Logger::open` (server
startup) to catch files that aged out while the server wasn't running.

Live config-file reload is now implemented in `src/server/mod.rs`/
`src/config/mod.rs` (IDEA.md "Configuration file" → "Live reload"):
`config::config_paths` factors the global-config/per-project-config path
derivation out of `config::load` so `server::run`'s accept loop can poll
the mtimes of the exact same two files (`ReloadWatch`) roughly once a
second without duplicating that logic. On a detected mtime change,
`apply_reload` re-runs `config::load` with the original startup
`CliOverrides` (so CLI-flag > env > per-project > global > default
precedence still holds after a reload) and diffs the result field-by-field
against the running configuration via three independent predicates —
`config_needs_listener_rebind` (`listen`/`port`/`tls_enabled`, plus `fqdn`
only while TLS is active), `config_needs_proxy_restart` (`proxy.*`), and
`config_needs_logger_reopen` (`log_dir`/rotate/keep) — applying only
whichever pieces actually changed. Every other field (`directory_listing`,
`mime_types`, `script_handlers`, `debug`, logging *format* overrides, …)
is hot-appliable by construction: it is swapped in atomically via a
`Mutex<Arc<RuntimeState>>` cell that every accept-loop iteration snapshots
once before spawning its per-connection thread, without dropping the
listener or any in-flight connection. A `base_dir` change (never
live-appliable — it is threaded through as a plain, non-swappable path at
startup) is detected, logged as a warning, recorded on the `/server-info`
dashboard (`IssueKind::ConfigReloadIssue`), and forced back to the running
value before the rest of the reload proceeds; a listener-rebind attempt
that fails (e.g. targeting a privileged port after `drop_privileges_if_root`
already ran, or a port already in use) is likewise warned/recorded and
its `listen`/`port`/`tls_enabled`/`fqdn` are reverted to the still-bound
values, rather than crashing or misreporting the running state.
Documented gap: a true end-to-end test that calls `server::run` directly
was judged unsafe
to add — `run()` calls `platform::drop_privileges_if_root`, which performs
an irreversible `setuid`/`setgid` on the *entire test process* when run as
root (the default inside the `casjaysdev/rust:latest` verification
container), which would corrupt every other test sharing that binary. The
same hot-appliable-change-reflected-in-a-request behavior is instead
covered via `request_over_loopback_opts` directly (bypassing `run()`/
privilege-drop entirely) in
`hot_appliable_directory_listing_change_is_reflected_in_a_subsequent_request`.

## [x] Full CLI flags / config-file loading — closed
`src/config/mod.rs` now implements the full IDEA.md schema: `Layer`/
`Resolved`/`CliOverrides` cover all 19 config keys (`base_dir`, `listen`,
`port`, `log_dir`, `debug`, `fqdn`, `tls.enabled`, `directory_listing`,
`mime_types`, `script_handlers`, `proxy.*`, `logging.access.*`,
`logging.error.*`), with CLI > env (`CASHTTPD_*`) > per-project config >
global config > built-in-default precedence, two-layer YAML at
`{config_dir}/config.yaml` and `{config_dir}/projects/{derived_name}.yaml`,
autogeneration with owner-only (0600) permissions on first `serve`, and
`--config-test`/`-t` syntax-only validation that never touches sockets or
writes files. `src/server/mod.rs::parse_cli_overrides` covers `--listen`,
`--port`, `--dir`, `--fqdn`, `--log`, `--config`, `--debug`; `--daemon`/
`--quiet`/`--config-test` are handled as invocation-shape flags in
`src/ui/cli/mod.rs` per IDEA.md (never persisted to config). Live reload of
config while `serve` is running (without restart) is not implemented — see
the item above.

## [ ] Local `cargo deny check` advisory-db fetch fails in this sandbox (git TLS)
Read: AI.md PART 10, PART 11
`cargo deny check licenses advisories bans sources` fails locally with a
git-CLI-specific TLS error (`SSL: no alternative certificate subject name
matches target hostname 'github.com'`) when cloning the RustSec advisory-db.
Confirmed this is specific to `git`'s HTTPS client in this sandbox — `wget`
and `cargo-audit`'s own HTTP client succeed against the same hostname. Not a
project configuration defect; expected to work on real CI runners. No
action needed unless it reproduces on real GitHub/GitLab/Gitea/Forgejo CI.

## [ ] Release workflow fixes are untested against a real tag push
Read: AI.md PART 2 "Binary Model", PART 5 "Release Artifacts", PART 6
"Build Metadata"
This session fixed three `release.yml` (GitHub/Gitea/Forgejo) and
`.gitlab-ci.yml`/`Jenkinsfile` bugs found during re-bootstrap
reconciliation: (1) added `build.rs` + Dockerfile `ARG BUILD_EPOCH`/
`ARG COMMIT_ID` wiring so `release.txt`/build metadata are actually
embedded (previously `option_env!("APP_VERSION")` etc. were always unset —
`release.txt` had zero effect); (2) replaced per-artifact `.sha256`
sidecar files with the spec-required aggregate `sha256.txt`/`sha512.txt`;
(3) fixed the Linux static-linkage check, which grepped `ldd` output for
`'not a dynamic executable|statically linked'` — a pattern that does NOT
match real musl static-pie `ldd` output (`/lib/ld-musl-x86_64.so.1
(0x...)`, confirmed directly by building `x86_64-unknown-linux-musl`
release inside `casjaysdev/rust:latest`), so the check would have silently
never matched real output and always failed on an actual tag-triggered
release run; now checks `file`'s `static-pie linked`/`statically linked`
output instead. `act --list` validates the modified GitHub/Gitea/Forgejo
YAML and `.gitlab-ci.yml` parses as valid YAML, and `--version` output was
manually verified to contain the correct embedded version/commit/date
inside the container, but none of these workflows have been exercised via
an actual tag push in real CI (release.yml only triggers on `v*` tags) —
verify on the next real release.

## [ ] Independently verify Gitea/Forgejo workflow provider compatibility
Read: AI.md PART 10
`.gitea/workflows/{ci,release}.yml` and `.forgejo/workflows/{ci,release}.yml`
are currently verbatim copies of the GitHub Actions workflows (per AI.md's
provider table, both use "GitHub Actions (act runner)" syntax). They
validate cleanly under `act --list` (same as the GitHub originals), but have
not been run against a real Gitea or Forgejo instance. Verify `gh release
create` (GitHub-CLI-specific, used in `release.yml`) has a working
equivalent on those platforms' Actions runners, and that the pinned
third-party action SHAs resolve there.

## [x] AI.md PART 10's own `hashFiles()` job-level `if:` example is invalid
Read: AI.md PART 10
Fixed upstream in the `claudemgr` `rust/APPLICATION.md` template (commit
`6af51c9f273e`), which moved the `hashFiles()` gate from job-level `if:` to
step-level `if:` inside `vuln-scan`/`image-scan` (valid there because
`actions/checkout` has already run as an earlier step in the same job).
cashttpd's own fix predates and differs from upstream's: a `detect` job that
checks out the repo and exposes `has_cargo_lock`/`has_dockerfile` as job
outputs, which `vuln-scan`/`image-scan` then reference via
`needs.detect.outputs.*`. Both patterns are valid; cashttpd keeps its
`detect`-job approach rather than switching to upstream's step-level-if,
since it was already implemented, tested, and green in real CI. AI.md
PART 10's canonical "Security Jobs in ci.yml Example" has been updated to
document the `detect`-job pattern actually in use, replacing the broken
job-level `hashFiles()` example. The same upstream commit's other fixes
(concurrency-group event_name suffix, `$(basename "$GITHUB_REPOSITORY")`
container naming, `docker/setup-buildx-action` v4.1.0 bump, TruffleHog
scan-range step + `--results=verified,unknown`) were cross-checked and
ported into `.github/`, `.gitea/`, and `.forgejo/` `ci.yml`/`release.yml`
where applicable.

## [ ] `Upgrade: h2c` handshake (RFC 9113 §3.2) is not implemented
Read: IDEA.md "Core behavior" → "Protocol version negotiation"; AI.md PART 9
Cleartext HTTP/2 is supported today only in its prior-knowledge form (RFC 9113 §3.4) — a client
that opens with the HTTP/2 connection preface is auto-detected by `hyper_util`'s
`server::conn::auto::Builder` in `servers::serve_http` and served over HTTP/2. The
`Upgrade: h2c` + `HTTP2-Settings` 101 handshake is *not* implemented: the mandated crate stack
(hyper 1.x over the `h2` crate) exposes no API for synthesizing the upgraded connection's
half-closed stream 1 from an already-parsed HTTP/1.1 request, so there is no way to complete the
handshake without either forking `h2` or hand-rolling HTTP/2 framing — both rejected. Requests
carrying `Upgrade: h2c` are therefore served over HTTP/1.1, which is the fallback RFC 9113 §3.2
itself sanctions ("a server that does not support HTTP/2 ... responds to the request as though
the Upgrade header field were absent"). Revisit if hyper/h2 grows a supported upgrade entry
point. Note that no major browser ever shipped `Upgrade: h2c`, so this affects only
h2c-upgrade-capable CLI clients (`curl --http2` against a plain-HTTP listener, which falls back
cleanly to HTTP/1.1; `curl --http2-prior-knowledge` gets real HTTP/2).

## [ ] rust-lint findings (pre-existing, unrelated to current work) — 18 issues
Read: `~/.claude/memory/rust_conventions.md`, `.github/workflows/release.yml`,
`.gitea/workflows/release.yml`, `.forgejo/workflows/release.yml`, `src/configs/mod.rs`,
`src/uis/cli/mod.rs`
Found by the `rust-lint` agent while gating the HTTP/2+HTTP/3 commit; none of these touch files
modified by that feature (`Cargo.lock`/`Makefile`/`src/servers/**`) or by the docker-packaging/
spec-doc work from the same session, so they are logged here rather than folded into an
unrelated commit:
- **`Cargo.toml`**: `edition = "2024"` — convention requires `"2021"`.
- **`src/configs/mod.rs`**: `#[allow(dead_code)]` at lines 176, 180, 184 — each needs an
  explanatory comment above it per the comment-conventions rule (no bare `#[allow(...)]`).
- **`src/uis/cli/mod.rs`**: `--color` flag is missing from the CLI definition (required values:
  `auto`/`yes`/`no`).
- **Binary naming in release workflows** (`.github/`, `.gitea/`, `.forgejo/` `release.yml` lines
  54–59, identical in all three): output names use `amd64`/`arm64`/`darwin` — convention
  requires `x86_64`/`aarch64`/`macos`.
