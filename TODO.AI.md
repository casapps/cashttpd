## [ ] HTTP/1.1 core conformance is done; script/proxy/TLS/htaccess layers remain
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
`{log_dir}/{derived_name}_{access,error}.log`. Still open (none of this is
implemented yet):
- Chunked *request* body decoding (only response framing is `Content-Length`
  today; no request body is read/forwarded anywhere yet since there is no
  CGI/proxy consumer for one).
- CGI/multi-language script execution (`script_handlers`, CGI 1.1 protocol,
  503-for-missing-interpreter) — IDEA.md "Multi-language script execution".
- `.htaccess`/`.htpasswd` compatibility (recursive discovery, cascade merge,
  AuthType/Require/Order-Allow-Deny, RewriteEngine/RewriteRule, ErrorDocument,
  DirectoryIndex, Options) — IDEA.md "`.htaccess`/`.htpasswd` compatibility".
- TLS certificate resolution (Let's Encrypt live/new-request + self-signed
  fallback, `{data_dir}/certs/{derived_name}/` storage) — IDEA.md "TLS
  certificate resolution". `Resolved.tls_enabled` is parsed/resolved but
  the listener is always plain HTTP.
- Framework dev-server proxying (`proxy.*` config keys are parsed/resolved
  but never consulted by `run()`/`handle_request()`).
- `/server-info` diagnostics dashboard.
- Live config-file reload (rebind on listen/port/tls change without
  restart) — `crate::config::load` is only called once, at `serve` startup.

Scheduled log rotation/retention is now implemented in
`src/support/rotation.rs` (`daily`/`weekly`/`monthly`/`yearly`, `NMB`/`NGB`,
and combined policies for `rotate`; `none`/`N`/`Nd`/`Nw`/`Nm`/`forever` for
`keep`) and wired into `server::LogStream`/`Logger`: each write
opportunistically checks whether the active file's rotate policy has fired
(time boundary crossed or size limit reached), renames it to a
date-stamped sibling, applies retention, and reopens a fresh active file at
the plain name; retention is also re-checked once at `Logger::open` (server
startup) to catch files that aged out while the server wasn't running.

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

## [ ] AI.md PART 10's own `hashFiles()` job-level `if:` example is invalid
Read: AI.md PART 10
AI.md's canonical "Security Jobs in ci.yml Example" uses
`if: ${{ hashFiles('Cargo.lock') != '' }}` at the job level for `vuln-scan`
and `image-scan`. Verified via a real GitHub Actions run
(github.com/casapps/cashttpd, run 31670043840) that this fails to schedule
any jobs at all — GitHub Actions evaluates job-level `if:` before a runner
is assigned and the repo is checked out, so `hashFiles()` has no filesystem
to read at that point. This is not a local `act`-only limitation as
previously assumed; it is invalid on real GitHub Actions. Fixed in this
project by adding a `detect` job that checks out the repo and exposes
`has_cargo_lock`/`has_dockerfile` as job outputs, which `vuln-scan`/
`image-scan` then reference via `needs.detect.outputs.*` instead. Flagging
here because AI.md PART 10 still documents the broken pattern as canonical
— worth raising upstream so other projects bootstrapped from this spec
don't repeat the same real-CI failure.
