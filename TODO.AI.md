## [ ] Full HTTP/1.1 RFC 9110/9112 conformance
Read: AI.md PART 7, PART 14
`src/server/mod.rs` implements a minimal GET/HEAD static-file server only.
Missing: full request header handling, keep-alive, chunked transfer
encoding, CGI/script execution, `.htaccess`/`.htpasswd` support, TLS,
framework dev-server proxying, `/server-info` dashboard, and Apache-combined
access logging. This is the single largest remaining functional gap.

## [ ] Full CLI flags / config-file loading
Read: AI.md PART 7
`ServeOptions` in `src/server/mod.rs` covers only `listen`, `port`, and
`base_dir` — a subset of IDEA.md's full CLI flags table. Full config-file
loading and the remaining flags are not yet implemented.

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
