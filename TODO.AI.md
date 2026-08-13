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

## [ ] act v0.2.89 cannot validate job-level `hashFiles()` in `if:` conditionals
Read: AI.md PART 10
`vuln-scan` and `image-scan` jobs in every GitHub-Actions-syntax workflow
(`.github/workflows/ci.yml`, `.gitea/workflows/ci.yml`,
`.forgejo/workflows/ci.yml`) use `if: ${{ hashFiles(...) != '' }}` at the
job level, exactly as AI.md PART 10's own canonical example specifies. This
is valid GitHub Actions syntax, but the locally installed `act` (v0.2.89,
latest as of this session) has a schema-validator limitation that rejects
`hashFiles()` in a job-level `if:`. Confirmed via direct upgrade-and-retest
that this is a persistent `act` tooling limitation, not a workflow defect —
real GitHub/Gitea/Forgejo Actions runners are not expected to be affected.
No action needed unless a future `act` release still fails after upgrading.

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
validate identically to the GitHub originals under `act --list` (same
pre-existing `hashFiles()` limitation on `ci.yml`, clean pass on
`release.yml`), but have not been run against a real Gitea or Forgejo
instance. Verify `gh release create` (GitHub-CLI-specific, used in
`release.yml`) has a working equivalent on those platforms' Actions
runners, and that the pinned third-party action SHAs resolve there.
