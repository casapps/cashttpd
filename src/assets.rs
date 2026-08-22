//! Compile-time asset embedding (AI.md PART 0 "Self-Contained Assets").
//!
//! Every runtime asset is baked into the binary with `include_str!` /
//! `include_bytes!` so the shipped artifact stays a single self-contained
//! file with no external data directory to install alongside it.

/// The project's full `LICENSE.md` — the project license, embedded-asset
/// notices, upstream NOTICE files, and the generated third-party crate
/// attribution region — embedded verbatim at compile time.
///
/// AI.md PART 11 "User-Visible Attribution Surface" requires the embedded
/// license data to be reachable at runtime rather than merely shipped in the
/// source repo; `--licenses` / `--credits` print this blob.
///
/// Note for `docker/Dockerfile`: `.dockerignore` must keep `LICENSE.md` in
/// the build context (it is re-included after the blanket `*.md` rule)
/// because this `include_str!` makes it a compile input, not just docs.
pub const LICENSE_TEXT: &str = include_str!("../LICENSE.md");

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards against the embed silently degrading to an empty or truncated
    /// blob — for example if `.dockerignore` starts excluding `LICENSE.md`
    /// from the build context again.
    #[test]
    fn embedded_license_text_is_present_and_complete() {
        assert!(
            LICENSE_TEXT.contains("# Project License"),
            "hand-written license region must be embedded"
        );
        assert!(
            LICENSE_TEXT.contains("# Third-Party Crate Attributions"),
            "generated attribution region must be embedded"
        );
    }
}
