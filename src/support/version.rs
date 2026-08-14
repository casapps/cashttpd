//! Version, commit, build-date, and site metadata (AI.md PART 6).

/// Version string: `release.txt` when present at build time, else the
/// `Cargo.toml` package version.
pub const VERSION: &str = match option_env!("APP_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// Official site URL, empty when unset (`site.txt` > `IDEA.md` > env > empty).
pub const OFFICIAL_SITE: &str = match option_env!("APP_OFFICIAL_SITE") {
    Some(v) => v,
    None => "",
};

/// Git commit ID embedded at build time, `"N/A"` when unavailable.
pub const COMMIT_ID: &str = match option_env!("APP_COMMIT_ID") {
    Some(v) => v,
    None => "N/A",
};

/// Build epoch (Unix seconds, UTC) embedded at build time, `"0"` when unset.
pub const BUILD_EPOCH: &str = match option_env!("APP_BUILD_EPOCH") {
    Some(v) => v,
    None => "0",
};

/// Build date derived from `BUILD_EPOCH` (RFC 3339 UTC); `"N/A"` when unset.
///
/// Formatted by hand from `time::OffsetDateTime` field accessors rather than
/// via the crate's `formatting` feature — `time` is already a dependency
/// (`server::tls` certificate validity) and this avoids pulling in an extra
/// feature/dependency surface for a single fixed-format timestamp.
pub fn build_date() -> String {
    match BUILD_EPOCH.parse::<i64>() {
        Ok(n) if n > 0 => match time::OffsetDateTime::from_unix_timestamp(n) {
            Ok(t) => format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                t.year(),
                t.month() as u8,
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            ),
            Err(_) => "N/A".into(),
        },
        _ => "N/A".into(),
    }
}
