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

/// Build date embedded at build time, `"N/A"` when unavailable.
pub const BUILD_DATE: &str = match option_env!("APP_BUILD_DATE") {
    Some(v) => v,
    None => "N/A",
};
