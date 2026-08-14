// Build metadata embedding (AI.md PART 6 "Build Metadata").
use std::{env, fs, path::Path};

fn main() {
    // Re-run this build script when either metadata file changes, otherwise
    // bumping release.txt / site.txt would not invalidate the embedded constants.
    println!("cargo:rerun-if-changed=release.txt");
    println!("cargo:rerun-if-changed=site.txt");

    if Path::new("release.txt").exists() {
        let version = fs::read_to_string("release.txt").unwrap();
        println!("cargo:rustc-env=APP_VERSION={}", version.trim());
    }

    if Path::new("site.txt").exists() {
        let site = fs::read_to_string("site.txt").unwrap();
        println!("cargo:rustc-env=APP_OFFICIAL_SITE={}", site.trim());
    }

    // Map build-environment variables to the APP_* names option_env!() reads.
    // BUILD_DATE is deliberately NOT mapped - the app derives it from BUILD_EPOCH.
    for (src, dst) in [
        ("COMMIT_ID", "APP_COMMIT_ID"),
        ("BUILD_EPOCH", "APP_BUILD_EPOCH"),
    ] {
        println!("cargo:rerun-if-env-changed={}", src);
        if let Ok(val) = env::var(src) {
            println!("cargo:rustc-env={}={}", dst, val.trim());
        }
    }
}
