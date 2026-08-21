//! OS/platform integration — per-user config/data/cache/log path
//! resolution (AI.md PART 4 "Path Rule"), using the frozen
//! `internal_org`/`internal_name` identifiers.

/// Dedicated non-root user/group name the binary creates and drops
/// privileges to when started as root inside a container (AI.md PART 5
/// "Container Runtime Rules" -> "Privilege drop, not Dockerfile users").
pub const SERVICE_USER: &str = "cashttpd";

/// If running as root (uid 0) on Unix, create `SERVICE_USER`'s dedicated
/// user/group if they don't already exist, then drop to that identity.
/// No-op (and no error) when not running as root, or on non-Unix targets —
/// privilege drop only applies to the root-started-in-container case.
#[cfg(unix)]
pub fn drop_privileges_if_root() -> std::io::Result<()> {
    use nix::unistd::{Uid, setgid, setuid};

    if !Uid::effective().is_root() {
        return Ok(());
    }

    let (uid, gid) = ensure_service_account()?;
    // Drop the group first, then the user — dropping uid first would
    // remove the permission needed to change gid afterward.
    setgid(gid).map_err(std::io::Error::from)?;
    setuid(uid).map_err(std::io::Error::from)?;
    Ok(())
}

#[cfg(not(unix))]
pub fn drop_privileges_if_root() -> std::io::Result<()> {
    Ok(())
}

/// Honestly-scoped, human-readable summary of what cashttpd actually does
/// (and does not) to contain a served request, for display on the
/// `/server-info` dashboard (IDEA.md "`/server-info` diagnostics dashboard"
/// — "sandboxing/child-lifecycle posture"). Only describes capability that
/// genuinely exists elsewhere in this codebase (`drop_privileges_if_root`)
/// — never overstates protection that isn't implemented, such as
/// process-tree isolation, cgroup/rlimit containment, or a seccomp filter,
/// none of which cashttpd currently applies to spawned CGI/script children
/// or the framework dev-server child process.
#[cfg(unix)]
pub fn sandboxing_posture() -> &'static str {
    "privilege drop only (root, if started as root, drops to the dedicated \
     cashttpd service user/group after binding); no process-tree isolation, \
     cgroup/rlimit containment, or seccomp filtering is applied to spawned \
     CGI/script or framework dev-server child processes"
}

#[cfg(not(unix))]
pub fn sandboxing_posture() -> &'static str {
    "no privilege drop or process containment on this platform; CGI/script \
     and framework dev-server child processes run with the same privileges \
     as cashttpd itself"
}

/// Ensure `SERVICE_USER`'s system user/group exist, creating them via
/// direct `/etc/passwd` / `/etc/group` entries if missing (the runtime
/// image ships no `useradd`/`adduser` binary — see AI.md PART 5 "Container
/// Runtime Rules"). Returns the resolved `(uid, gid)`.
#[cfg(unix)]
fn ensure_service_account() -> std::io::Result<(nix::unistd::Uid, nix::unistd::Gid)> {
    use nix::unistd::{Gid, Uid};
    use std::fs::OpenOptions;
    use std::io::Write;

    const SERVICE_UID: u32 = 8877;
    const SERVICE_GID: u32 = 8877;

    let group_line = std::fs::read_to_string("/etc/group")
        .unwrap_or_default()
        .lines()
        .any(|line| line.split(':').next() == Some(SERVICE_USER));
    if !group_line {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/etc/group")?;
        writeln!(f, "{SERVICE_USER}:x:{SERVICE_GID}:")?;
    }

    let user_line = std::fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .any(|line| line.split(':').next() == Some(SERVICE_USER));
    if !user_line {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/etc/passwd")?;
        writeln!(
            f,
            "{SERVICE_USER}:x:{SERVICE_UID}:{SERVICE_GID}:cashttpd service user:/nonexistent:/sbin/nologin"
        )?;
    }

    Ok((Uid::from_raw(SERVICE_UID), Gid::from_raw(SERVICE_GID)))
}

/// Per-user platform-standard directories (AI.md PART 4 "Path Rule"),
/// anchored on the frozen `internal_org`/`internal_name` pair
/// (`casapps`/`cashttpd`) so a project/org rename never moves user data.
pub mod paths {
    use std::path::PathBuf;

    const INTERNAL_ORG: &str = "casapps";
    const INTERNAL_NAME: &str = "cashttpd";

    fn home() -> PathBuf {
        #[cfg(windows)]
        {
            std::env::var_os("USERPROFILE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
        }
        #[cfg(not(windows))]
        {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
        }
    }

    /// Per-user config directory — `~/.config/casapps/cashttpd/` on Linux/
    /// BSD, the macOS `Application Support/.../config/` variant, or
    /// `%AppData%\casapps\cashttpd\config\` on Windows.
    pub fn config_dir() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            home()
                .join("Library/Application Support")
                .join(INTERNAL_ORG)
                .join(INTERNAL_NAME)
                .join("config")
        }
        #[cfg(windows)]
        {
            std::env::var_os("AppData")
                .map(PathBuf::from)
                .unwrap_or_else(home)
                .join(INTERNAL_ORG)
                .join(INTERNAL_NAME)
                .join("config")
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home().join(".config"))
                .join(INTERNAL_ORG)
                .join(INTERNAL_NAME)
        }
    }

    /// Per-user data directory — see `config_dir()` for the per-OS pattern
    /// this mirrors. Used for TLS certificate storage
    /// (`{data_dir}/certs/{derived_name}/` per IDEA.md "TLS certificate
    /// resolution") — see `servers::tls::cert_dir()`.
    pub fn data_dir() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            home()
                .join("Library/Application Support")
                .join(INTERNAL_ORG)
                .join(INTERNAL_NAME)
                .join("data")
        }
        #[cfg(windows)]
        {
            std::env::var_os("LocalAppData")
                .map(PathBuf::from)
                .unwrap_or_else(home)
                .join(INTERNAL_ORG)
                .join(INTERNAL_NAME)
                .join("data")
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home().join(".local/share"))
                .join(INTERNAL_ORG)
                .join(INTERNAL_NAME)
        }
    }

    /// Per-user log directory (the default `--log`/`log_dir` target) — see
    /// `config_dir()` for the per-OS pattern this mirrors.
    pub fn log_dir() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            home()
                .join("Library/Logs")
                .join(INTERNAL_ORG)
                .join(INTERNAL_NAME)
        }
        #[cfg(windows)]
        {
            std::env::var_os("LocalAppData")
                .map(PathBuf::from)
                .unwrap_or_else(home)
                .join(INTERNAL_ORG)
                .join(INTERNAL_NAME)
                .join("logs")
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home().join(".local/state"))
                .join(INTERNAL_ORG)
                .join(INTERNAL_NAME)
                .join("logs")
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn config_data_log_dirs_are_distinct_and_non_empty() {
            let c = config_dir();
            let d = data_dir();
            let l = log_dir();
            assert!(!c.as_os_str().is_empty());
            assert!(!d.as_os_str().is_empty());
            assert!(!l.as_os_str().is_empty());
            assert_ne!(c, d);
            assert_ne!(d, l);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandboxing_posture_is_non_empty() {
        assert!(!sandboxing_posture().is_empty());
    }
}

// No unit tests for `drop_privileges_if_root()` / `ensure_service_account()`:
// the project's toolchain container (`casjaysdev/rust:latest`) runs as real
// root, so calling `drop_privileges_if_root()` in-process would take the
// genuine root path — writing to `/etc/passwd`/`/etc/group` and calling
// `setuid`/`setgid`, which is process-wide and would permanently drop
// privileges for every other test sharing this test binary's process
// (Rust's test harness runs tests as threads within one process). There is
// no safe non-root branch to exercise here without either running the
// entire test binary as a non-root user (not how CI invokes `cargo test`)
// or refactoring privilege-drop out of a directly-callable function, which
// is a larger design change than this coverage pass is scoped to make.
