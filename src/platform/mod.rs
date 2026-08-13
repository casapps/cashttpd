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
