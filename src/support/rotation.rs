//! Log rotation and retention (AI.md PART 7 "Logging & Log Rotation",
//! IDEA.md "Log rotation and retention") — shared by the access and error
//! log streams. Rotation is checked opportunistically (before each write,
//! and once at startup to catch files that aged out while the server
//! wasn't running), never via an always-running timer.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// A parsed `rotate:` policy (AI.md "Rotation Options") — time-based,
/// size-based, or both combined (`weekly,50MB`), whichever fires first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeUnit {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RotatePolicy {
    pub time: Option<TimeUnit>,
    pub size_bytes: Option<u64>,
}

/// A parsed `keep:` retention policy (AI.md "Retention Options").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepPolicy {
    None,
    Count(u32),
    Days(u32),
    Weeks(u32),
    Months(u32),
    Forever,
}

pub fn parse_rotate(spec: &str) -> RotatePolicy {
    let mut policy = RotatePolicy::default();
    for part in spec.split(',') {
        let part = part.trim();
        match part.to_ascii_lowercase().as_str() {
            "never" => {}
            "daily" => policy.time = Some(TimeUnit::Daily),
            "weekly" => policy.time = Some(TimeUnit::Weekly),
            "monthly" => policy.time = Some(TimeUnit::Monthly),
            "yearly" => policy.time = Some(TimeUnit::Yearly),
            other => {
                if let Some(mb) = other.strip_suffix("mb") {
                    if let Ok(n) = mb.parse::<u64>() {
                        policy.size_bytes = Some(n * 1024 * 1024);
                    }
                } else if let Some(gb) = other.strip_suffix("gb") {
                    if let Ok(n) = gb.parse::<u64>() {
                        policy.size_bytes = Some(n * 1024 * 1024 * 1024);
                    }
                }
            }
        }
    }
    policy
}

pub fn parse_keep(spec: &str) -> KeepPolicy {
    let spec = spec.trim().to_ascii_lowercase();
    if spec == "none" || spec.is_empty() {
        return KeepPolicy::None;
    }
    if spec == "forever" {
        return KeepPolicy::Forever;
    }
    if let Some(n) = spec.strip_suffix('d') {
        if let Ok(n) = n.parse() {
            return KeepPolicy::Days(n);
        }
    }
    if let Some(n) = spec.strip_suffix('w') {
        if let Ok(n) = n.parse() {
            return KeepPolicy::Weeks(n);
        }
    }
    if let Some(n) = spec.strip_suffix('m') {
        if let Ok(n) = n.parse() {
            return KeepPolicy::Months(n);
        }
    }
    if let Ok(n) = spec.parse() {
        return KeepPolicy::Count(n);
    }
    KeepPolicy::None
}

/// Proleptic-Gregorian civil date (year, month 1-12, day 1-31) for a Unix
/// timestamp — shared by rotation-period math and `server::format_http_date`.
pub fn civil_date_from_unix(unix_secs: u64) -> (i64, u32, u32) {
    let mut days = (unix_secs / 86400) as i64;
    let mut year = 1970i64;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let year_days = if leap { 366 } else { 365 };
        if days < year_days {
            break;
        }
        days -= year_days;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_lengths = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0usize;
    for (idx, len) in month_lengths.iter().enumerate() {
        if days < *len {
            month = idx;
            break;
        }
        days -= len;
    }
    (year, (month + 1) as u32, (days + 1) as u32)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// True when the time-based portion of `policy` has crossed a period
/// boundary between `period_start_secs` (when the active file was opened
/// or last rotated) and now.
pub fn time_boundary_crossed(unit: TimeUnit, period_start_secs: u64) -> bool {
    let now = now_secs();
    match unit {
        TimeUnit::Daily => civil_date_from_unix(period_start_secs) != civil_date_from_unix(now),
        TimeUnit::Weekly => (now / 86400) / 7 != (period_start_secs / 86400) / 7,
        TimeUnit::Monthly => {
            let (y1, m1, _) = civil_date_from_unix(period_start_secs);
            let (y2, m2, _) = civil_date_from_unix(now);
            (y1, m1) != (y2, m2)
        }
        TimeUnit::Yearly => {
            civil_date_from_unix(period_start_secs).0 != civil_date_from_unix(now).0
        }
    }
}

/// Whether `policy` requires rotating the active log file right now, given
/// its current size and the wall-clock time its current period began.
pub fn should_rotate(policy: &RotatePolicy, current_len: u64, period_start_secs: u64) -> bool {
    if let Some(unit) = policy.time {
        if time_boundary_crossed(unit, period_start_secs) {
            return true;
        }
    }
    if let Some(limit) = policy.size_bytes {
        if current_len >= limit {
            return true;
        }
    }
    false
}

/// Rotates `active_path` (e.g. `{log_dir}/{name}_access.log`) to a
/// date-stamped file in the same directory and applies retention, per
/// IDEA.md "Log rotation and retention" — the active file always stays at
/// the plain name.
pub fn rotate_file(active_path: &Path, keep: KeepPolicy) -> std::io::Result<()> {
    if !active_path.exists() {
        return Ok(());
    }
    let (y, m, d) = civil_date_from_unix(now_secs());
    let stamp = format!("{y:04}-{m:02}-{d:02}");
    let mut rotated = active_path.as_os_str().to_os_string();
    rotated.push(format!("-{stamp}"));
    let rotated_path = PathBuf::from(rotated);
    // If a rotated file for today already exists (rotated more than once in
    // the same day due to a size trigger), append a numeric disambiguator
    // rather than clobbering the previous rotation.
    let mut final_path = rotated_path.clone();
    let mut n = 1;
    while final_path.exists() {
        let mut candidate = active_path.as_os_str().to_os_string();
        candidate.push(format!("-{stamp}.{n}"));
        final_path = PathBuf::from(candidate);
        n += 1;
    }
    std::fs::rename(active_path, &final_path)?;
    apply_retention(active_path, keep)
}

/// Deletes rotated siblings of `active_path` that fall outside `keep`.
/// Checked at each rotation and once at server startup (IDEA.md "Retention
/// is checked at each rotation ... and once at server startup").
pub fn apply_retention(active_path: &Path, keep: KeepPolicy) -> std::io::Result<()> {
    if keep == KeepPolicy::Forever {
        return Ok(());
    }
    let dir = match active_path.parent() {
        Some(d) => d,
        None => return Ok(()),
    };
    let active_name = match active_path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_string(),
        None => return Ok(()),
    };
    let prefix = format!("{active_name}-");

    let mut rotated: Vec<(PathBuf, SystemTime)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with(&prefix) {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((entry.path(), modified))
        })
        .collect();
    rotated.sort_by_key(|(_, m)| *m);

    match keep {
        KeepPolicy::None => {
            for (path, _) in &rotated {
                std::fs::remove_file(path).ok();
            }
        }
        KeepPolicy::Count(n) => {
            let n = n as usize;
            if rotated.len() > n {
                for (path, _) in &rotated[..rotated.len() - n] {
                    std::fs::remove_file(path).ok();
                }
            }
        }
        KeepPolicy::Days(_) | KeepPolicy::Weeks(_) | KeepPolicy::Months(_) => {
            let max_age_secs: u64 = match keep {
                KeepPolicy::Days(n) => n as u64 * 86400,
                KeepPolicy::Weeks(n) => n as u64 * 7 * 86400,
                KeepPolicy::Months(n) => n as u64 * 30 * 86400,
                _ => unreachable!(),
            };
            let now = now_secs();
            for (path, modified) in &rotated {
                let age = now.saturating_sub(
                    modified
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(now),
                );
                if age > max_age_secs {
                    std::fs::remove_file(path).ok();
                }
            }
        }
        KeepPolicy::Forever => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rotate_handles_combined_policy() {
        let p = parse_rotate("weekly,50MB");
        assert_eq!(p.time, Some(TimeUnit::Weekly));
        assert_eq!(p.size_bytes, Some(50 * 1024 * 1024));
    }

    #[test]
    fn parse_rotate_handles_never() {
        let p = parse_rotate("never");
        assert!(p.time.is_none());
        assert!(p.size_bytes.is_none());
    }

    #[test]
    fn parse_keep_handles_all_variants() {
        assert_eq!(parse_keep("none"), KeepPolicy::None);
        assert_eq!(parse_keep("forever"), KeepPolicy::Forever);
        assert_eq!(parse_keep("5"), KeepPolicy::Count(5));
        assert_eq!(parse_keep("30d"), KeepPolicy::Days(30));
        assert_eq!(parse_keep("4w"), KeepPolicy::Weeks(4));
        assert_eq!(parse_keep("2m"), KeepPolicy::Months(2));
    }

    #[test]
    fn civil_date_from_unix_matches_known_date() {
        assert_eq!(civil_date_from_unix(1704067200), (2024, 1, 1));
    }

    #[test]
    fn should_rotate_by_size_limit() {
        let policy = RotatePolicy {
            time: None,
            size_bytes: Some(100),
        };
        assert!(should_rotate(&policy, 150, 0));
        assert!(!should_rotate(&policy, 50, 0));
    }

    #[test]
    fn rotate_file_renames_and_retains_per_keep_policy() {
        let dir = std::env::temp_dir().join(format!(
            "cashttpd-rotate-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let active = dir.join("proj_access.log");
        std::fs::write(&active, b"line one\n").unwrap();

        rotate_file(&active, KeepPolicy::Forever).unwrap();
        assert!(!active.exists());
        let rotated_count = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(rotated_count, 1);

        std::fs::write(&active, b"line two\n").unwrap();
        rotate_file(&active, KeepPolicy::None).unwrap();
        let remaining: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != active.file_name().unwrap())
            .collect();
        assert!(remaining.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
