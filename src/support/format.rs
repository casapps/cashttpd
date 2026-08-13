//! Human-readable formatting helpers for user-facing surfaces (AI.md PART 7
//! "Human-Readable Values (User-Facing Output)"). GUI/TUI/CLI pretty output
//! calls these; machine surfaces (`--json`, `--plain`, log files) keep raw
//! base units and never call into this module.

/// Format a duration in whole seconds as the largest fitting unit, at most
/// two units, with correct singular/plural: `1 second`, `45 seconds`,
/// `3 minutes`, `2 minutes 5 seconds`, `2 hours`, `1 hour 30 minutes`,
/// `3 days 4 hours`.
pub fn duration(total_seconds: u64) -> String {
    fn unit(n: u64, singular: &str, plural: &str) -> String {
        format!("{n} {}", if n == 1 { singular } else { plural })
    }

    if total_seconds < 60 {
        return unit(total_seconds, "second", "seconds");
    }

    let minutes = total_seconds / 60;
    let seconds = total_seconds % 60;
    if minutes < 60 {
        return if seconds == 0 {
            unit(minutes, "minute", "minutes")
        } else {
            format!(
                "{} {}",
                unit(minutes, "minute", "minutes"),
                unit(seconds, "second", "seconds")
            )
        };
    }

    let hours = minutes / 60;
    let rem_minutes = minutes % 60;
    if hours < 24 {
        return if rem_minutes == 0 {
            unit(hours, "hour", "hours")
        } else {
            format!(
                "{} {}",
                unit(hours, "hour", "hours"),
                unit(rem_minutes, "minute", "minutes")
            )
        };
    }

    let days = hours / 24;
    let rem_hours = hours % 24;
    if rem_hours == 0 {
        unit(days, "day", "days")
    } else {
        format!(
            "{} {}",
            unit(days, "day", "days"),
            unit(rem_hours, "hour", "hours")
        )
    }
}

/// Format a byte count on 1024 boundaries with full unit names, at most one
/// decimal place, dropping a trailing `.0`: `1 byte`, `512 bytes`,
/// `1 kilobyte`, `2.5 megabytes`, `5 gigabytes`, `1.2 terabytes`.
pub fn size(bytes: u64) -> String {
    const UNITS: [(&str, &str); 5] = [
        ("byte", "bytes"),
        ("kilobyte", "kilobytes"),
        ("megabyte", "megabytes"),
        ("gigabyte", "gigabytes"),
        ("terabyte", "terabytes"),
    ];

    if bytes < 1024 {
        let (s, p) = UNITS[0];
        return format!("{bytes} {}", if bytes == 1 { s } else { p });
    }

    let mut value = bytes as f64;
    let mut idx = 0usize;
    while value >= 1024.0 && idx < UNITS.len() - 1 {
        value /= 1024.0;
        idx += 1;
    }

    let rounded = (value * 10.0).round() / 10.0;
    let (s, p) = UNITS[idx];
    let unit_name = if rounded == 1.0 { s } else { p };

    if (rounded - rounded.trunc()).abs() < f64::EPSILON {
        format!("{} {}", rounded.trunc() as u64, unit_name)
    } else {
        format!("{rounded:.1} {unit_name}")
    }
}

/// Format an integer count with locale-aware (currently: US-style comma)
/// thousands separators, e.g. `12,847`.
pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().rev().enumerate() {
        if i != 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_formats() {
        assert_eq!(duration(1), "1 second");
        assert_eq!(duration(45), "45 seconds");
        assert_eq!(duration(180), "3 minutes");
        assert_eq!(duration(125), "2 minutes 5 seconds");
        assert_eq!(duration(7200), "2 hours");
        assert_eq!(duration(5400), "1 hour 30 minutes");
        assert_eq!(duration(90 * 3600 + 4 * 3600 - 90 * 3600), "4 hours");
        assert_eq!(duration(3 * 86400 + 4 * 3600), "3 days 4 hours");
    }

    #[test]
    fn size_formats() {
        assert_eq!(size(1), "1 byte");
        assert_eq!(size(512), "512 bytes");
        assert_eq!(size(1024), "1 kilobyte");
        assert_eq!(size(1024 * 1024 * 5 / 2), "2.5 megabytes");
        assert_eq!(size(5u64 * 1024 * 1024 * 1024), "5 gigabytes");
    }

    #[test]
    fn count_formats() {
        assert_eq!(count(12847), "12,847");
        assert_eq!(count(999), "999");
        assert_eq!(count(1000), "1,000");
    }
}
