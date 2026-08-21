//! NO_COLOR support and the TUI/CLI ANSI-mapped color palette (AI.md
//! PART 7 "NO_COLOR Support" / "Color Enablement Precedence" /
//! "Color Palette (TUI/CLI/GUI)"). This is a single native-terminal binary
//! (TUI + CLI only, no GUI, no served web frontend), so there is no web CSS
//! token palette here — see AI.md PART 7 "Color Palette" for that rule.

use std::io::IsTerminal;

/// ANSI 16-color indices (0-15) for TUI/CLI semantic roles.
/// `ratatui::style::Color::Indexed()` and the `ESC[38;5;{n}m` escape both
/// accept these indices directly.
///
/// AI.md's own reference snippet derives `Serialize`/`Deserialize` here;
/// that derive is deferred until config-file loading needs it — see
/// TODO.AI.md for why (this toolchain image's host triple is itself
/// `x86_64-unknown-linux-musl`, so the project's own required
/// `.cargo/config.toml` `+crt-static` rustflag for that exact target also
/// applies to proc-macro/build-script compilation, which cannot produce a
/// `crt-static` dylib — any proc-macro-derive dependency, `serde_derive`
/// included, fails to build under plain `cargo build`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalPalette {
    pub foreground: String,
    pub muted: String,
    pub primary: String,
    pub success: String,
    pub warning: String,
    pub error: String,
    pub info: String,
    pub border: String,
}

pub fn terminal_palette_dark() -> TerminalPalette {
    TerminalPalette {
        foreground: "15".into(),
        muted: "7".into(),
        primary: "13".into(),
        success: "10".into(),
        warning: "11".into(),
        error: "9".into(),
        info: "12".into(),
        border: "13".into(),
    }
}

pub fn terminal_palette_light() -> TerminalPalette {
    TerminalPalette {
        foreground: "0".into(),
        muted: "8".into(),
        primary: "4".into(),
        success: "2".into(),
        warning: "3".into(),
        error: "1".into(),
        info: "4".into(),
        border: "4".into(),
    }
}

/// Return true if color output should be used. CLI and TUI output MUST
/// gate on this — never a separate ad hoc `NO_COLOR` check.
///
/// Precedence: CLI flag > config file > `NO_COLOR` env var > TTY/TERM
/// auto-detect.
pub fn color_enabled(force_color: Option<bool>) -> bool {
    // 1. CLI flag overrides everything.
    if let Some(forced) = force_color {
        return forced;
    }

    // 2. Config file — no persisted `output.color` setting exists yet
    //    (see TODO.AI.md); when config gains one, check it here before
    //    falling through to NO_COLOR/TTY detection.

    // 3. NO_COLOR env var (non-empty = disable).
    if std::env::var("NO_COLOR")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        return false;
    }

    // 4. Auto-detect: TTY + TERM support.
    if !std::io::stdout().is_terminal() {
        return false;
    }
    if std::env::var("TERM").map(|v| v == "dumb").unwrap_or(false) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_flag_wins() {
        assert!(color_enabled(Some(true)));
        assert!(!color_enabled(Some(false)));
    }

    #[test]
    fn dark_and_light_palettes_differ() {
        assert_ne!(
            terminal_palette_dark().primary,
            terminal_palette_light().primary
        );
    }
}
