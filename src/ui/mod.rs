//! Presentation-mode dispatch (AI.md PART 3 "Runtime Mode Selection").

pub mod cli;
pub mod tui;

use std::io::IsTerminal;

/// The two presentation surfaces this project ever offers. No GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiMode {
    Tui,
    Cli,
}

/// Selects TUI vs CLI-style output per the priority order in AI.md PART 3:
/// `--daemon` forces CLI-style; otherwise TUI unless the terminal is
/// incapable (non-TTY, `TERM=dumb`, `CI`, etc.), which falls back to CLI.
pub fn detect_ui_mode(args: &[String]) -> UiMode {
    if args.iter().any(|a| a == "--daemon") {
        return UiMode::Cli;
    }

    let stdin_tty = std::io::stdin().is_terminal();
    let stdout_tty = std::io::stdout().is_terminal();
    let term_dumb = std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false);
    let ci = std::env::var("CI")
        .map(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false);

    if stdin_tty && stdout_tty && !term_dumb && !ci {
        UiMode::Tui
    } else {
        UiMode::Cli
    }
}
