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

/// Flags and subcommands whose entire purpose is to print to stdout and exit,
/// or to run the server itself. Every one of them is a CLI-style surface with
/// no interactive screen to draw, so none may ever be routed to the TUI.
///
/// Without this list the TUI branch swallows the invocation and the binary is
/// functionally inert from any interactive terminal: `serve` never binds,
/// `--config-test` "passes" with exit 0 without validating anything, and
/// `--version`/`--help` never render. AI.md PART 7 "Standard CLI Flags"
/// requires `--help`/`--version` to exit 0 with their output unconditionally,
/// and AI.md PART 14 "Runtime Model" makes `serve` a CLI-style surface.
const CLI_FORCING_ARGS: [&str; 11] = [
    "serve",
    "--daemon",
    "--quiet",
    "--config-test",
    "-t",
    "--version",
    "-v",
    "--help",
    "-h",
    "--licenses",
    "--credits",
];

/// Selects TUI vs CLI-style output per the priority order in AI.md PART 3
/// "Runtime Mode Selection".
///
/// Priority, highest first:
/// 1. An explicit CLI-forcing flag or subcommand (`CLI_FORCING_ARGS`) —
///    `--daemon` and `--quiet` per IDEA.md "CLI flags (full reference)", the
///    rest because they are print-and-exit or server surfaces.
/// 2. `NO_COLOR` — AI.md PART 7 "NO_COLOR Support" says to prefer CLI/plain
///    rather than force a degraded, color-dependent pseudo-TUI.
/// 3. Terminal capability — non-TTY stdin/stdout, `TERM=dumb`, or `CI` all
///    fall back to CLI.
///
/// Only a bare, interactive, color-capable invocation reaches the TUI.
pub fn detect_ui_mode(args: &[String]) -> UiMode {
    // args[0] is the program name; a path component matching a flag name must
    // not be mistaken for the flag itself.
    if args
        .iter()
        .skip(1)
        .any(|a| CLI_FORCING_ARGS.contains(&a.as_str()))
    {
        return UiMode::Cli;
    }

    let no_color = std::env::var("NO_COLOR")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    let stdin_tty = std::io::stdin().is_terminal();
    let stdout_tty = std::io::stdout().is_terminal();
    let term_dumb = std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false);
    let ci = std::env::var("CI")
        .map(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false);

    if stdin_tty && stdout_tty && !term_dumb && !ci && !no_color {
        UiMode::Tui
    } else {
        UiMode::Cli
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(rest: &[&str]) -> Vec<String> {
        std::iter::once("cashttpd".to_string())
            .chain(rest.iter().map(|s| s.to_string()))
            .collect()
    }

    #[test]
    fn daemon_flag_forces_cli_mode_regardless_of_terminal_state() {
        assert_eq!(detect_ui_mode(&args(&["--daemon"])), UiMode::Cli);
    }

    /// Regression guard: every print-and-exit flag and the `serve` subcommand
    /// must route to CLI. Before this list existed, an interactive terminal
    /// sent all of them to the TUI stub and the binary did nothing at all.
    #[test]
    fn print_and_exit_flags_and_serve_all_force_cli_mode() {
        for flag in CLI_FORCING_ARGS {
            assert_eq!(
                detect_ui_mode(&args(&[flag])),
                UiMode::Cli,
                "{flag} must never be routed to the TUI"
            );
        }
    }

    /// The flag must be recognized wherever it appears, including after the
    /// subcommand, and must not be matched against argv[0].
    #[test]
    fn cli_forcing_args_are_matched_positionally_but_never_in_argv0() {
        assert_eq!(
            detect_ui_mode(&args(&["serve", "--port", "8080"])),
            UiMode::Cli
        );
        assert_eq!(detect_ui_mode(&args(&["serve", "--quiet"])), UiMode::Cli);
        assert_eq!(
            detect_ui_mode(&["/opt/serve/cashttpd".to_string()]),
            detect_ui_mode(&["cashttpd".to_string()]),
            "a path component matching a flag name must not force CLI"
        );
    }

    #[test]
    fn no_daemon_flag_falls_back_to_cli_in_non_terminal_test_harness() {
        // The test harness's stdin/stdout are never a real TTY, so this
        // always takes the non-interactive fallback branch — it still
        // exercises the full decision chain (TERM/CI env reads) without
        // depending on real terminal state.
        let args: Vec<String> = vec![];
        assert_eq!(detect_ui_mode(&args), UiMode::Cli);
    }
}
