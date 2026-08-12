//! Terminal UI surface — the default when run in the foreground on a
//! capable terminal (AI.md PART 3).

/// Entry point for TUI mode. Full ratatui-based UI is tracked in
/// TODO.AI.md.
pub fn run() {
    println!("cashttpd {} (tui mode)", crate::support::version::VERSION);
}
