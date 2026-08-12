//! CLI-style plain output surface — used for `--daemon` and non-interactive
//! fallback (AI.md PART 3).

/// Entry point for CLI-style mode. Full flag parsing, config loading, and
/// server startup are tracked in TODO.AI.md.
pub fn run() {
    println!("cashttpd {} (cli mode)", crate::support::version::VERSION);
}
