//! CLI-style plain output surface — used for `--daemon` and non-interactive
//! fallback (AI.md PART 3), and the `serve` subcommand entry point (AI.md
//! PART 14 "Runtime Model": `serve` always forces CLI mode).

/// Entry point for CLI-style mode. Full flag parsing, config loading, and
/// remaining CLI flags beyond `--config-test`/`serve` are tracked in
/// TODO.AI.md.
pub fn run() {
    let args: Vec<String> = std::env::args().collect();

    // `--version` / `-V`: print version plus embedded build metadata (AI.md
    // PART 6 "Build Metadata") and exit.
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!(
            "cashttpd {} (commit {}, built {}){}",
            crate::support::version::VERSION,
            crate::support::version::COMMIT_ID,
            crate::support::version::BUILD_DATE,
            if crate::support::version::OFFICIAL_SITE.is_empty() {
                String::new()
            } else {
                format!(" — {}", crate::support::version::OFFICIAL_SITE)
            }
        );
        std::process::exit(0);
    }

    // `--config-test` / `-t`: parse and validate config, print errors to
    // stderr, exit 0 (valid) or 1 (invalid); never touches sockets or
    // running state (AI.md PART 14 "Signals & Lifecycle").
    if args.iter().any(|a| a == "--config-test" || a == "-t") {
        match crate::config::validate() {
            Ok(()) => {
                println!("cashttpd: configuration syntax is ok");
                std::process::exit(0);
            }
            Err(err) => {
                eprintln!("cashttpd: configuration error: {err}");
                std::process::exit(1);
            }
        }
    }

    // `serve`: starts the daemon in the foreground (AI.md PART 14 "Runtime
    // Model" — never self-daemonizes; systemd/the container runtime
    // supervises it).
    if args.iter().any(|a| a == "serve") {
        let opts = crate::server::parse_serve_options(&args);
        if let Err(err) = crate::server::run(opts) {
            eprintln!("cashttpd: fatal: {err}");
            std::process::exit(1);
        }
        return;
    }

    println!("cashttpd {} (cli mode)", crate::support::version::VERSION);
}
