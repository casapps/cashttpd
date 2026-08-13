//! CLI-style plain output surface — used for `--daemon` and non-interactive
//! fallback (AI.md PART 3), and the `serve` subcommand entry point (AI.md
//! PART 14 "Runtime Model": `serve` always forces CLI mode).

/// Entry point for CLI-style mode. Full flag parsing, config loading, and
/// remaining CLI flags beyond `--config-test`/`serve` are tracked in
/// TODO.AI.md.
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(run_with_args(&args));
}

/// Dispatch logic split out from `run()` so it is unit testable without
/// invoking `std::process::exit` on the test process itself — `run()`
/// remains the real entry point and still exits with the code this
/// returns. The `serve` branch is intentionally not covered by unit tests
/// here since it starts a real listener; `server::run` and
/// `server::parse_serve_options` have their own direct unit tests instead.
fn run_with_args(args: &[String]) -> i32 {
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
        return 0;
    }

    // `--config-test` / `-t`: parse and validate config, print errors to
    // stderr, exit 0 (valid) or 1 (invalid); never touches sockets or
    // running state (AI.md PART 14 "Signals & Lifecycle").
    if args.iter().any(|a| a == "--config-test" || a == "-t") {
        return match crate::config::validate() {
            Ok(()) => {
                println!("cashttpd: configuration syntax is ok");
                0
            }
            Err(err) => {
                eprintln!("cashttpd: configuration error: {err}");
                1
            }
        };
    }

    // `serve`: starts the daemon in the foreground (AI.md PART 14 "Runtime
    // Model" — never self-daemonizes; systemd/the container runtime
    // supervises it).
    if args.iter().any(|a| a == "serve") {
        let opts = crate::server::parse_serve_options(args);
        return match crate::server::run(opts) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("cashttpd: fatal: {err}");
                1
            }
        };
    }

    println!("cashttpd {} (cli mode)", crate::support::version::VERSION);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_flag_prints_and_reports_success() {
        assert_eq!(run_with_args(&["--version".to_string()]), 0);
        assert_eq!(run_with_args(&["-V".to_string()]), 0);
    }

    #[test]
    fn config_test_flag_reports_success_since_validate_is_currently_infallible() {
        assert_eq!(run_with_args(&["--config-test".to_string()]), 0);
        assert_eq!(run_with_args(&["-t".to_string()]), 0);
    }

    #[test]
    fn no_recognized_flags_falls_back_to_cli_banner_and_reports_success() {
        assert_eq!(run_with_args(&[]), 0);
    }
}
