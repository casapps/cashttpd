//! CLI-style plain output surface — used for `--daemon` and non-interactive
//! fallback (AI.md PART 3), and the `serve` subcommand entry point (AI.md
//! PART 14 "Runtime Model": `serve` always forces CLI mode).

use clap::parser::ValueSource;
use clap::{Arg, ArgAction, Command};

/// Builds the top-level flag/subcommand grammar for the CLI-style surface
/// (IDEA.md "CLI flags (full reference)"). Uses clap's builder API rather
/// than `features = ["derive"]` — the derive proc-macro cannot be built on
/// this project's musl-hosted, `+crt-static` toolchain (see the `clap`
/// dependency comment in `Cargo.toml`) — but still gets `--help`/`-h` and
/// per-subcommand help generated for free instead of hand-rolled
/// `std::env::args()` scanning. `--version` keeps its own hand-written
/// output (embedded build metadata), so clap's automatic version flag is
/// disabled here and replaced below with an equivalent `--version`/`-v`
/// arg (AI.md "Standard CLI Flags" — `-v` is the required short form) that
/// this module's own handler renders.
fn cli() -> Command {
    Command::new("cashttpd")
        .about("RFC-compliant local-development HTTP/HTTPS server.")
        .disable_version_flag(true)
        .arg(
            Arg::new("version")
                .long("version")
                .short('v')
                .help("Print version plus embedded build metadata and exit")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("config-test")
                .long("config-test")
                .short('t')
                .help(
                    "Parse and validate configuration, print errors to \
                     stderr, exit 0/1 without starting the server",
                )
                .action(ArgAction::SetTrue),
        )
        .arg(color_arg())
        .arg(
            Arg::new("daemon")
                .long("daemon")
                .help(
                    "Force CLI-style output regardless of terminal \
                     capability (consumed before this parser runs; \
                     accepted here so a real invocation still validates)",
                )
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            Command::new("serve")
                .about("Start the HTTP/HTTPS server in the foreground")
                .arg(
                    Arg::new("quiet")
                        .long("quiet")
                        .help("Suppress ongoing access/error line echo")
                        .action(ArgAction::SetTrue),
                )
                .arg(Arg::new("listen").long("listen").value_name("address"))
                .arg(
                    Arg::new("port")
                        .long("port")
                        .value_name("port")
                        .value_parser(clap::value_parser!(u16)),
                )
                .arg(
                    Arg::new("dir")
                        .long("dir")
                        .value_name("dir")
                        .value_parser(clap::value_parser!(std::path::PathBuf)),
                )
                .arg(Arg::new("fqdn").long("fqdn").value_name("fqdn"))
                .arg(
                    Arg::new("log")
                        .long("log")
                        .value_name("dir")
                        .value_parser(clap::value_parser!(std::path::PathBuf)),
                )
                .arg(
                    Arg::new("config")
                        .long("config")
                        .value_name("file")
                        .value_parser(clap::value_parser!(std::path::PathBuf)),
                )
                .arg(color_arg())
                .arg(
                    Arg::new("debug")
                        .long("debug")
                        .help("Enable debug/tracing mode")
                        .action(ArgAction::SetTrue),
                ),
        )
}

/// The standard three-value `--color` flag, declared identically at the top
/// level and on `serve` so it is accepted on either side of the subcommand.
/// There is deliberately no `--no-color`: `--color no` and the `NO_COLOR`
/// environment variable are the two documented ways to turn color off.
fn color_arg() -> Arg {
    Arg::new("color")
        .long("color")
        .value_name("when")
        .default_value("auto")
        .value_parser(["auto", "yes", "no"])
        .help("Color output: auto (TTY detect), yes (force on), no (force off)")
}

/// Entry point for CLI-style mode.
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(run_with_args(&args));
}

/// Dispatch logic split out from `run()` so it is unit testable without
/// invoking `std::process::exit` on the test process itself — `run()`
/// remains the real entry point and still exits with the code this
/// returns. The `serve` branch is intentionally not covered by unit tests
/// here since it starts a real listener; `servers::run` and
/// `servers::parse_serve_options` have their own direct unit tests instead.
/// `args` includes the program name at index 0, matching `std::env::args()`
/// and clap's own expected `argv` shape.
fn run_with_args(args: &[String]) -> i32 {
    let matches = match cli().try_get_matches_from(args) {
        Ok(matches) => matches,
        Err(err) => {
            let _ = err.print();
            return err.exit_code();
        }
    };

    // `--color` is resolved before anything is printed, so even `--version`
    // and clap's own error output obey it. The subcommand's own occurrence
    // wins when both are given (`cashttpd --color yes serve --color no`),
    // matching how clap scopes a repeated flag.
    let color = matches
        .subcommand_matches("serve")
        .filter(|serve| serve.value_source("color") == Some(ValueSource::CommandLine))
        .and_then(|serve| serve.get_one::<String>("color"))
        .or_else(|| matches.get_one::<String>("color"))
        .map(String::as_str)
        .unwrap_or("auto");
    crate::supports::color::set_cli_color(crate::supports::color::parse_color_flag(color));

    // `--version` / `-v`: print version plus embedded build metadata (AI.md
    // PART 6 "Build Metadata") and exit.
    if matches.get_flag("version") {
        println!(
            "cashttpd {} (commit {}, built {}){}",
            crate::supports::version::VERSION,
            crate::supports::version::COMMIT_ID,
            crate::supports::version::build_date(),
            if crate::supports::version::OFFICIAL_SITE.is_empty() {
                String::new()
            } else {
                format!(" — {}", crate::supports::version::OFFICIAL_SITE)
            }
        );
        return 0;
    }

    // `--config-test` / `-t`: parse and validate config, print errors to
    // stderr, exit 0 (valid) or 1 (invalid); never touches sockets or
    // running state (AI.md PART 14 "Signals & Lifecycle").
    if matches.get_flag("config-test") {
        let overrides = crate::servers::parse_cli_overrides(args);
        return match crate::configs::validate(&overrides) {
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
    // supervises it). `--daemon` (background, forces CLI-style output) and
    // `--quiet` (suppress ongoing access/error line echo — file logging
    // stays unconditional) are CLI-only invocation flags, never persisted
    // to config (IDEA.md "CLI flags (full reference)").
    if let Some(serve_matches) = matches.subcommand_matches("serve") {
        let quiet = serve_matches.get_flag("quiet");
        // The actual override values are re-derived from the raw argument
        // list by `crate::servers::parse_serve_options`/`parse_cli_overrides`
        // — the single place that layers CLI flag > env var > per-project
        // config > global config > built-in default (IDEA.md's documented
        // precedence chain) — rather than from `serve_matches`, so that
        // precedence logic stays centralized in one function instead of
        // being duplicated here.
        let (opts, cli_overrides) = crate::servers::parse_serve_options(args);
        return match crate::servers::run(opts, quiet, cli_overrides) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("cashttpd: fatal: {err}");
                1
            }
        };
    }

    println!("cashttpd {} (cli mode)", crate::supports::version::VERSION);
    0
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
    fn version_flag_prints_and_reports_success() {
        assert_eq!(run_with_args(&args(&["--version"])), 0);
        assert_eq!(run_with_args(&args(&["-v"])), 0);
    }

    #[test]
    fn config_test_flag_reports_success_when_no_config_files_exist() {
        assert_eq!(run_with_args(&args(&["--config-test"])), 0);
        assert_eq!(run_with_args(&args(&["-t"])), 0);
    }

    #[test]
    fn no_recognized_flags_falls_back_to_cli_banner_and_reports_success() {
        assert_eq!(run_with_args(&args(&[])), 0);
    }

    #[test]
    fn help_flag_is_provided_by_clap_and_exits_successfully() {
        assert_eq!(run_with_args(&args(&["--help"])), 0);
        assert_eq!(run_with_args(&args(&["-h"])), 0);
    }

    #[test]
    fn color_flag_is_accepted_in_both_forms_and_rejects_other_values() {
        assert_eq!(run_with_args(&args(&["--color", "no", "--version"])), 0);
        assert_eq!(run_with_args(&args(&["--color=yes", "--version"])), 0);
        assert_eq!(run_with_args(&args(&["--color", "auto", "--version"])), 0);
        assert_ne!(run_with_args(&args(&["--color", "sometimes"])), 0);
    }

    #[test]
    fn color_flag_is_also_accepted_on_the_serve_subcommand() {
        let matches = cli()
            .try_get_matches_from(args(&["serve", "--color", "no"]))
            .expect("serve accepts --color");
        let serve = matches.subcommand_matches("serve").unwrap();
        assert_eq!(
            serve.get_one::<String>("color").map(String::as_str),
            Some("no")
        );
        assert_eq!(
            serve.value_source("color"),
            Some(ValueSource::CommandLine),
            "an explicit serve-level --color must outrank the top-level default"
        );
    }

    #[test]
    fn unknown_flag_reports_failure() {
        assert_ne!(run_with_args(&args(&["--not-a-real-flag"])), 0);
    }
}
