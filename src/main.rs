//! cashttpd — RFC-compliant local-development HTTP/HTTPS server.
//!
//! Picks the presentation mode (TUI vs CLI-style) per AI.md PART 3
//! "Runtime Mode Selection", then hands off to the shared application core.

mod apps;
mod assets;
mod configs;
mod platforms;
mod servers;
mod states;
mod supports;
mod uis;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();

    let mode = uis::detect_ui_mode(&args);

    match mode {
        uis::UiMode::Tui => uis::tui::run(),
        uis::UiMode::Cli => uis::cli::run(),
    }
}
