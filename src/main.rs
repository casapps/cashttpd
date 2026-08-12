//! cashttpd — RFC-compliant local-development HTTP/HTTPS server.
//!
//! Picks the presentation mode (TUI vs CLI-style) per AI.md PART 3
//! "Runtime Mode Selection", then hands off to the shared application core.

mod app;
mod assets;
mod config;
mod platform;
mod server;
mod state;
mod support;
mod ui;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();

    let mode = ui::detect_ui_mode(&args);

    match mode {
        ui::UiMode::Tui => ui::tui::run(),
        ui::UiMode::Cli => ui::cli::run(),
    }
}
