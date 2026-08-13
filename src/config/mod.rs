//! Configuration loading and defaults (IDEA.md "Configuration file",
//! "CLI flags (full reference)"). Layering: CLI flag > environment variable
//! > per-project config > global config > built-in default.

/// Parse and validate the effective configuration without touching sockets
/// or running state — backs `--config-test` / `-t` (AI.md PART 14
/// "Signals & Lifecycle", required for this project since IDEA.md declares
/// it an RFC-compliant HTTP/1.1+ server). Full config-file parsing lands
/// with the config-loading implementation; see TODO.AI.md.
pub fn validate() -> Result<(), String> {
    Ok(())
}
