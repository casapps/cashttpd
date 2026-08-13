//! Signal handling scaffold for the server/daemon runtime (AI.md PART 14
//! "Signals & Lifecycle", overridden per project-specific rules in IDEA.md
//! "Graceful shutdown and signal handling").
//!
//! IDEA.md deviates from AI.md PART 14's generic daemon defaults in two
//! documented ways: `SIGHUP` does not reload config here (config reload is
//! already handled by live file watching), so it is treated as an ordinary
//! terminating signal identical to `SIGINT`/`SIGTERM`; and there is no
//! `daemon.shutdown_timeout` — graceful shutdown waits for in-flight
//! requests to finish naturally, with no forced cutoff. A *second*
//! `SIGINT`/`SIGTERM` while shutdown is already in progress forces an
//! immediate exit (the explicit "Ctrl-C twice" escape hatch).
//!
//! Full request-draining/child-process-teardown wiring lands with the HTTP
//! listener implementation (see TODO.AI.md); this module owns signal
//! registration and the shutdown-flag state machine only.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::flag;

/// Shared shutdown state: flips to `true` on the first
/// SIGINT/SIGTERM/SIGHUP delivery. A *second* delivery of the same signal
/// is handled entirely at the OS-signal level by
/// `register_conditional_shutdown` in `install_handlers` below and never
/// reaches this struct — see that function's doc comment.
#[derive(Clone)]
pub struct ShutdownState {
    shutdown_requested: Arc<AtomicBool>,
}

impl ShutdownState {
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }
}

/// Register SIGINT/SIGTERM/SIGHUP handlers and return the shared shutdown
/// state the caller polls from its accept/drain loop.
///
/// Each signal gets two handlers, applied in this exact order (signal-hook
/// runs handlers for one signal in registration order):
/// 1. `flag::register_conditional_shutdown` is armed first: it checks
///    `shutdown_requested` *as it stood before this delivery*. On the first
///    delivery the flag is still `false`, so this is a no-op. On a *second*
///    delivery of the same signal — sent while shutdown is already in
///    progress — the flag is already `true`, so this terminates the
///    process immediately, independent of whether the caller's drain loop
///    is still polling. This is the "Ctrl-C twice forces immediate exit"
///    escape hatch from IDEA.md "Graceful shutdown and signal handling".
/// 2. `flag::register` runs second and flips `shutdown_requested` to
///    `true` — the caller's accept/drain loop polls this to start graceful
///    shutdown. Registering it second guarantees step 1 always observes
///    the pre-delivery value, never the value this same delivery just set.
pub fn install_handlers() -> std::io::Result<ShutdownState> {
    let shutdown_requested = Arc::new(AtomicBool::new(false));

    for sig in [SIGINT, SIGTERM, SIGHUP] {
        flag::register_conditional_shutdown(sig, 1, Arc::clone(&shutdown_requested))?;
        flag::register(sig, Arc::clone(&shutdown_requested))?;
    }

    Ok(ShutdownState { shutdown_requested })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_has_no_shutdown_requested() {
        let state = ShutdownState {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
        };
        assert!(!state.is_shutdown_requested());
    }
}
