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
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

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
    child_pid: Arc<AtomicI32>,
}

impl ShutdownState {
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Records the PID of a framework dev-server child process (IDEA.md
    /// "Framework dev-server proxying" — "no orphaned processes left
    /// running after cashttpd exits, under any exit path") so the raw
    /// signal handler installed by `install_handlers` can terminate it on
    /// *every* delivery of SIGINT/SIGTERM/SIGHUP, including the "second
    /// signal forces an immediate exit" path, which bypasses ordinary
    /// `Drop`-based cleanup entirely.
    pub fn track_child_process(&self, pid: u32) {
        self.child_pid.store(pid as i32, Ordering::SeqCst);
    }

    /// Clears the tracked child PID once the caller has already killed and
    /// reaped it itself on the ordinary graceful-shutdown path, so a late
    /// signal delivered after that point never signals a stale/reused PID.
    pub fn clear_child_process(&self) {
        self.child_pid.store(0, Ordering::SeqCst);
    }

    /// Builds a fresh, never-shutdown-requested state without registering
    /// any real OS signal handler — for tests that need a `ShutdownState`
    /// to pass into code under test (e.g. `servers::apply_reload`) but must
    /// not risk a real `SIGINT`/`SIGTERM`/`SIGHUP` handler registration
    /// firing across unrelated tests sharing the same test binary process.
    #[cfg(test)]
    pub fn new_for_test() -> Self {
        Self {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            child_pid: Arc::new(AtomicI32::new(0)),
        }
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
    let child_pid = Arc::new(AtomicI32::new(0));

    for sig in [SIGINT, SIGTERM, SIGHUP] {
        // Registered first so it runs on *every* delivery of this signal —
        // including the very first one. A tracked framework dev-server
        // child (see `ShutdownState::track_child_process`) can't wait for
        // the graceful drain loop to notice `shutdown_requested`, because a
        // *second* delivery below terminates the process immediately via
        // `flag::register_conditional_shutdown`, which never runs ordinary
        // `Drop` cleanup.
        let pid_for_handler = Arc::clone(&child_pid);
        // SAFETY: the closure only loads an `AtomicI32` and, if non-zero,
        // calls `kill(2)` via `nix` — both are async-signal-safe operations
        // with no allocation, locking, or panicking path.
        unsafe {
            signal_hook::low_level::register(sig, move || {
                let pid = pid_for_handler.load(Ordering::SeqCst);
                if pid > 0 {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid),
                        nix::sys::signal::Signal::SIGTERM,
                    );
                }
            })?;
        }
        flag::register_conditional_shutdown(sig, 1, Arc::clone(&shutdown_requested))?;
        flag::register(sig, Arc::clone(&shutdown_requested))?;
    }

    Ok(ShutdownState {
        shutdown_requested,
        child_pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_has_no_shutdown_requested() {
        let state = ShutdownState {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            child_pid: Arc::new(AtomicI32::new(0)),
        };
        assert!(!state.is_shutdown_requested());
    }

    #[test]
    fn track_and_clear_child_process_round_trips() {
        let state = ShutdownState {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            child_pid: Arc::new(AtomicI32::new(0)),
        };
        state.track_child_process(4242);
        assert_eq!(state.child_pid.load(Ordering::SeqCst), 4242);
        state.clear_child_process();
        assert_eq!(state.child_pid.load(Ordering::SeqCst), 0);
    }
}
