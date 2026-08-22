//! HTTP/HTTPS listener, routing, and request handling (IDEA.md
//! "Core behavior", "Security / access control model").
//!
//! Implements: full request-header parsing, persistent (keep-alive)
//! connections, conditional requests (`If-Modified-Since`/`If-None-Match`),
//! single-range `Range` requests, IANA-registry-backed `Content-Type`
//! detection, default-index/opt-in directory listing, embedded mobile-first
//! error pages, `.ht*` trust-boundary denial, and unconditional
//! Apache-format access/error file logging.
//!
//! Also implements CGI 1.1 / multi-language script execution (`cgi-bin/`
//! exec-by-shebang and extension-based `script_handlers` interpreter
//! dispatch), scheduled log rotation/retention, and `.htaccess`/`.htpasswd`
//! Apache-compatible per-directory configuration (`servers::htaccess`) —
//! recursive discovery/cascade merge, `AuthType Basic` + bcrypt/apr1/
//! `{SHA}` `.htpasswd` authentication, `Require`/legacy `Order`/`Allow`/
//! `Deny` authorization, `ErrorDocument`, `DirectoryIndex`, `Options
//! Indexes`/`FollowSymLinks`, and `RewriteEngine`/`RewriteRule`/`Redirect`/
//! `RedirectMatch`, applied per the documented 6-phase per-request order.
//!
//! Also implements framework dev-server proxying (`servers::proxy`, IDEA.md
//! "Framework dev-server proxying"): auto-detected or explicitly configured
//! requests under a `path_prefix` are relayed to a spawned dev-server child
//! process, streamed both ways, with WebSocket/`Upgrade` support.
//!
//! Also implements the `/server-info` diagnostics dashboard (`servers::info`,
//! IDEA.md "`/server-info` diagnostics dashboard"): a built-in, always-on
//! route (dispatched before the framework-proxy prefix check and before the
//! `.htaccess` 6-phase pipeline) rendering live request/response stats,
//! per-handler-type latency, hot paths, and a grouped, click-through error/
//! issue list, entirely from bounded in-memory state distinct from the
//! durable on-disk access/error log.
//!
//! Also implements live config-file reload (IDEA.md "Configuration file" →
//! "Live reload"): `run`'s accept loop polls the mtimes of the same global/
//! per-project files `crate::configs::load` reads (via
//! `crate::configs::config_paths`) roughly once a second, and on a detected
//! change re-runs `crate::configs::load` with the original startup
//! `CliOverrides` (so CLI-flag precedence still wins) and diffs the result
//! against the running configuration to decide what to apply: hot-appliable
//! settings (`directory_listing`, `mime_types`, `script_handlers`, `debug`,
//! logging rotate/keep, `proxy.*`, …) are swapped in atomically via a
//! `RuntimeState` cell; a `listen`/`port`/`tls.enabled`/`fqdn` change
//! rebinds the listener in place without dropping the process; a change
//! this project cannot apply live (e.g. `base_dir`, or a rebind that fails
//! because it targets a privileged port after privileges were already
//! dropped) is logged as a warning and recorded on the `/server-info`
//! dashboard, never silently ignored or a crash.
//!
//! Also implements protocol version negotiation (IDEA.md "Core behavior" →
//! "Protocol version negotiation"). The listener is async (`tokio`) and its
//! message framing is `hyper`'s rather than hand-rolled:
//!
//! * Cleartext (`tls.enabled: false`) on `--port` serves HTTP/1.1 always,
//!   and HTTP/2 over cleartext (h2c) by prior knowledge — `hyper_util`'s
//!   `server::conn::auto` builder sniffs the RFC 9113 §3.4 connection
//!   preface and switches framing accordingly. A request carrying
//!   `Upgrade: h2c` is answered over HTTP/1.1, which RFC 9113 §3.2
//!   explicitly permits ("A server that does not support HTTP/2 can respond
//!   to the request as though the `Upgrade` header field were absent"); the
//!   upgrade dance itself is not implemented, and the header never bypasses
//!   any part of the normal request pipeline.
//! * TLS (`tls.enabled: true`) on `--port` negotiates `h2` or `http/1.1`
//!   via ALPN (`servers::tls`). The ALPN result — not connection sniffing —
//!   selects the framing, so a peer cannot negotiate one version and then
//!   speak another (an h1/h2 request-smuggling class of bug).
//! * TLS additionally serves HTTP/3 (RFC 9114) over QUIC (RFC 9000) on a
//!   UDP listener bound to the same port number (`servers::http3`), and
//!   advertises it to TCP clients with `Alt-Svc: h3=":{port}"`. QUIC
//!   mandates TLS 1.3, so there is no cleartext HTTP/3.
//!
//! Request bodies support `Transfer-Encoding: chunked` (RFC 9112 §7.1) in
//! addition to `Content-Length` on HTTP/1.1, and DATA-frame framing on
//! HTTP/2 and HTTP/3 — all three decoded by the protocol library rather
//! than by this module, including RFC 9112 §6.1's rejection of a message
//! carrying both framings at once. Every request reaches `handle_request`
//! as one normalized `Request` plus a fully-buffered body regardless of the
//! version it arrived on, so the security pipeline below is identical
//! across all three.
//!
//! Script/CGI dispatch also resolves `PATH_INFO`/`PATH_TRANSLATED` per CGI
//! 1.1 semantics: when the full literal request path does not exist,
//! `handle_request` walks the path's ancestor components looking for the
//! longest existing-file prefix that `classify_script` still recognizes as
//! a script; the remaining trailing segments become `PATH_INFO` (and
//! `PATH_TRANSLATED` is derived from it under `base_dir`), threaded through
//! `dispatch_script` into the CGI environment. Plain static-file resolution
//! is unaffected — PATH_INFO splitting only ever applies to script routes.

use std::collections::HashMap;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};

use crate::supports::signal;

mod compress;
mod headers;
mod htaccess;
mod http3;
mod info;
mod proxy;
mod ssi;
mod tls;

/// The single response body type every handler in this crate produces.
/// Boxed (rather than a concrete `Full`/`Incoming`) because a response is
/// either a fully-buffered in-memory body (static files, error pages,
/// directory listings, CGI output) or a streamed upstream body relayed by
/// `servers::proxy` — one type has to cover both, and all three protocol
/// versions consume the same one.
pub type Body = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

/// Wraps fully-buffered bytes as a `Body`. `Full` is infallible, so the
/// error type is mapped via an uninhabited match rather than a runtime
/// conversion.
pub fn full_body(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

/// HTTP/2 (RFC 9113) connection limits applied to every HTTP/2 connection,
/// cleartext or TLS. These are hardening settings, not tuning knobs:
///
/// * `max_concurrent_streams` bounds how many requests one connection can
///   have in flight (SETTINGS_MAX_CONCURRENT_STREAMS, RFC 9113 §5.1.2).
/// * `max_pending_accept_reset_streams` and `max_local_error_reset_streams`
///   are hyper's CVE-2023-44487 ("HTTP/2 Rapid Reset") mitigations — a peer
///   that opens and immediately `RST_STREAM`s requests in a loop otherwise
///   costs the server unbounded work for near-zero client cost. Both are
///   pinned explicitly rather than left to the library default so a
///   dependency bump cannot silently loosen them.
/// * `max_header_list_size` bounds decompressed header-block size, which is
///   the HPACK-decompression-bomb equivalent of a request-line length cap.
const H2_MAX_CONCURRENT_STREAMS: u32 = 128;
const H2_MAX_PENDING_ACCEPT_RESET_STREAMS: usize = 32;
const H2_MAX_LOCAL_ERROR_RESET_STREAMS: usize = 32;
const H2_MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;

/// Cap on a buffered request body, applied uniformly to HTTP/1.1, HTTP/2,
/// and HTTP/3 before the body is read into memory. Bodies are buffered (as
/// they were before the async rewrite) so CGI/script dispatch and proxying
/// can both see the whole payload; without a cap that buffering is an
/// unbounded-memory denial of service on every protocol version.
const MAX_REQUEST_BODY: u64 = 64 * 1024 * 1024;

/// How long a peer may take to send a complete request head before the
/// connection is dropped — a Slowloris bound, replacing the fixed 30s read
/// timeout the previous blocking implementation set on the socket.
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Effective runtime configuration for `serve` — the fully layered result
/// of IDEA.md's "CLI flag > env var > per-project config > global config >
/// built-in default" precedence (see `crate::configs::load`).
pub type ServeOptions = crate::configs::Resolved;

/// Parses the `serve` subcommand's CLI flags and layers them over
/// environment variables and config-file settings via `crate::configs::load`
/// (IDEA.md "Configuration file", "CLI flags (full reference)"). Also
/// returns the parsed `CliOverrides` themselves — `run` needs them again at
/// live-reload time so a reload re-runs the exact same CLI-flag > env >
/// per-project > global > default precedence chain, rather than letting a
/// file edit override a flag the user passed at startup.
pub fn parse_serve_options(args: &[String]) -> (ServeOptions, crate::configs::CliOverrides) {
    let overrides = parse_cli_overrides(args);
    let opts = crate::configs::load(&overrides, true).unwrap_or_else(|err| {
        eprintln!("cashttpd: warning: config load failed ({err}); using built-in defaults");
        crate::configs::load(&crate::configs::CliOverrides::default(), false)
            .unwrap_or_else(|_| fallback_defaults())
    });
    (opts, overrides)
}

fn fallback_defaults() -> ServeOptions {
    crate::configs::Resolved {
        base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        listen: "::1".to_string(),
        port: 8080,
        log_dir: crate::platforms::paths::log_dir(),
        debug: false,
        fqdn: None,
        tls_enabled: false,
        directory_listing: false,
        mime_types: Default::default(),
        script_handlers: Default::default(),
        ssi_extensions: crate::configs::builtin_ssi_extensions(),
        security_headers: crate::configs::builtin_security_headers(
            false,
            crate::configs::ServerTokens::Full,
        ),
        cors: Some(crate::configs::builtin_cors_headers()),
        proxy: Default::default(),
        logging_access_format: "combined".to_string(),
        logging_access_rotate: "daily".to_string(),
        logging_access_keep: "30d".to_string(),
        logging_error_format: "standard".to_string(),
        logging_error_rotate: "daily".to_string(),
        logging_error_keep: "30d".to_string(),
        project_config_path: PathBuf::new(),
    }
}

/// Parses `--listen`, `--port`, `--dir`, `--fqdn`, `--log`, `--config`,
/// `--debug` into a `CliOverrides` (IDEA.md "CLI flags (full reference)").
/// `--daemon`/`--quiet`/`--config-test` are invocation-shape flags handled
/// by `crate::uis::cli`, not persisted settings — they are not parsed here.
pub fn parse_cli_overrides(args: &[String]) -> crate::configs::CliOverrides {
    let mut o = crate::configs::CliOverrides::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                if let Some(v) = args.get(i + 1) {
                    o.listen = Some(v.clone());
                    i += 1;
                }
            }
            "--port" => {
                if let Some(v) = args.get(i + 1) {
                    if let Ok(p) = v.parse() {
                        o.port = Some(p);
                    }
                    i += 1;
                }
            }
            "--dir" => {
                if let Some(v) = args.get(i + 1) {
                    o.base_dir = Some(PathBuf::from(v));
                    i += 1;
                }
            }
            "--fqdn" => {
                if let Some(v) = args.get(i + 1) {
                    o.fqdn = Some(v.clone());
                    i += 1;
                }
            }
            "--log" => {
                if let Some(v) = args.get(i + 1) {
                    o.log_dir = Some(PathBuf::from(v));
                    i += 1;
                }
            }
            "--config" => {
                if let Some(v) = args.get(i + 1) {
                    o.config_path = Some(PathBuf::from(v));
                    i += 1;
                }
            }
            "--debug" => {
                o.debug = Some(true);
            }
            _ => {}
        }
        i += 1;
    }
    o
}

/// Runs the `serve` daemon (AI.md PART 14 "Runtime Model"): binds a
/// dual-stack listener, drops root privileges once bound ("Sockets, Ports
/// & Privileges" — bind-then-drop), installs signal handlers, and serves
/// `base_dir` until shutdown is requested. `SIGHUP` is a terminating signal
/// here, not a reload, per IDEA.md's documented deviation from this PART's
/// generic default.
/// `quiet` suppresses ongoing per-request access/error lines on the live
/// TUI/CLI display (IDEA.md "Logging" → `--quiet`) — file logging is always
/// unconditional regardless of this flag.
pub fn run(
    opts: ServeOptions,
    quiet: bool,
    cli: crate::configs::CliOverrides,
) -> std::io::Result<()> {
    // IDEA.md "TLS certificate resolution": `--fqdn` is required whenever
    // `tls.enabled: true` — fail fast, non-zero exit, no certless/
    // hostnameless HTTPS mode.
    if opts.tls_enabled && opts.fqdn.as_deref().unwrap_or("").is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tls.enabled is true but no --fqdn/fqdn was provided (required whenever TLS is on)",
        ));
    }

    // TLS certificate resolution can need port 80 (ACME HTTP-01) — resolve
    // it before dropping privileges, not after. Warnings are collected here
    // (rather than recorded directly) because `info::Stats` isn't
    // constructed until after privilege drop/signal install below; they are
    // folded into the dashboard's issue list as `TlsIssue` once it exists.
    // `build_server_config`'s callback is `impl Fn(&str)`, not `FnMut` —
    // interior mutability via `RefCell` is required to collect warnings
    // without changing that signature.
    let tls_warnings = std::cell::RefCell::new(Vec::<String>::new());
    let (mut listener, tls_config) = bind_listener(&opts, &opts.base_dir, |msg| {
        eprintln!("cashttpd: warning: {msg}");
        tls_warnings.borrow_mut().push(msg.to_string());
    })?;
    let tls_warnings = tls_warnings.into_inner();

    // Privileged ports (<1024): bind first, then drop privileges — the
    // daemon never continues running as root after binding. A live-reload
    // rebind onto a privileged port after this point will fail (expected —
    // see `apply_reload`), and is logged as a warning rather than crashing.
    crate::platforms::drop_privileges_if_root()?;

    let shutdown = signal::install_handlers()?;

    let base_dir = Arc::new(
        opts.base_dir
            .canonicalize()
            .unwrap_or_else(|_| opts.base_dir.clone()),
    );
    std::fs::create_dir_all(&opts.log_dir).ok();
    let name = crate::configs::derived_name(&base_dir);
    let logger = Arc::new(Logger::open_with_policy(
        &opts.log_dir,
        &name,
        quiet,
        &opts.logging_access_rotate,
        &opts.logging_access_keep,
        &opts.logging_error_rotate,
        &opts.logging_error_keep,
    ));

    let banner = format!(
        "cashttpd {} listening on {} (base dir: {}, {})",
        crate::supports::version::VERSION,
        format_bind_addr(&opts),
        base_dir.display(),
        if opts.tls_enabled { "https" } else { "http" }
    );
    if crate::supports::color::color_enabled(None) {
        let light_bg = std::env::var("COLORFGBG")
            .ok()
            .and_then(|v| v.rsplit(';').next().map(str::to_string))
            .and_then(|bg| bg.parse::<u8>().ok())
            .is_some_and(|bg| bg >= 8);
        let palette = if light_bg {
            crate::supports::color::terminal_palette_light()
        } else {
            crate::supports::color::terminal_palette_dark()
        };
        println!("\x1b[38;5;{}m{banner}\x1b[0m", palette.primary);
    } else {
        println!("{banner}");
    }

    let stats = Arc::new(info::Stats::new(crate::platforms::sandboxing_posture()));
    // Startup-time TLS warnings aren't tied to a specific request — recorded
    // with synthetic method/target/status values consistent with that.
    for warning in &tls_warnings {
        stats.record_issue(
            info::IssueKind::TlsIssue,
            "/",
            warning,
            "TLS",
            opts.fqdn.as_deref().unwrap_or(""),
            0,
            None,
        );
    }
    let started_at = Instant::now();

    // Framework dev-server proxying (IDEA.md "Framework dev-server
    // proxying") — resolved and spawned once here, never per-request. The
    // child's PID is handed to `shutdown` so every signal-driven exit path
    // (including the "second signal forces an immediate exit" one) kills
    // it, not just the graceful path below.
    let proxy_target = proxy::resolve_proxy_target(&base_dir, &opts.proxy).map(Arc::new);
    let mut proxy_child = None;
    if let Some(target) = &proxy_target {
        match proxy::spawn_child(target, &base_dir) {
            Ok(child) => {
                shutdown.track_child_process(child.id());
                stats.set_proxy_child_pid(child.id());
                proxy_child = Some(child);
            }
            Err(err) => {
                logger.error(&format!(
                    "failed to start framework dev-server ({} : {}): {err}",
                    target.kind, target.command
                ));
            }
        }
    }

    // Live config-file reload (IDEA.md "Configuration file" → "Live
    // reload"): watch the same two files `crate::configs::load` reads, and
    // bundle everything a reload can swap atomically into one cell so a
    // connection accepted mid-reload always sees an internally-consistent
    // snapshot (never, say, a new `opts` paired with the old `logger`).
    let (global_config_path, project_config_path) = crate::configs::config_paths(&cli);
    let mut reload_watch = ReloadWatch::new(global_config_path, project_config_path);
    let mut last_reload_check = Instant::now();
    let runtime: Mutex<Arc<RuntimeState>> = Mutex::new(Arc::new(RuntimeState {
        opts: Arc::new(opts),
        tls_config,
        proxy_target,
        logger,
    }));

    // Everything above is startup work that must happen synchronously and
    // in order (bind while privileged, then drop privileges, then install
    // handlers). The async runtime is only entered once that is settled, so
    // no listener or child process is ever created from inside a worker
    // thread whose privileges have already been dropped mid-sequence.
    let async_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    async_runtime.block_on(async {
        // The accept loop needs a reactor-registered listener, while
        // `apply_reload` rebinds a plain `std` one (it is called from this
        // same loop, but is otherwise ordinary synchronous code). The std
        // listener stays the source of truth and the tokio listener is a
        // registered duplicate of it, refreshed whenever a reload rebinds.
        let mut accept = tokio::net::TcpListener::from_std(listener.try_clone()?)?;
        let mut h3 = spawn_http3(&accept, &runtime, &base_dir, &stats);

        while !shutdown.is_shutdown_requested() {
            if last_reload_check.elapsed() >= Duration::from_secs(1) {
                last_reload_check = Instant::now();
                if reload_watch.changed() {
                    let rebound = apply_reload(
                        &cli,
                        &runtime,
                        &mut listener,
                        &base_dir,
                        quiet,
                        &mut proxy_child,
                        &shutdown,
                        &stats,
                    );
                    if rebound {
                        accept = tokio::net::TcpListener::from_std(listener.try_clone()?)?;
                        if let Some(handle) = h3.take() {
                            handle.shutdown();
                        }
                        h3 = spawn_http3(&accept, &runtime, &base_dir, &stats);
                    }
                }
            }

            // A bounded wait rather than a bare `accept().await`: the loop
            // has to come back around regularly to notice a shutdown signal
            // and to run the ~1s reload check even while no client connects.
            let accepted =
                match tokio::time::timeout(Duration::from_millis(200), accept.accept()).await {
                    Ok(result) => result,
                    Err(_timed_out) => continue,
                };
            match accepted {
                Ok((stream, addr)) => {
                    // A poisoned mutex here would only mean some other
                    // accept-loop task panicked while holding it; the
                    // snapshot itself is still valid data, so recover it
                    // rather than propagating the panic into this request.
                    let ctx = ServeContext {
                        base_dir: Arc::clone(&base_dir),
                        state: Arc::clone(
                            &runtime
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner),
                        ),
                        stats: Arc::clone(&stats),
                    };
                    tokio::spawn(async move {
                        let logger = Arc::clone(&ctx.state.logger);
                        if let Err(err) = serve_tcp_connection(stream, addr, ctx).await {
                            logger.error(&format!("connection error from {addr}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    // See the poisoned-mutex-recovery comment above.
                    runtime
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .logger
                        .error(&format!("accept error: {err}"));
                }
            }
        }

        if let Some(handle) = h3.take() {
            handle.shutdown();
        }
        Ok::<(), std::io::Error>(())
    })?;

    // Ordinary graceful-shutdown path: kill and reap the framework
    // dev-server child directly (the signal handler above already sent it
    // SIGTERM on the signal that broke this loop, but that's fire-and-
    // forget — this makes sure it's actually gone and not a zombie before
    // cashttpd itself exits).
    if let Some(mut child) = proxy_child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    shutdown.clear_child_process();

    println!(
        "cashttpd: graceful shutdown complete after {}, served {} requests",
        crate::supports::format::duration(started_at.elapsed().as_secs()),
        crate::supports::format::count(stats.total_requests())
    );

    Ok(())
}

/// Formats `opts.listen`/`opts.port` as a bindable socket address string,
/// bracketing a bare (non-`[...]`-wrapped) IPv6 literal — shared by the
/// startup bind and every live-reload rebind so they can never drift apart.
fn format_bind_addr(opts: &ServeOptions) -> String {
    let host = if opts.listen.contains(':') && !opts.listen.starts_with('[') {
        format!("[{}]", opts.listen)
    } else {
        opts.listen.clone()
    };
    format!("{host}:{}", opts.port)
}

/// Binds the listener and, when `opts.tls_enabled`, resolves the TLS
/// certificate for it. Used both at startup and for every live-reload
/// listener rebind (`apply_reload`) so the two paths share one procedure.
fn bind_listener(
    opts: &ServeOptions,
    base_dir: &Path,
    on_tls_warning: impl Fn(&str),
) -> std::io::Result<(TcpListener, Option<Arc<tls::TlsSetup>>)> {
    let listener = TcpListener::bind(format_bind_addr(opts))?;
    // Required before `tokio::net::TcpListener::from_std` can adopt it.
    listener.set_nonblocking(true)?;

    let tls_config = if opts.tls_enabled {
        let fqdn = opts.fqdn.clone().unwrap_or_default();
        Some(Arc::new(tls::build_server_config(
            &fqdn,
            &opts.listen,
            base_dir,
            on_tls_warning,
        )?))
    } else {
        None
    };
    Ok((listener, tls_config))
}

/// Per-connection view of everything a request handler needs: the
/// canonicalized document root, the current (reload-swappable) runtime
/// snapshot, and the shared `/server-info` statistics. Cloned per accepted
/// connection so a reload landing mid-connection cannot change the
/// configuration a connection already in progress is being served under.
#[derive(Clone)]
struct ServeContext {
    base_dir: Arc<PathBuf>,
    state: Arc<RuntimeState>,
    stats: Arc<info::Stats>,
}

/// Starts the HTTP/3 listener for the current runtime snapshot, or returns
/// `None` when TLS is off (QUIC mandates TLS 1.3, so cleartext HTTP/3 does
/// not exist). The UDP socket is bound to the TCP listener's *actual* local
/// address, which matters when `port: 0` was requested — the two listeners
/// must agree on a port number for the `Alt-Svc` advertisement to be true.
fn spawn_http3(
    accept: &tokio::net::TcpListener,
    runtime: &Mutex<Arc<RuntimeState>>,
    base_dir: &Arc<PathBuf>,
    stats: &Arc<info::Stats>,
) -> Option<http3::Handle> {
    // See the poisoned-mutex-recovery comment in the accept loop above.
    let state = Arc::clone(
        &runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    let quic = Arc::clone(&state.tls_config.as_ref()?.quic);
    let addr = match accept.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            state
                .logger
                .error(&format!("HTTP/3 listener not started: {err}"));
            return None;
        }
    };
    let ctx = ServeContext {
        base_dir: Arc::clone(base_dir),
        state: Arc::clone(&state),
        stats: Arc::clone(stats),
    };
    match http3::spawn(addr, quic, ctx) {
        Ok(handle) => Some(handle),
        Err(err) => {
            // A failed QUIC bind is not fatal: HTTP/1.1 and HTTP/2 are still
            // being served on TCP. It is recorded rather than swallowed so
            // the reason shows up on the `/server-info` dashboard.
            state
                .logger
                .error(&format!("HTTP/3 listener not started on {addr}: {err}"));
            stats.record_issue(
                info::IssueKind::TlsIssue,
                "/",
                &format!("HTTP/3 listener not started on {addr}: {err}"),
                "QUIC",
                &state.opts.fqdn.clone().unwrap_or_default(),
                0,
                None,
            );
            None
        }
    }
}

/// Bundles every piece of per-connection runtime configuration a live
/// config reload can swap atomically (IDEA.md "Configuration file" → "Live
/// reload") without dropping the accept loop or any already-accepted
/// connection. Rebuilt wholesale on each applied reload rather than
/// mutated field-by-field, so a reload is all-or-nothing from any given
/// connection's point of view: each accept-loop iteration takes one fresh
/// `Arc::clone` snapshot of this before spawning its per-connection
/// thread, in place of the plain per-field `Arc::clone`s taken before live
/// reload existed.
struct RuntimeState {
    opts: Arc<ServeOptions>,
    tls_config: Option<Arc<tls::TlsSetup>>,
    proxy_target: Option<Arc<proxy::ProxyTarget>>,
    logger: Arc<Logger>,
}

/// Tracks the last-seen mtime of the global and per-project config files so
/// a reload check only re-reads/re-applies them when at least one actually
/// changed since the previous check. Comparing mtimes (rather than acting
/// on every wake) already gives natural debouncing against an editor's
/// temp-file-rename-into-place — no reload happens unless the mtime
/// genuinely differs from what was already seen.
struct ReloadWatch {
    global_path: PathBuf,
    project_path: PathBuf,
    global_mtime: Option<SystemTime>,
    project_mtime: Option<SystemTime>,
}

impl ReloadWatch {
    fn new(global_path: PathBuf, project_path: PathBuf) -> Self {
        let global_mtime = file_mtime(&global_path);
        let project_mtime = file_mtime(&project_path);
        Self {
            global_path,
            project_path,
            global_mtime,
            project_mtime,
        }
    }

    /// Returns `true` (and updates the stored mtimes) when either watched
    /// file's mtime differs from what was last seen — a file that no
    /// longer exists reports `None`, which itself counts as a change from
    /// a previously-`Some` value. Exposed as a directly-callable method,
    /// separate from the accept loop's own ~1s poll-interval gate, so a
    /// test can call it synchronously against real files it touches
    /// without waiting on real wall-clock time.
    fn changed(&mut self) -> bool {
        let global_mtime = file_mtime(&self.global_path);
        let project_mtime = file_mtime(&self.project_path);
        let changed = global_mtime != self.global_mtime || project_mtime != self.project_mtime;
        self.global_mtime = global_mtime;
        self.project_mtime = project_mtime;
        changed
    }
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Whether `new` differs from `old` in a way that requires closing the
/// current listener socket and opening a new one (IDEA.md "Live reload" —
/// `listen`/`port` changing, or `tls.enabled` flipping, re-binds the
/// listener without dropping the process). An `fqdn` change is folded in
/// here too, but only while TLS is (or becomes) enabled, since it's the
/// TLS certificate resolved for the listener that actually depends on it.
fn config_needs_listener_rebind(old: &ServeOptions, new: &ServeOptions) -> bool {
    old.listen != new.listen
        || old.port != new.port
        || old.tls_enabled != new.tls_enabled
        || (new.tls_enabled && old.fqdn != new.fqdn)
}

/// Whether `new` differs from `old` in a way that requires killing the
/// current framework dev-server child (if any) and resolving/spawning a
/// fresh one (IDEA.md "Framework dev-server proxying" `proxy.*` keys).
fn config_needs_proxy_restart(old: &ServeOptions, new: &ServeOptions) -> bool {
    old.proxy.enabled != new.proxy.enabled
        || old.proxy.kind != new.proxy.kind
        || old.proxy.command != new.proxy.command
        || old.proxy.upstream != new.proxy.upstream
        || old.proxy.path_prefix != new.proxy.path_prefix
}

/// Whether `new` differs from `old` in a way that requires reopening the
/// access/error `Logger` against a new directory or rotate/keep policy
/// (IDEA.md "Logging" → "Log rotation and retention").
fn config_needs_logger_reopen(old: &ServeOptions, new: &ServeOptions) -> bool {
    old.log_dir != new.log_dir
        || old.logging_access_rotate != new.logging_access_rotate
        || old.logging_access_keep != new.logging_access_keep
        || old.logging_error_rotate != new.logging_error_rotate
        || old.logging_error_keep != new.logging_error_keep
}

/// One reload attempt: re-runs `crate::configs::load` with the original
/// startup `cli` overrides (so CLI-flag precedence still wins over any
/// file change) and, when the result actually differs, applies whatever of
/// it can be applied live — a listener rebind, a framework dev-server
/// child restart, and/or a `Logger` reopen, each only when that specific
/// piece actually changed — before atomically swapping `runtime` to the
/// new snapshot. Anything that cannot be applied live (a `base_dir`
/// change, or a listener rebind that fails — e.g. targeting a privileged
/// port after privileges were already dropped) is logged as a warning and
/// recorded on the `/server-info` dashboard; the server keeps running on
/// its previous configuration for that piece rather than crashing.
///
/// Returns whether the listener was actually rebound, so the caller knows
/// to re-register the new socket with the async reactor and restart the
/// HTTP/3 listener that shares its port number.
// Each parameter is a distinct piece of the running server's live state
// (client overrides for precedence, the swappable runtime cell, the bound
// listener that may need rebinding, base_dir, quiet flag, the proxy child
// process, shutdown/signal state, and stats) that live-reload (IDEA.md
// "Configuration file" → "Live reload") must inspect or mutate together in
// one atomic pass; splitting them into a struct would just relocate the
// same fields without reducing what this function actually touches.
#[allow(clippy::too_many_arguments)]
fn apply_reload(
    cli: &crate::configs::CliOverrides,
    runtime: &Mutex<Arc<RuntimeState>>,
    listener: &mut TcpListener,
    base_dir: &Path,
    quiet: bool,
    proxy_child: &mut Option<std::process::Child>,
    shutdown: &signal::ShutdownState,
    stats: &info::Stats,
) -> bool {
    // See the poisoned-mutex-recovery comment in the accept loop above.
    let current = Arc::clone(
        &runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );

    let mut new_opts = match crate::configs::load(cli, false) {
        Ok(o) => o,
        Err(err) => {
            let msg = format!("config reload failed: {err}; keeping previous configuration");
            current.logger.error(&msg);
            stats.record_issue(
                info::IssueKind::ConfigReloadIssue,
                "/",
                &msg,
                "RELOAD",
                "-",
                0,
                None,
            );
            return false;
        }
    };

    let mut warnings = Vec::new();

    // `base_dir` cannot change live — the served directory tree, cert
    // storage path, and log-file name are all derived from it once at
    // startup and threaded through as a plain (non-swappable) `Arc<Path>`.
    if new_opts.base_dir != current.opts.base_dir {
        warnings.push(format!(
            "base_dir change from {} to {} cannot be applied live (requires a restart); keeping the running base_dir",
            current.opts.base_dir.display(),
            new_opts.base_dir.display()
        ));
        new_opts.base_dir = current.opts.base_dir.clone();
    }

    let mut listener_rebound = false;
    let mut tls_config = current.tls_config.clone();
    if config_needs_listener_rebind(&current.opts, &new_opts) {
        let fqdn_for_warning = new_opts.fqdn.clone().unwrap_or_default();
        match bind_listener(&new_opts, base_dir, |msg| {
            stats.record_issue(
                info::IssueKind::TlsIssue,
                "/",
                msg,
                "TLS",
                &fqdn_for_warning,
                0,
                None,
            );
        }) {
            Ok((new_listener, new_tls)) => {
                *listener = new_listener;
                tls_config = new_tls;
                listener_rebound = true;
            }
            Err(err) => {
                warnings.push(format!(
                    "listener rebind to {} (tls={}) failed: {err}; still serving on the previous bind",
                    format_bind_addr(&new_opts),
                    new_opts.tls_enabled
                ));
                // The bind itself failed, so the process is still listening
                // on `current`'s address/TLS state — reflect that in the
                // swapped-in config rather than reporting a `listen`/`port`/
                // `tls_enabled`/`fqdn` the running listener never actually
                // took on.
                new_opts.listen = current.opts.listen.clone();
                new_opts.port = current.opts.port;
                new_opts.tls_enabled = current.opts.tls_enabled;
                new_opts.fqdn = current.opts.fqdn.clone();
            }
        }
    }

    let proxy_target = if config_needs_proxy_restart(&current.opts, &new_opts) {
        if let Some(mut child) = proxy_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        shutdown.clear_child_process();
        let target = proxy::resolve_proxy_target(base_dir, &new_opts.proxy).map(Arc::new);
        match &target {
            Some(t) => match proxy::spawn_child(t, base_dir) {
                Ok(child) => {
                    shutdown.track_child_process(child.id());
                    stats.set_proxy_child_pid(child.id());
                    *proxy_child = Some(child);
                }
                Err(err) => {
                    stats.set_proxy_child_pid(0);
                    warnings.push(format!(
                        "failed to restart framework dev-server ({}: {}): {err}",
                        t.kind, t.command
                    ));
                }
            },
            None => stats.set_proxy_child_pid(0),
        }
        target
    } else {
        current.proxy_target.clone()
    };

    let logger = if config_needs_logger_reopen(&current.opts, &new_opts) {
        std::fs::create_dir_all(&new_opts.log_dir).ok();
        let name = crate::configs::derived_name(base_dir);
        Arc::new(Logger::open_with_policy(
            &new_opts.log_dir,
            &name,
            quiet,
            &new_opts.logging_access_rotate,
            &new_opts.logging_access_keep,
            &new_opts.logging_error_rotate,
            &new_opts.logging_error_keep,
        ))
    } else {
        current.logger.clone()
    };

    let updated = Arc::new(RuntimeState {
        opts: Arc::new(new_opts),
        tls_config,
        proxy_target,
        logger: logger.clone(),
    });
    // See the poisoned-mutex-recovery comment in the accept loop above.
    *runtime
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = updated;

    logger.error(&format!(
        "config reload applied{}",
        if listener_rebound {
            " (listener rebound)"
        } else {
            ""
        }
    ));
    for warning in &warnings {
        logger.error(&format!("config reload warning: {warning}"));
        stats.record_issue(
            info::IssueKind::ConfigReloadIssue,
            "/",
            warning,
            "RELOAD",
            "-",
            0,
            None,
        );
    }
    listener_rebound
}

/// One request, normalized to the same shape regardless of whether it
/// arrived as an HTTP/1.1 message (RFC 9112), an HTTP/2 HEADERS frame (RFC
/// 9113), or an HTTP/3 HEADERS frame (RFC 9114). Header names are
/// lowercased — mandatory on HTTP/2 and HTTP/3, and case-insensitive on
/// HTTP/1.1 (RFC 9110 §5.1) — so every lookup below is version-agnostic.
struct Request {
    method: String,
    path: String,
    version: String,
    headers: HashMap<String, String>,
}

impl Request {
    /// Builds the normalized request from an `http::request::Parts`, the
    /// common currency of both `hyper` (HTTP/1.1, HTTP/2) and `h3`
    /// (HTTP/3).
    ///
    /// `path` deliberately carries the origin-form target *including* the
    /// query string, exactly as the previous hand-rolled parser recorded
    /// the request line's second token: everything downstream (`.htaccess`
    /// rewrites, `QUERY_STRING`, logging) is written against that shape.
    /// A request whose target has no path at all (`OPTIONS *`, or an
    /// authority-form CONNECT) normalizes to `*`, which fails the known-
    /// method/route checks in `handle_request` rather than being treated as
    /// the document root.
    ///
    /// Repeated header fields are joined with `", "` per RFC 9110 §5.3
    /// rather than silently dropping all but one — the CGI environment and
    /// the proxy forwarder both need the complete field value.
    fn from_parts(parts: &http::request::Parts) -> Self {
        let path = match parts.uri.path_and_query() {
            Some(pq) => pq.as_str().to_string(),
            None => "*".to_string(),
        };
        let version = match parts.version {
            http::Version::HTTP_10 => "HTTP/1.0",
            http::Version::HTTP_2 => "HTTP/2.0",
            http::Version::HTTP_3 => "HTTP/3.0",
            _ => "HTTP/1.1",
        }
        .to_string();
        let mut headers: HashMap<String, String> = HashMap::new();
        for (name, value) in parts.headers.iter() {
            // A header whose value is not valid UTF-8 is dropped rather
            // than lossily transcoded: it would otherwise reach the CGI
            // environment and the upstream proxy request as different bytes
            // than the peer sent, which is exactly how header-smuggling
            // bugs start.
            let Ok(value) = value.to_str() else { continue };
            headers
                .entry(name.as_str().to_ascii_lowercase())
                .and_modify(|existing| {
                    existing.push_str(", ");
                    existing.push_str(value);
                })
                .or_insert_with(|| value.to_string());
        }
        Self {
            method: parts.method.as_str().to_string(),
            path,
            version,
            headers,
        }
    }
}

/// Which framing to speak on an accepted connection. Chosen once, up front,
/// from the TLS ALPN result (or from the absence of TLS) rather than
/// re-derived per message — a connection that negotiated `h2` is served as
/// HTTP/2 and nothing else, which is what keeps an h1/h2 request-smuggling
/// confusion from being reachable at all.
enum HttpMode {
    /// Cleartext: HTTP/1.1, upgraded to HTTP/2 only when the peer opens
    /// with the RFC 9113 §3.4 connection preface (prior-knowledge h2c).
    Auto,
    /// ALPN negotiated `http/1.1`, or the peer offered no ALPN at all.
    Http1,
    /// ALPN negotiated `h2`.
    Http2,
}

/// Serves one accepted TCP connection end to end: TLS handshake (when
/// enabled), protocol selection, then `hyper`'s connection driver.
async fn serve_tcp_connection(
    stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    ctx: ServeContext,
) -> std::io::Result<()> {
    // Small responses (error pages, 304s, CGI output) should leave
    // immediately rather than waiting on Nagle coalescing.
    let _ = stream.set_nodelay(true);
    let client = addr.to_string();

    let Some(setup) = ctx.state.tls_config.clone() else {
        return serve_http(TokioIo::new(stream), ctx, client, HttpMode::Auto).await;
    };

    // The handshake is bounded by the same deadline as a request head: an
    // idle peer that opens a socket and never sends a ClientHello must not
    // hold a connection slot indefinitely.
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&setup.tcp));
    let tls = tokio::time::timeout(REQUEST_HEAD_TIMEOUT, acceptor.accept(stream))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out")
        })??;
    // rustls reports the negotiated protocol, or `None` when the client sent
    // no ALPN extension. Only the exact byte string `h2` selects HTTP/2;
    // everything else (including `http/1.1` and no ALPN) is HTTP/1.1, per
    // RFC 9113 §3.1.
    let mode = if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
        HttpMode::Http2
    } else {
        HttpMode::Http1
    };
    serve_http(TokioIo::new(tls), ctx, client, mode).await
}

/// Drives one connection with `hyper`, in whichever framing `mode` selected.
/// All three arms share exactly one service function, so no request can
/// reach the handler pipeline through a version-specific side door.
async fn serve_http<I>(
    io: I,
    ctx: ServeContext,
    client: String,
    mode: HttpMode,
) -> std::io::Result<()>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let ctx = ctx.clone();
        let client = client.clone();
        async move { serve_hyper_request(ctx, client, req).await }
    });

    let result = match mode {
        HttpMode::Auto => {
            let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            builder.http1().timer(TokioTimer::new());
            configure_http1(&mut builder.http1());
            builder.http2().timer(TokioTimer::new());
            configure_http2(&mut builder.http2());
            builder.serve_connection_with_upgrades(io, service).await
        }
        HttpMode::Http1 => {
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder.timer(TokioTimer::new());
            configure_http1(&mut builder);
            builder
                .serve_connection(io, service)
                .with_upgrades()
                .await
                .map_err(Into::into)
        }
        HttpMode::Http2 => {
            let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
            builder.timer(TokioTimer::new());
            configure_http2(&mut builder);
            builder
                .serve_connection(io, service)
                .await
                .map_err(Into::into)
        }
    };

    // A peer disconnecting mid-response is routine, not a server fault; the
    // error is still surfaced to the caller, which logs it to the error log
    // exactly as the previous implementation logged connection errors.
    result.map_err(std::io::Error::other)
}

/// Applies the HTTP/1.1 hardening and output-shape settings shared by the
/// cleartext and ALPN-`http/1.1` paths.
fn configure_http1<T: HeaderCasing>(builder: &mut T) {
    // Apache-style capitalized header names on the wire. HTTP/1.1 header
    // names are case-insensitive (RFC 9110 §5.1), but this server's whole
    // point is drop-in familiarity with Apache output.
    builder.set_title_case_headers(true);
    // Slowloris bound: a peer has this long to finish sending a request
    // head, replacing the blocking implementation's socket read timeout.
    builder.set_header_read_timeout(REQUEST_HEAD_TIMEOUT);
}

/// Applies the HTTP/2 (RFC 9113) hardening settings shared by the
/// prior-knowledge h2c and ALPN-`h2` paths — see the `H2_*` constants.
fn configure_http2<T: Http2Limits>(builder: &mut T) {
    builder.set_max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);
    builder.set_max_pending_accept_reset_streams(H2_MAX_PENDING_ACCEPT_RESET_STREAMS);
    builder.set_max_local_error_reset_streams(H2_MAX_LOCAL_ERROR_RESET_STREAMS);
    builder.set_max_header_list_size(H2_MAX_HEADER_LIST_SIZE);
}

/// The HTTP/1.1 knobs `configure_http1` sets. `hyper`'s standalone
/// `http1::Builder` and `hyper_util`'s `auto::Http1Builder` expose the same
/// methods but share no trait, so this bridges them rather than duplicating
/// the settings (and risking the two paths drifting apart).
trait HeaderCasing {
    fn set_title_case_headers(&mut self, enabled: bool);
    fn set_header_read_timeout(&mut self, timeout: Duration);
}

impl HeaderCasing for hyper::server::conn::http1::Builder {
    fn set_title_case_headers(&mut self, enabled: bool) {
        self.title_case_headers(enabled);
    }
    fn set_header_read_timeout(&mut self, timeout: Duration) {
        self.header_read_timeout(timeout);
    }
}

impl HeaderCasing for hyper_util::server::conn::auto::Http1Builder<'_, TokioExecutor> {
    fn set_title_case_headers(&mut self, enabled: bool) {
        self.title_case_headers(enabled);
    }
    fn set_header_read_timeout(&mut self, timeout: Duration) {
        self.header_read_timeout(timeout);
    }
}

/// The HTTP/2 limits `configure_http2` sets, bridging `hyper`'s standalone
/// `http2::Builder` and `hyper_util`'s `auto::Http2Builder` for the same
/// reason `HeaderCasing` exists.
trait Http2Limits {
    fn set_max_concurrent_streams(&mut self, max: u32);
    fn set_max_pending_accept_reset_streams(&mut self, max: usize);
    fn set_max_local_error_reset_streams(&mut self, max: usize);
    fn set_max_header_list_size(&mut self, max: u32);
}

impl Http2Limits for hyper::server::conn::http2::Builder<TokioExecutor> {
    fn set_max_concurrent_streams(&mut self, max: u32) {
        self.max_concurrent_streams(max);
    }
    fn set_max_pending_accept_reset_streams(&mut self, max: usize) {
        self.max_pending_accept_reset_streams(max);
    }
    fn set_max_local_error_reset_streams(&mut self, max: usize) {
        self.max_local_error_reset_streams(max);
    }
    fn set_max_header_list_size(&mut self, max: u32) {
        self.max_header_list_size(max);
    }
}

impl Http2Limits for hyper_util::server::conn::auto::Http2Builder<'_, TokioExecutor> {
    fn set_max_concurrent_streams(&mut self, max: u32) {
        self.max_concurrent_streams(max);
    }
    fn set_max_pending_accept_reset_streams(&mut self, max: usize) {
        self.max_pending_accept_reset_streams(max);
    }
    fn set_max_local_error_reset_streams(&mut self, max: usize) {
        self.max_local_error_reset_streams(max);
    }
    fn set_max_header_list_size(&mut self, max: u32) {
        self.max_header_list_size(max);
    }
}

/// Adapts one `hyper` request (HTTP/1.1 or HTTP/2) into the version-neutral
/// `dispatch` pipeline: normalizes the head, buffers the body under
/// `MAX_REQUEST_BODY`, and carries the `Upgrade` handle through for the
/// WebSocket proxy relay.
async fn serve_hyper_request(
    ctx: ServeContext,
    client: String,
    mut req: hyper::Request<Incoming>,
) -> std::io::Result<Response<Body>> {
    // Must be taken before the request is decomposed — `hyper` stores the
    // upgrade handle in the request extensions, which `into_parts` moves
    // out of reach of the proxy relay otherwise. Taking it does not itself
    // upgrade anything; it only becomes live if a 101 is actually returned.
    let upgrade = hyper::upgrade::on(&mut req);
    let (parts, incoming) = req.into_parts();
    let request = Request::from_parts(&parts);

    // A declared body larger than the cap is refused before a single byte
    // of it is buffered.
    let declared: Option<u64> = request
        .headers
        .get("content-length")
        .and_then(|v| v.trim().parse().ok());
    if declared.is_some_and(|len| len > MAX_REQUEST_BODY) {
        return Ok(dispatch_status(&ctx, &request, &client, 413, 0).await);
    }

    let body = match http_body_util::Limited::new(incoming, MAX_REQUEST_BODY as usize)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            // Two distinct client faults reach here and they get distinct
            // statuses: a peer that exceeded the cap without declaring it
            // (`LengthLimitError`) is 413, while a truncated or malformed
            // body — including the RFC 9112 §7.1 chunk-framing errors
            // `hyper` rejects on our behalf — is 400.
            let status = if err
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                413
            } else {
                400
            };
            return Ok(dispatch_status(&ctx, &request, &client, status, 0).await);
        }
    };

    Ok(dispatch(&ctx, &request, body, &client, Some(upgrade)).await)
}

/// Logs and returns a bare status response for a request that never reaches
/// the handler pipeline (body too large, or unreadable). Kept on the same
/// logging/stats path as a served request so a rejected request is still
/// visible in the access log and on `/server-info`.
async fn dispatch_status(
    ctx: &ServeContext,
    request: &Request,
    client: &str,
    status: u16,
    body_len: u64,
) -> Response<Body> {
    let response = respond_error(status, request, &ctx.state.opts).unwrap_or_else(|_| {
        let mut fallback = Response::new(full_body(Bytes::new()));
        *fallback.status_mut() =
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        fallback
    });
    finish_response(ctx, request, client, response, body_len).await
}

/// The one entry point every protocol version funnels through: runs the
/// request through `handle_request`, then applies the shared response
/// post-processing (HTTP/3 advertisement, statistics, access logging).
async fn dispatch(
    ctx: &ServeContext,
    request: &Request,
    body: Bytes,
    client: &str,
    upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Response<Body> {
    let body_len = body.len() as u64;
    let response = match handle_request(ctx, request, &body, client, upgrade).await {
        Ok(response) => response,
        Err(err) => {
            // A handler-level I/O failure is the server's fault, not the
            // peer's, and is reported as such instead of dropping the
            // connection with no response at all (which is what the
            // blocking implementation did).
            ctx.state
                .logger
                .error(&format!("{client} request error: {err}"));
            respond_error(500, request, &ctx.state.opts).unwrap_or_else(|_| {
                let mut fallback = Response::new(full_body(Bytes::new()));
                *fallback.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                fallback
            })
        }
    };
    finish_response(ctx, request, client, response, body_len).await
}

/// Response post-processing shared by every protocol version: advertises
/// HTTP/3 when it is actually running, attaches the default security/`Server`
/// /CORS headers, negotiates response compression, and only then records the
/// exchange in the `/server-info` statistics and the on-disk access log.
///
/// Ordering matters in both directions here. Headers and compression run
/// before `response_bytes` so the access log and the dashboard report the
/// bytes actually put on the wire rather than the pre-compression size, and
/// they run after every handler has returned so a CGI script's or a proxied
/// upstream's own headers are already in place for `headers::apply` to
/// defer to.
async fn finish_response(
    ctx: &ServeContext,
    request: &Request,
    client: &str,
    mut response: Response<Body>,
    request_body_len: u64,
) -> Response<Body> {
    // IDEA.md "Protocol version negotiation": HTTP/3 shares the TCP
    // listener's port number, so the advertisement is exact. It is only
    // truthful when TLS is on (QUIC mandates TLS 1.3), and is not sent on
    // HTTP/3 responses themselves — the peer is already there.
    if ctx.state.opts.tls_enabled && request.version != "HTTP/3.0" {
        if let Ok(value) = http::HeaderValue::from_str(&format!("h3=\":{}\"", ctx.state.opts.port))
        {
            response.headers_mut().insert(http::header::ALT_SVC, value);
        }
    }

    headers::apply(&mut response, request, &ctx.state.opts);
    compress::maybe_compress(
        &mut response,
        request.headers.get("accept-encoding").map(String::as_str),
    )
    .await;

    let status = response.status().as_u16();
    let bytes = response_bytes(&response);
    ctx.stats.record_totals(
        &request.method,
        &request.path,
        status,
        bytes,
        request_body_len,
    );
    ctx.state.logger.access(
        client,
        &request.method,
        &request.path,
        &request.version,
        status,
        bytes,
        &request.headers,
    );
    response
}

/// Response body size for the access log and statistics. Buffered bodies
/// report an exact size hint; a streamed proxy relay does not, so its
/// upstream-declared `Content-Length` is used instead, and a streamed
/// response with no declared length logs `0` (the same "unknown" marker the
/// Apache combined format uses).
fn response_bytes(response: &Response<Body>) -> u64 {
    use hyper::body::Body as _;
    response
        .body()
        .size_hint()
        .exact()
        .or_else(|| {
            response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0)
}

/// `.htaccess`/`.htpasswd` are never servable as static content, at any
/// depth — non-negotiable trust boundary (IDEA.md ".htaccess"/".htpasswd"
/// compatibility"), unaffected by (and never overridable from within) the
/// `.htaccess` cascade itself.
fn is_ht_path(decoded: &str) -> bool {
    decoded.split('/').any(|seg| {
        seg == ".htaccess" || seg == ".htpasswd" || (seg.starts_with(".ht") && seg.len() > 3)
    })
}

/// Merges the `.htaccess` cascade rooted at `base_dir` down to the nearest
/// existing directory containing `decoded` (IDEA.md "Discovery is
/// recursive... including `base_dir/.htaccess` itself").
fn htaccess_rules_for(base_dir: &Path, decoded: &str) -> htaccess::Rules {
    let requested = decoded.trim_start_matches('/');
    let candidate = if requested.is_empty() {
        base_dir.to_path_buf()
    } else {
        base_dir.join(requested)
    };
    let mut dir = if candidate.is_dir() {
        candidate
    } else {
        candidate
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| base_dir.to_path_buf())
    };
    loop {
        if dir.is_dir() {
            break;
        }
        match dir.parent() {
            Some(p) if p == base_dir || p.starts_with(base_dir) => dir = p.to_path_buf(),
            _ => {
                dir = base_dir.to_path_buf();
                break;
            }
        }
    }
    let dir = dir.canonicalize().unwrap_or(dir);
    if dir != base_dir && !dir.starts_with(base_dir) {
        return htaccess::Rules::default();
    }
    htaccess::merge_cascade(base_dir, &dir)
}

/// True when any path component between `base_dir` and `candidate` (not yet
/// canonicalized) is itself a symlink — used to enforce `Options
/// -FollowSymLinks`. Default-deny of escaping `base_dir` applies regardless
/// (enforced separately via the post-`canonicalize` `starts_with` check).
fn path_contains_symlink(base_dir: &Path, candidate: &Path) -> bool {
    let rel = match candidate.strip_prefix(base_dir) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let mut cur = base_dir.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        if let Ok(meta) = std::fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                return true;
            }
        }
    }
    false
}

/// Phase 6 of the per-request evaluation order (IDEA.md "ErrorDocument
/// mapping applies to any error status from any phase above"): serves the
/// configured `ErrorDocument` target if one exists for `status`, else falls
/// back to the embedded default error page.
async fn respond_with_error_document(
    status: u16,
    request: &Request,
    opts: &ServeOptions,
    base_dir: &Path,
    rules: &htaccess::Rules,
) -> std::io::Result<Response<Body>> {
    if let Some(target) = rules.error_documents.get(&status) {
        if target.starts_with("http://") || target.starts_with("https://") {
            return build_response(
                302,
                "Found",
                Bytes::new(),
                &[("Location".to_string(), target.clone())],
            );
        }
        let rel = target.trim_start_matches('/');
        if let Ok(resolved) = base_dir.join(rel).canonicalize() {
            if (resolved == base_dir || resolved.starts_with(base_dir)) && resolved.is_file() {
                if let Ok(content) = tokio::fs::read(&resolved).await {
                    let content_type = content_type_for(&resolved, opts);
                    return build_response(
                        status,
                        reason_phrase(status),
                        Bytes::from(content),
                        &[("Content-Type".to_string(), content_type)],
                    );
                }
            }
        }
    }
    respond_error(status, request, opts)
}

/// Best-effort CGI 1.1 PATH_INFO/PATH_TRANSLATED resolution (CGI 1.1
/// §4.1.5/§4.1.6; Apache-compatible "longest existing-file prefix" rule):
/// only reached when the full literal `decoded` path does not exist on
/// disk at all. Walks the path's ancestor `/`-separated segment prefixes —
/// from the immediate parent up to `base_dir` itself, each still required
/// to stay within `base_dir` (never escaping it) — looking for the first
/// prefix that exists, is a file, and `classify_script` still recognizes
/// as a script; the unconsumed trailing segments become `PATH_INFO`
/// (leading-`/`-prefixed), and `PATH_TRANSLATED` is `PATH_INFO` resolved
/// under `base_dir` (which need not itself exist — matching real CGI/
/// Apache behavior for a nonexistent trailing segment). Returns `None` if
/// no ancestor qualifies, in which case the caller falls through to its
/// normal 404 — this never applies to plain static-file resolution or to
/// the directory/default-index branch, only to a fully-nonexistent literal
/// path.
fn resolve_script_path_info(
    base_dir: &Path,
    decoded: &str,
    opts: &ServeOptions,
) -> Option<(PathBuf, ScriptRoute, String, String)> {
    let segs: Vec<&str> = decoded
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    for popped in 1..=segs.len() {
        let prefix = &segs[..segs.len() - popped];
        let candidate = if prefix.is_empty() {
            base_dir.to_path_buf()
        } else {
            base_dir.join(prefix.join("/"))
        };
        let Ok(resolved) = candidate.canonicalize() else {
            continue;
        };
        if resolved != base_dir && !resolved.starts_with(base_dir) {
            continue;
        }
        if !resolved.is_file() {
            continue;
        }
        let Some(route) = classify_script(base_dir, &resolved, opts) else {
            continue;
        };
        let remaining = &segs[segs.len() - popped..];
        let path_info = format!("/{}", remaining.join("/"));
        let path_translated = base_dir
            .join(path_info.trim_start_matches('/'))
            .to_string_lossy()
            .to_string();
        return Some((resolved, route, path_info, path_translated));
    }
    None
}

/// The top-level per-request dispatcher (static files, CGI/scripts,
/// proxying, `.htaccess` pipeline, `/server-info`), shared verbatim by
/// HTTP/1.1, HTTP/2, and HTTP/3 — every access-control decision below
/// applies identically on all three, because all three arrive here.
///
/// `upgrade` is the connection's `Upgrade` handle, present only on HTTP/1.1
/// (HTTP/2 and HTTP/3 have no `Upgrade` mechanism, RFC 9113 §8.1); it is
/// used solely by the framework-proxy WebSocket relay.
async fn handle_request(
    ctx: &ServeContext,
    request: &Request,
    body: &[u8],
    client: &str,
    upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> std::io::Result<Response<Body>> {
    let base_dir: &Path = ctx.base_dir.as_path();
    let opts: &ServeOptions = &ctx.state.opts;
    let stats: &info::Stats = &ctx.stats;
    let proxy_target = &ctx.state.proxy_target;

    let _in_flight = stats.in_flight_guard();
    let handler_started = Instant::now();
    let head_only = request.method == "HEAD";
    let known_method = matches!(
        request.method.as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS"
    );
    if !known_method {
        return respond_error(405, request, opts);
    }

    let raw_path = request.path.split('?').next().unwrap_or("/");
    let query = request.path.split_once('?').map(|x| x.1).unwrap_or("");
    let mut decoded = percent_decode(raw_path);

    // A target that is not origin-form (`OPTIONS *`, authority-form) never
    // names a resource in this document root, and must not be allowed to
    // fall through to path resolution.
    if !decoded.starts_with('/') {
        return respond_error(400, request, opts);
    }

    if is_ht_path(&decoded) {
        return respond_error(403, request, opts);
    }

    // The `/server-info` diagnostics dashboard (IDEA.md "`/server-info`
    // diagnostics dashboard") is a synthetic, built-in route dispatched
    // before the framework-proxy prefix check and before the `.htaccess`
    // 6-phase pipeline — always on, never `--debug`-gated, and never
    // resolved against the filesystem, so it can never surface anything
    // outside `base_dir` or any `.ht*` content.
    if decoded == "/server-info" && (request.method == "GET" || request.method == "HEAD") {
        let html = info::render_dashboard(stats, opts, proxy_target.as_deref());
        return build_response(
            200,
            "OK",
            Bytes::from(html),
            &[(
                "Content-Type".to_string(),
                "text/html; charset=utf-8".to_string(),
            )],
        );
    }

    let remote_ip = client.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(client);

    // Framework dev-server proxying (IDEA.md "Framework dev-server
    // proxying") — a request under `path_prefix` is relayed to the
    // upstream dev server entirely in place of cashttpd's own static/CGI/
    // `.htaccess` pipeline below; everything else still goes through it.
    if let Some(target) = proxy_target {
        if decoded.starts_with(target.path_prefix.as_str()) {
            let _upstream = stats.upstream_guard();
            let outcome = proxy::proxy_request(target, request, body, client, opts, upgrade).await;
            stats.record_handler(info::HandlerType::FrameworkProxy, handler_started.elapsed());
            if let Ok(response) = &outcome {
                let status = response.status().as_u16();
                if status >= 400 {
                    stats.record_issue(
                        info::IssueKind::FrameworkProxyError,
                        &decoded,
                        &format!("upstream returned status {status}"),
                        &request.method,
                        &target.upstream,
                        status,
                        request.headers.get("referer").cloned(),
                    );
                }
            }
            return outcome;
        }
    }

    // A CORS preflight is answered here, after the framework-proxy check (so
    // a dev server that implements its own CORS policy still sees it) but
    // before path resolution: a preflight names no resource to act on, and
    // falling through would answer it `405`, which browsers read as a failed
    // preflight. `headers::apply` attaches the method/header echo on the way
    // out, on this response like any other.
    if let Some(response) = headers::preflight_response(request, opts) {
        stats.record_handler(info::HandlerType::StaticFile, handler_started.elapsed());
        return Ok(response);
    }

    // Phase 1 (IDEA.md 6-phase evaluation order): rewrite/redirect first,
    // it can change the target path/resource before anything else runs.
    let mut rules = htaccess_rules_for(base_dir, &decoded);
    match htaccess::apply_rewrites(
        &rules,
        &decoded,
        query,
        &request.method,
        remote_ip,
        &request.headers,
    ) {
        htaccess::RewriteOutcome::Redirect(status, target) => {
            return build_response(
                status,
                reason_phrase(status),
                Bytes::new(),
                &[("Location".to_string(), target)],
            );
        }
        htaccess::RewriteOutcome::Rewritten(new_path) => {
            if is_ht_path(&new_path) {
                return respond_error(403, request, opts);
            }
            decoded = new_path;
            rules = htaccess_rules_for(base_dir, &decoded);
        }
        htaccess::RewriteOutcome::Unchanged => {}
    }

    // Phase 2: legacy `Order`/`Allow`/`Deny` access control, against the
    // possibly-rewritten target.
    if !htaccess::access_allowed(&rules, remote_ip) {
        stats.record_handler(info::HandlerType::HtaccessDenied, handler_started.elapsed());
        stats.record_issue(
            info::IssueKind::AccessControlDenial,
            &decoded,
            "denied by Order/Allow/Deny",
            &request.method,
            base_dir
                .join(decoded.trim_start_matches('/'))
                .to_string_lossy()
                .as_ref(),
            403,
            request.headers.get("referer").cloned(),
        );
        return respond_with_error_document(403, request, opts, base_dir, &rules).await;
    }

    // Phases 3-4: `AuthType Basic` authentication, then `Require`
    // authorization.
    if rules
        .auth_type
        .as_deref()
        .is_some_and(|t| t.eq_ignore_ascii_case("basic"))
        && rules.require_valid_user()
    {
        let Some(user_file) = rules.auth_user_file.clone() else {
            return respond_with_error_document(500, request, opts, base_dir, &rules).await;
        };
        let creds = request
            .headers
            .get("authorization")
            .and_then(|h| htaccess::parse_basic_auth(h));
        let authed_user = creds.and_then(|(user, pass)| {
            if htaccess::verify_password(&user_file, &user, &pass) {
                Some(user)
            } else {
                None
            }
        });
        match authed_user {
            None => {
                let realm = rules
                    .auth_name
                    .clone()
                    .unwrap_or_else(|| "Restricted".to_string());
                let auth_body = error_page(401, request, opts.debug);
                return build_response(
                    401,
                    reason_phrase(401),
                    Bytes::from(auth_body),
                    &[
                        (
                            "Content-Type".to_string(),
                            "text/html; charset=utf-8".to_string(),
                        ),
                        (
                            "WWW-Authenticate".to_string(),
                            format!("Basic realm=\"{realm}\""),
                        ),
                    ],
                );
            }
            Some(user) => {
                if !htaccess::is_authorized(&rules, &user) {
                    stats.record_handler(
                        info::HandlerType::HtaccessDenied,
                        handler_started.elapsed(),
                    );
                    stats.record_issue(
                        info::IssueKind::AccessControlDenial,
                        &decoded,
                        &format!("user {user} not authorized (Require)"),
                        &request.method,
                        base_dir
                            .join(decoded.trim_start_matches('/'))
                            .to_string_lossy()
                            .as_ref(),
                        403,
                        request.headers.get("referer").cloned(),
                    );
                    return respond_with_error_document(403, request, opts, base_dir, &rules).await;
                }
            }
        }
    }

    let requested = decoded.trim_start_matches('/');
    let candidate = if requested.is_empty() {
        base_dir.to_path_buf()
    } else {
        base_dir.join(requested)
    };

    if rules.follow_symlinks == Some(false) && path_contains_symlink(base_dir, &candidate) {
        stats.record_handler(info::HandlerType::HtaccessDenied, handler_started.elapsed());
        stats.record_issue(
            info::IssueKind::AccessControlDenial,
            &decoded,
            "denied by Options -FollowSymLinks",
            &request.method,
            candidate.to_string_lossy().as_ref(),
            403,
            request.headers.get("referer").cloned(),
        );
        return respond_with_error_document(403, request, opts, base_dir, &rules).await;
    }

    let resolved = match candidate.canonicalize() {
        Ok(p) if p == base_dir || p.starts_with(base_dir) => p,
        _ => {
            if let Some((script_path, route, path_info, path_translated)) =
                resolve_script_path_info(base_dir, &decoded, opts)
            {
                let handler = handler_type_for_route(base_dir, &script_path);
                let outcome = dispatch_script(
                    base_dir,
                    &script_path,
                    &route,
                    request,
                    opts,
                    body,
                    client,
                    head_only,
                    stats,
                    &path_info,
                    &path_translated,
                )
                .await;
                stats.record_handler(handler, handler_started.elapsed());
                return outcome;
            }
            stats.record_handler(info::HandlerType::StaticFile, handler_started.elapsed());
            stats.record_issue(
                info::IssueKind::BrokenStaticRef,
                &decoded,
                "404 not found",
                &request.method,
                candidate.to_string_lossy().as_ref(),
                404,
                request.headers.get("referer").cloned(),
            );
            return respond_with_error_document(404, request, opts, base_dir, &rules).await;
        }
    };

    if resolved.is_dir() {
        if request.method != "GET" && request.method != "HEAD" {
            return respond_with_error_document(405, request, opts, base_dir, &rules).await;
        }
        let default_index = ["index.html".to_string(), "index.htm".to_string()];
        let index_list = rules.directory_index.as_deref().unwrap_or(&default_index);
        for index in index_list {
            let candidate_index = resolved.join(index);
            if candidate_index.is_file() {
                if let Some(route) = classify_script(base_dir, &candidate_index, opts) {
                    let handler = handler_type_for_route(base_dir, &candidate_index);
                    let outcome = dispatch_script(
                        base_dir,
                        &candidate_index,
                        &route,
                        request,
                        opts,
                        body,
                        client,
                        head_only,
                        stats,
                        "",
                        "",
                    )
                    .await;
                    stats.record_handler(handler, handler_started.elapsed());
                    return outcome;
                }
                let outcome =
                    serve_file(&candidate_index, base_dir, request, opts, client, head_only).await;
                stats.record_handler(info::HandlerType::StaticFile, handler_started.elapsed());
                return outcome;
            }
        }
        // `Options Indexes`/`-Indexes` merges with/overrides the config-file
        // `directory_listing` setting for this subtree (IDEA.md "Options").
        if rules.indexes.unwrap_or(opts.directory_listing) {
            let outcome = serve_directory_listing(base_dir, &resolved, raw_path, head_only).await;
            stats.record_handler(
                info::HandlerType::DirectoryListing,
                handler_started.elapsed(),
            );
            return outcome;
        }
        stats.record_handler(info::HandlerType::HtaccessDenied, handler_started.elapsed());
        return respond_with_error_document(403, request, opts, base_dir, &rules).await;
    }

    if let Some(route) = classify_script(base_dir, &resolved, opts) {
        let handler = handler_type_for_route(base_dir, &resolved);
        let outcome = dispatch_script(
            base_dir, &resolved, &route, request, opts, body, client, head_only, stats, "", "",
        )
        .await;
        stats.record_handler(handler, handler_started.elapsed());
        return outcome;
    }

    if request.method != "GET" && request.method != "HEAD" {
        return respond_with_error_document(405, request, opts, base_dir, &rules).await;
    }
    let outcome = serve_file(&resolved, base_dir, request, opts, client, head_only).await;
    stats.record_handler(info::HandlerType::StaticFile, handler_started.elapsed());
    outcome
}

/// Distinguishes IDEA.md's two script-handler-type dashboard buckets
/// (`cgi-bin/` vs generic `script/CGI`) for an already-classified script
/// route, without changing `classify_script`'s return type.
fn handler_type_for_route(base_dir: &Path, resolved: &Path) -> info::HandlerType {
    if resolved
        .strip_prefix(base_dir)
        .ok()
        .and_then(|rel| rel.components().next())
        .is_some_and(|c| c.as_os_str() == "cgi-bin")
    {
        info::HandlerType::CgiBin
    } else {
        info::HandlerType::ScriptCgi
    }
}

/// Which of the two CGI 1.1 execution paths (IDEA.md "Multi-language script
/// execution") a resolved, existing file should be routed through — `None`
/// means "serve as static content".
enum ScriptRoute {
    /// `cgi-bin/` location-based, or a `script_handlers` extension mapped to
    /// the reserved `exec` value: the file itself is exec'd directly and
    /// must be independently executable with its own shebang/native binary.
    ExecDirect,
    /// `script_handlers` extension-based dispatch: the file is passed as an
    /// argument to the given interpreter command.
    Interpreter(String),
}

/// Classifies `resolved` per IDEA.md "Multi-language script execution":
/// path 1 (`cgi-bin/`, location wins unconditionally, extension ignored),
/// then path 2 (`script_handlers` extension table, built-in-table base
/// merged under global/per-project config — see
/// `configs::builtin_script_handlers`). Returns `None` for plain static
/// content (no extension match, or the extension is explicitly disabled via
/// a `null`/empty `script_handlers` entry).
fn classify_script(base_dir: &Path, resolved: &Path, opts: &ServeOptions) -> Option<ScriptRoute> {
    if let Ok(rel) = resolved.strip_prefix(base_dir) {
        if rel
            .components()
            .next()
            .map(|c| c.as_os_str() == "cgi-bin")
            .unwrap_or(false)
        {
            return Some(ScriptRoute::ExecDirect);
        }
    }
    let ext = resolved
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext.is_empty() {
        return None;
    }
    match opts.script_handlers.get(&ext) {
        Some(Some(cmd)) if cmd == "exec" => Some(ScriptRoute::ExecDirect),
        Some(Some(cmd)) => Some(ScriptRoute::Interpreter(cmd.clone())),
        Some(None) | None => None,
    }
}

fn is_executable_file(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        _ => false,
    }
}

/// Resolves an interpreter binary for `script_handlers` per-request (IDEA.md
/// "Interpreter discovery" — never cached, so installing/removing an
/// interpreter while the server runs takes effect on the very next request).
/// Absolute paths are checked directly; bare names are searched on `$PATH`.
fn find_interpreter(bin: &str) -> Option<PathBuf> {
    let path = Path::new(bin);
    if path.is_absolute() {
        return if is_executable_file(path) {
            Some(path.to_path_buf())
        } else {
            None
        };
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(bin);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Splits a script's raw stdout into its CGI header block and body (IDEA.md
/// "CGI 1.1 protocol semantics" — headers first, blank-line-terminated,
/// then body). Falls back to "no headers, whole output is body" when the
/// output doesn't contain a header/body separator or doesn't parse as
/// `Key: value` lines, matching the documented `Content-Type: text/html` /
/// `200 OK` fallback.
fn parse_cgi_output(raw: &[u8]) -> (Vec<(String, String)>, &[u8]) {
    let split_at = find_subslice(raw, b"\r\n\r\n")
        .map(|i| (i, i + 4))
        .or_else(|| find_subslice(raw, b"\n\n").map(|i| (i, i + 2)));
    let Some((head_end, body_start)) = split_at else {
        return (Vec::new(), raw);
    };
    let head_str = String::from_utf8_lossy(&raw[..head_end]);
    let mut headers = Vec::new();
    for line in head_str.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        match line.split_once(':') {
            Some((k, v)) => headers.push((k.trim().to_string(), v.trim().to_string())),
            None => return (Vec::new(), raw),
        }
    }
    if headers.is_empty() {
        return (Vec::new(), raw);
    }
    (headers, &raw[body_start..])
}

/// Renders a 500 with the script/CGI execution's own server-side failure
/// detail folded in under `--debug` (IDEA.md "Debug/error forwarding" —
/// only used when the script produced no usable output at all). Also
/// records a `ScriptFailure` issue on the dashboard with the full captured
/// `detail` (which already includes captured stderr where available), per
/// IDEA.md "`/server-info` diagnostics dashboard" — "full captured stderr
/// for CGI failures".
// Each parameter feeds a distinct part of the error response/log line this
// builds (stream to write to, the failing request, config for error-page
// rendering, keep-alive, the human-readable failure detail, stats to
// record against, and the decoded path/script path for the log entry) —
// no natural subgroup exists that would shrink this without adding
// indirection.
#[allow(clippy::too_many_arguments)]
fn respond_script_failure(
    request: &Request,
    opts: &ServeOptions,
    detail: &str,
    stats: &info::Stats,
    decoded_path: &str,
    script_path: &Path,
) -> std::io::Result<Response<Body>> {
    stats.record_issue(
        info::IssueKind::ScriptFailure,
        decoded_path,
        detail,
        &request.method,
        script_path.to_string_lossy().as_ref(),
        500,
        request.headers.get("referer").cloned(),
    );
    let body = error_page_with_trace(500, request, opts.debug, Some(detail));
    build_response(
        500,
        reason_phrase(500),
        Bytes::from(body),
        &[(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
    )
}

/// Executes a CGI/script request end-to-end (IDEA.md "Multi-language script
/// execution" -> "CGI 1.1 protocol semantics"): resolves the program to run
/// (per `route`), builds the full CGI 1.1 environment — including
/// `PATH_INFO`/`PATH_TRANSLATED` (CGI 1.1 §4.1.5/§4.1.6), threaded through
/// from `handle_request`'s ancestor-prefix script resolution and empty for
/// a request that names the script's own path with no extra trailing
/// segments — streams the request body to the child's stdin, captures
/// stdout/stderr, and translates the script's CGI-style output into an
/// HTTP response. No execution timeout — "No artificial resource limits"
/// (IDEA.md "Security").
// CGI/multi-language script dispatch (IDEA.md "CGI 1.1 / multi-language
// scripting") needs base_dir, the resolved script path, the matched route's
// interpreter config, the parsed request, effective server config, body,
// client address, and whether it's a HEAD request all at once to build the
// correct CGI environment and response — these are the CGI-spec-mandated
// inputs, not accumulated incidental state.
#[allow(clippy::too_many_arguments)]
async fn dispatch_script(
    base_dir: &Path,
    script_path: &Path,
    route: &ScriptRoute,
    request: &Request,
    opts: &ServeOptions,
    body: &[u8],
    client: &str,
    head_only: bool,
    stats: &info::Stats,
    path_info: &str,
    path_translated: &str,
) -> std::io::Result<Response<Body>> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;

    let decoded_path = percent_decode(request.path.split('?').next().unwrap_or("/"));

    let (program, fixed_args) = match route {
        ScriptRoute::ExecDirect => {
            if !is_executable_file(script_path) {
                return respond_script_failure(
                    request,
                    opts,
                    &format!(
                        "{} is not marked executable (cgi-bin/exec-directly scripts require \
                         their own executable bit and shebang/native binary)",
                        script_path.display()
                    ),
                    stats,
                    &decoded_path,
                    script_path,
                );
            }
            (script_path.to_path_buf(), Vec::new())
        }
        ScriptRoute::Interpreter(cmd) => {
            let mut parts = cmd.split_whitespace();
            let bin = match parts.next() {
                Some(b) => b,
                None => {
                    return respond_script_failure(
                        request,
                        opts,
                        "script_handlers entry resolved to an empty command",
                        stats,
                        &decoded_path,
                        script_path,
                    );
                }
            };
            let fixed_args: Vec<String> = parts.map(str::to_string).collect();
            match find_interpreter(bin) {
                Some(p) => (p, fixed_args),
                None => {
                    let msg = format!("{bin} is not installed");
                    stats.record_issue(
                        info::IssueKind::MissingInterpreter,
                        &decoded_path,
                        &msg,
                        &request.method,
                        script_path.to_string_lossy().as_ref(),
                        503,
                        request.headers.get("referer").cloned(),
                    );
                    return build_response(
                        503,
                        "Service Unavailable",
                        Bytes::from(msg),
                        &[(
                            "Content-Type".to_string(),
                            "text/plain; charset=utf-8".to_string(),
                        )],
                    );
                }
            }
        }
    };

    let query = request.path.split_once('?').map(|x| x.1).unwrap_or("");
    let script_name = format!(
        "/{}",
        script_path
            .strip_prefix(base_dir)
            .unwrap_or(script_path)
            .to_string_lossy()
            .replace('\\', "/")
    );
    let (remote_addr, remote_port) = client.rsplit_once(':').unwrap_or((client, ""));

    let mut cmd = Command::new(&program);
    if matches!(route, ScriptRoute::Interpreter(_)) {
        for a in &fixed_args {
            cmd.arg(a);
        }
        cmd.arg(script_path);
    }

    let work_dir = script_path.parent().unwrap_or(base_dir);
    cmd.current_dir(work_dir);
    cmd.env("REQUEST_METHOD", &request.method);
    cmd.env("QUERY_STRING", query);
    cmd.env(
        "CONTENT_TYPE",
        request
            .headers
            .get("content-type")
            .cloned()
            .unwrap_or_default(),
    );
    cmd.env("CONTENT_LENGTH", body.len().to_string());
    cmd.env("SCRIPT_NAME", &script_name);
    cmd.env("SCRIPT_FILENAME", script_path.to_string_lossy().to_string());
    cmd.env("PATH_INFO", path_info);
    cmd.env("PATH_TRANSLATED", path_translated);
    cmd.env(
        "SERVER_NAME",
        opts.fqdn.clone().unwrap_or_else(|| "localhost".to_string()),
    );
    cmd.env("SERVER_PORT", opts.port.to_string());
    cmd.env("SERVER_PROTOCOL", &request.version);
    cmd.env(
        "SERVER_SOFTWARE",
        format!("cashttpd/{}", crate::supports::version::VERSION),
    );
    cmd.env("GATEWAY_INTERFACE", "CGI/1.1");
    cmd.env("REMOTE_ADDR", remote_addr);
    cmd.env("REMOTE_PORT", remote_port);
    cmd.env("DOCUMENT_ROOT", base_dir.to_string_lossy().to_string());
    if opts.tls_enabled {
        cmd.env("HTTPS", "on");
    }
    for (k, v) in &request.headers {
        if k.eq_ignore_ascii_case("content-type") || k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        let var = format!("HTTP_{}", k.to_ascii_uppercase().replace('-', "_"));
        cmd.env(var, v);
    }

    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // The child must not inherit this process's signal disposition surprises
    // or outlive the response: `kill_on_drop` guarantees the subprocess is
    // reaped if this task is cancelled (client disconnect on an HTTP/2 or
    // HTTP/3 stream reset), which the previous blocking implementation could
    // not express.
    cmd.kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) => {
            return respond_script_failure(
                request,
                opts,
                &format!("failed to start {}: {err}", program.display()),
                stats,
                &decoded_path,
                script_path,
            );
        }
    };

    // Feeding stdin from a separate task while `wait_with_output` concurrently
    // drains stdout/stderr is what removes the deadlock the synchronous
    // implementation had: a request body larger than the pipe buffer used to
    // block the server in `write_all` while the script blocked writing a
    // response nothing was reading.
    if let Some(mut stdin) = child.stdin.take() {
        let payload = body.to_vec();
        tokio::spawn(async move {
            if !payload.is_empty() {
                let _ = stdin.write_all(&payload).await;
            }
            let _ = stdin.shutdown().await;
        });
    }

    let output = child.wait_with_output().await;
    let (stdout_buf, stderr_buf, wait_result) = match output {
        Ok(out) => (out.stdout, out.stderr, Ok(out.status)),
        Err(err) => (Vec::new(), Vec::new(), Err(err)),
    };

    if stdout_buf.is_empty() {
        let detail = match wait_result {
            Ok(status) if !status.success() => format!(
                "{} exited with {status}\n{}",
                program.display(),
                String::from_utf8_lossy(&stderr_buf)
            ),
            Err(err) => format!("failed to wait on {}: {err}", program.display()),
            Ok(_) => String::from_utf8_lossy(&stderr_buf).to_string(),
        };
        return respond_script_failure(request, opts, &detail, stats, &decoded_path, script_path);
    }

    let (headers, cgi_body) = parse_cgi_output(&stdout_buf);
    let mut resp_status = 200u16;
    let mut resp_reason = "OK".to_string();
    let mut extra: Vec<(String, String)> = Vec::new();
    let mut has_content_type = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("status") {
            let mut parts = v.splitn(2, ' ');
            if let Some(code) = parts.next().and_then(|c| c.trim().parse::<u16>().ok()) {
                resp_status = code;
                resp_reason = parts
                    .next()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| reason_phrase(code))
                    .to_string();
            }
            continue;
        }
        if k.eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }
        extra.push((k, v));
    }
    if !has_content_type {
        extra.push((
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        ));
    }

    // A HEAD response keeps the script's own `Content-Length` semantics: the
    // body is dropped but the length header still describes what a GET would
    // have returned (RFC 9110 §9.3.2).
    let payload = if head_only {
        if !extra
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        {
            extra.push(("Content-Length".to_string(), cgi_body.len().to_string()));
        }
        Bytes::new()
    } else {
        Bytes::copy_from_slice(cgi_body)
    };

    build_response(resp_status, &resp_reason, payload, &extra)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn etag_for(len: u64, modified: SystemTime) -> String {
    let secs = modified
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("\"{len:x}-{secs:x}\"")
}

fn http_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_http_date(secs)
}

/// Minimal RFC 9110 §5.6.7 "IMF-fixdate" formatter — no external date crate
/// dependency for this single call site.
fn format_http_date(unix_secs: u64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days_since_epoch = unix_secs / 86400;
    let secs_of_day = unix_secs % 86400;
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    let weekday = DAYS[((days_since_epoch + 4) % 7) as usize];

    let mut days = days_since_epoch as i64;
    let mut year = 1970i64;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let year_days = if leap { 366 } else { 365 };
        if days < year_days {
            break;
        }
        days -= year_days;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_lengths = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0usize;
    for (idx, len) in month_lengths.iter().enumerate() {
        if days < *len {
            month = idx;
            break;
        }
        days -= len;
    }
    let day = days + 1;

    format!(
        "{weekday}, {day:02} {} {year} {h:02}:{m:02}:{s:02} GMT",
        MONTHS[month]
    )
}

fn content_type_for(path: &Path, opts: &ServeOptions) -> String {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if let Some(overridden) = opts.mime_types.get(&ext) {
        return overridden.clone();
    }
    let guess = mime_guess::from_path(path).first_or_octet_stream();
    let essence = guess.essence_str().to_string();
    if essence.starts_with("text/")
        || essence == "application/json"
        || essence == "application/javascript"
    {
        format!("{essence}; charset=utf-8")
    } else {
        essence
    }
}

// Static-file serving (conditional requests, single-range `Range`,
// `Content-Type` detection) needs the stream, resolved path, parsed
// request, effective config, and the head-only/keep-alive flags together
// to pick the right status/headers/body per RFC 7232/7233 — each is used
// independently in that decision.
#[allow(clippy::too_many_arguments)]
async fn serve_file(
    path: &Path,
    base_dir: &Path,
    request: &Request,
    opts: &ServeOptions,
    client: &str,
    head_only: bool,
) -> std::io::Result<Response<Body>> {
    let metadata = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(_) => return respond_error(404, request, opts),
    };
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

    // Server-Side Includes (IDEA.md "Server-Side Includes (SSI)") take over
    // before any conditional-request or `Range` handling: the composed output
    // is not the file on disk, so this file's size, mtime, and byte offsets
    // do not describe it (see `ssi::serve`).
    if ssi::applies(path, opts) {
        return ssi::serve(path, base_dir, request, opts, client, head_only, modified).await;
    }

    let len = metadata.len();
    let etag = etag_for(len, modified);
    let last_modified = http_date(modified);

    if let Some(inm) = request.headers.get("if-none-match") {
        if inm == &etag {
            return build_response(304, "Not Modified", Bytes::new(), &[]);
        }
    } else if let Some(ims) = request.headers.get("if-modified-since") {
        if ims == &last_modified {
            return build_response(304, "Not Modified", Bytes::new(), &[]);
        }
    }

    let content_type = content_type_for(path, opts);
    let extra = vec![
        ("ETag".to_string(), etag),
        ("Last-Modified".to_string(), last_modified),
        ("Accept-Ranges".to_string(), "bytes".to_string()),
        ("Content-Type".to_string(), content_type),
    ];

    if let Some(range) = request.headers.get("range") {
        if let Some((start, end)) = parse_range(range, len) {
            let take = (end - start + 1) as usize;
            let mut range_headers = extra;
            range_headers.push((
                "Content-Range".to_string(),
                format!("bytes {start}-{end}/{len}"),
            ));
            // A HEAD on a range request still reports the selected range's
            // length without reading it (RFC 9110 §9.3.2).
            if head_only {
                range_headers.push(("Content-Length".to_string(), take.to_string()));
                return build_response(206, "Partial Content", Bytes::new(), &range_headers);
            }
            let mut file = tokio::fs::File::open(path).await?;
            file.seek_to(start).await?;
            let mut buf = vec![0u8; take];
            {
                use tokio::io::AsyncReadExt;
                file.read_exact(&mut buf).await?;
            }
            return build_response(206, "Partial Content", Bytes::from(buf), &range_headers);
        }
        return build_response(
            416,
            "Range Not Satisfiable",
            Bytes::new(),
            &[("Content-Range".to_string(), format!("bytes */{len}"))],
        );
    }

    // HEAD never reads the file: the declared `Content-Length` is taken from
    // the metadata already loaded above, so a HEAD on a multi-gigabyte file
    // costs one `stat` (RFC 9110 §9.3.2).
    if head_only {
        let mut head_headers = extra;
        head_headers.push(("Content-Length".to_string(), len.to_string()));
        return build_response(200, "OK", Bytes::new(), &head_headers);
    }
    let body = tokio::fs::read(path).await?;
    build_response(200, "OK", Bytes::from(body), &extra)
}

trait SeekExt {
    async fn seek_to(&mut self, pos: u64) -> std::io::Result<()>;
}

impl SeekExt for tokio::fs::File {
    async fn seek_to(&mut self, pos: u64) -> std::io::Result<()> {
        use std::io::SeekFrom;
        use tokio::io::AsyncSeekExt;
        self.seek(SeekFrom::Start(pos)).await?;
        Ok(())
    }
}

/// Parses a single `bytes=start-end` range (RFC 9110 §14.1.2) — multi-range
/// (`multipart/byteranges`) is not yet implemented, tracked in TODO.AI.md.
fn parse_range(header: &str, len: u64) -> Option<(u64, u64)> {
    let spec = header.strip_prefix("bytes=")?;
    let spec = spec.split(',').next()?.trim();
    let (start_s, end_s) = spec.split_once('-')?;
    if start_s.is_empty() {
        let suffix: u64 = end_s.parse().ok()?;
        if suffix == 0 || len == 0 {
            return None;
        }
        let start = len.saturating_sub(suffix);
        return Some((start, len - 1));
    }
    let start: u64 = start_s.parse().ok()?;
    let end: u64 = if end_s.is_empty() {
        len.saturating_sub(1)
    } else {
        end_s.parse().ok()?
    };
    if start > end || start >= len {
        return None;
    }
    Some((start, end.min(len.saturating_sub(1))))
}

async fn serve_directory_listing(
    base_dir: &Path,
    dir: &Path,
    raw_path: &str,
    head_only: bool,
) -> std::io::Result<Response<Body>> {
    let mut entries: Vec<(String, Option<u64>)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name == ".htaccess" || name == ".htpasswd" || name.starts_with(".ht") {
                return None;
            }
            let is_dir = e.path().is_dir();
            let size = if is_dir {
                None
            } else {
                e.metadata().ok().map(|m| m.len())
            };
            Some((if is_dir { format!("{name}/") } else { name }, size))
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let display_path = if raw_path.starts_with('/') {
        raw_path.to_string()
    } else {
        format!("/{raw_path}")
    };
    let _ = base_dir;
    let rows: String = entries
        .iter()
        .map(|(e, size)| {
            let href = format!("/{e}");
            let size_label = size.map(crate::supports::format::size).unwrap_or_default();
            format!(
                "<li><a href=\"{}{href}\">{}</a><span class=\"size\">{size_label}</span></li>",
                display_path.trim_end_matches('/'),
                html_escape(e)
            )
        })
        .collect();
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" \
         content=\"width=device-width, initial-scale=1\"><title>Index of {p}</title>\
         <style>body{{font-family:system-ui,sans-serif;margin:1rem;max-width:40rem}}\
         ul{{list-style:none;padding:0}}li{{padding:.4rem 0;border-bottom:1px solid #ddd}}\
         a{{text-decoration:none;color:#2563eb;word-break:break-all}}</style></head>\
         <body><h1>Index of {p}</h1><ul>{rows}</ul></body></html>",
        p = html_escape(&display_path)
    );
    let headers = if head_only {
        vec![
            (
                "Content-Type".to_string(),
                "text/html; charset=utf-8".to_string(),
            ),
            ("Content-Length".to_string(), body.len().to_string()),
        ]
    } else {
        vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )]
    };
    let payload = if head_only {
        Bytes::new()
    } else {
        Bytes::from(body)
    };
    build_response(200, "OK", payload, &headers)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        416 => "Range Not Satisfiable",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// Embedded mobile-first error page (IDEA.md "Error pages and debug mode")
/// — no dependency on any file existing in `base_dir`.
fn error_page(status: u16, request: &Request, debug: bool) -> String {
    error_page_with_trace(status, request, debug, None)
}

/// Same as `error_page`, additionally folding in the server's own view of a
/// script/CGI execution failure under `--debug` (IDEA.md "Debug/error
/// forwarding" — only surfaced when the script produced no usable output at
/// all; a script's own error output/page is always relayed as-is, never
/// routed through this path).
fn error_page_with_trace(
    status: u16,
    request: &Request,
    debug: bool,
    trace: Option<&str>,
) -> String {
    let reason = reason_phrase(status);
    let detail = if debug {
        match trace {
            Some(t) => format!(
                "<p class=\"detail\">Debug mode is on — server-side failure detail:</p>\
                 <pre class=\"detail\">{}</pre>",
                html_escape(t)
            ),
            None => "<p class=\"detail\">Debug mode is on.</p>".to_string(),
        }
    } else {
        String::new()
    };
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{status} {reason}</title>\
         <style>body{{font-family:system-ui,sans-serif;margin:0;padding:2rem 1.25rem;\
         background:#0f172a;color:#e2e8f0;min-height:100vh;box-sizing:border-box}}\
         .card{{max-width:32rem;margin:2rem auto;background:#1e293b;border-radius:.75rem;\
         padding:1.5rem}}h1{{font-size:2.5rem;margin:0 0 .25rem}}\
         .reason{{font-size:1.1rem;color:#94a3b8;margin:0 0 1rem}}\
         code{{background:#334155;padding:.15rem .4rem;border-radius:.25rem}}\
         .detail{{color:#fbbf24}}pre.detail{{white-space:pre-wrap;word-break:break-word;\
         overflow-x:auto}}</style></head><body><div class=\"card\">\
         <h1>{status}</h1><p class=\"reason\">{reason}</p>\
         <p><code>{method} {path}</code></p>{detail}</div></body></html>",
        method = html_escape(&request.method),
        path = html_escape(&request.path),
    )
}

/// Builds the canonical error response for `status`, using the embedded
/// error page. A HEAD request keeps the length header a GET would have
/// produced but carries no body (RFC 9110 §9.3.2).
fn respond_error(
    status: u16,
    request: &Request,
    opts: &ServeOptions,
) -> std::io::Result<Response<Body>> {
    let body = error_page(status, request, opts.debug);
    let mut headers = vec![(
        "Content-Type".to_string(),
        "text/html; charset=utf-8".to_string(),
    )];
    if request.method == "HEAD" {
        headers.push(("Content-Length".to_string(), body.len().to_string()));
        return build_response(status, reason_phrase(status), Bytes::new(), &headers);
    }
    build_response(status, reason_phrase(status), Bytes::from(body), &headers)
}

/// Assembles a `hyper` response from a status line, body, and the handler's
/// extra headers. Version-specific framing (chunked/`Content-Length` for
/// HTTP/1.1, HPACK for HTTP/2, QPACK for HTTP/3) is `hyper`'s/`h3`'s job —
/// this only produces the abstract message, which is what keeps one handler
/// pipeline serving all three protocol versions. Header names and values
/// that cannot be represented on the wire are rejected here rather than
/// silently forwarded, so a CGI script cannot inject a response header
/// (`Status: 200\r\nSet-Cookie: ...`-style splitting) — `http`'s parsers
/// refuse CR/LF and other illegal octets outright.
fn build_response(
    status: u16,
    reason: &str,
    body: Bytes,
    extra_headers: &[(String, String)],
) -> std::io::Result<Response<Body>> {
    let code = StatusCode::from_u16(status)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let mut builder = Response::builder().status(code);
    // A custom reason phrase only exists on HTTP/1.1; `hyper` drops the
    // extension for HTTP/2 and HTTP/3, which have no reason phrase at all
    // (RFC 9113 §8.3.2). Only attach it when it differs from the canonical
    // phrase, so ordinary responses stay byte-identical to before.
    if reason != code.canonical_reason().unwrap_or("") {
        if let Ok(phrase) = hyper::ext::ReasonPhrase::try_from(reason.as_bytes().to_vec()) {
            if let Some(ext) = builder.extensions_mut() {
                ext.insert(phrase);
            }
        }
    }
    if let Some(headers) = builder.headers_mut() {
        for (k, v) in extra_headers {
            let Ok(name) = http::header::HeaderName::from_bytes(k.as_bytes()) else {
                continue;
            };
            let Ok(value) = http::HeaderValue::from_str(v) else {
                continue;
            };
            headers.append(name, value);
        }
    }
    builder
        .body(full_body(body))
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

/// One log stream (access or error): its open file handle, path, and
/// rotation/retention state (IDEA.md "Log rotation and retention").
struct LogStream {
    path: PathBuf,
    file: Option<std::fs::File>,
    rotate: crate::supports::rotation::RotatePolicy,
    keep: crate::supports::rotation::KeepPolicy,
    period_start: u64,
}

impl LogStream {
    fn open(path: PathBuf, rotate_spec: &str, keep_spec: &str) -> Self {
        let rotate = crate::supports::rotation::parse_rotate(rotate_spec);
        let keep = crate::supports::rotation::parse_keep(keep_spec);
        // Retention is checked once at startup, to catch files that aged
        // out while the server wasn't running (IDEA.md "Retention is
        // checked at each rotation ... and once at server startup").
        crate::supports::rotation::apply_retention(&path, keep).ok();
        let period_start = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            });
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok();
        Self {
            path,
            file,
            rotate,
            keep,
            period_start,
        }
    }

    /// Rotates the active file if its rotate policy requires it, then
    /// reopens a fresh active file. Checked opportunistically before every
    /// write rather than via a background timer.
    fn maybe_rotate(&mut self) {
        let current_len = self
            .file
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .map(|m| m.len())
            .unwrap_or(0);
        if !crate::supports::rotation::should_rotate(&self.rotate, current_len, self.period_start) {
            return;
        }
        self.file = None;
        if crate::supports::rotation::rotate_file(&self.path, self.keep).is_ok() {
            self.period_start = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            self.file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .ok();
        }
    }

    fn write_line(&mut self, line: &str) {
        self.maybe_rotate();
        if let Some(f) = self.file.as_mut() {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// Unconditional access/error file logging (IDEA.md "Logging") — Apache
/// combined access format and Apache-style error format, written under
/// `{log_dir}/{derived_name}_{access,error}.log`, with time/size rotation
/// and age/count retention per IDEA.md "Log rotation and retention".
struct Logger {
    access: std::sync::Mutex<LogStream>,
    error: std::sync::Mutex<LogStream>,
    quiet: bool,
}

impl Logger {
    #[cfg(test)]
    fn open(log_dir: &Path, name: &str, quiet: bool) -> Self {
        Self::open_with_policy(log_dir, name, quiet, "daily", "30d", "daily", "30d")
    }

    // Log directory/name plus the independent access-log and error-log
    // rotate/keep policies (each configurable separately per IDEA.md
    // "Logging") must all be supplied at open time to construct both
    // `LogStream`s correctly — collapsing the two policy pairs into one
    // struct would only rename the same six values.
    #[allow(clippy::too_many_arguments)]
    fn open_with_policy(
        log_dir: &Path,
        name: &str,
        quiet: bool,
        access_rotate: &str,
        access_keep: &str,
        error_rotate: &str,
        error_keep: &str,
    ) -> Self {
        let access = LogStream::open(
            log_dir.join(format!("{name}_access.log")),
            access_rotate,
            access_keep,
        );
        let error = LogStream::open(
            log_dir.join(format!("{name}_error.log")),
            error_rotate,
            error_keep,
        );
        Self {
            access: std::sync::Mutex::new(access),
            error: std::sync::Mutex::new(error),
            quiet,
        }
    }

    // Mirrors the Apache "combined" access-log format's own field list
    // (IDEA.md "Logging") — client, method, path, version, status, bytes,
    // and headers (for referer/user-agent) are exactly the fields that
    // format requires per line; grouping them would just wrap that spec.
    #[allow(clippy::too_many_arguments)]
    fn access(
        &self,
        client: &str,
        method: &str,
        path: &str,
        version: &str,
        status: u16,
        bytes: u64,
        headers: &HashMap<String, String>,
    ) {
        let host = client.rsplit_once(':').map(|(h, _)| h).unwrap_or(client);
        let now = format_http_date(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        let referer = headers
            .get("referer")
            .cloned()
            .unwrap_or_else(|| "-".to_string());
        let agent = headers
            .get("user-agent")
            .cloned()
            .unwrap_or_else(|| "-".to_string());
        let line = format!(
            "{host} - - [{now}] \"{method} {path} {version}\" {status} {bytes} \"{referer}\" \"{agent}\"\n"
        );
        if !self.quiet {
            print!("{line}");
        }
        if let Ok(mut guard) = self.access.lock() {
            guard.write_line(&line);
        }
    }

    fn error(&self, message: &str) {
        let now = format_http_date(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        let line = format!("[{now}] [error] {message}\n");
        eprint!("{line}");
        if let Ok(mut guard) = self.error.lock() {
            guard.write_line(&line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;
    use std::net::TcpStream;

    fn unique_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "cashttpd-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        dir
    }

    fn test_opts(base_dir: PathBuf) -> ServeOptions {
        crate::configs::Resolved {
            base_dir,
            listen: "127.0.0.1".to_string(),
            port: 0,
            log_dir: std::env::temp_dir(),
            debug: false,
            fqdn: None,
            tls_enabled: false,
            directory_listing: false,
            mime_types: Default::default(),
            script_handlers: Default::default(),
            proxy: Default::default(),
            logging_access_format: "combined".to_string(),
            logging_access_rotate: "daily".to_string(),
            logging_access_keep: "30d".to_string(),
            logging_error_format: "standard".to_string(),
            logging_error_rotate: "daily".to_string(),
            logging_error_keep: "30d".to_string(),
            ssi_extensions: crate::configs::builtin_ssi_extensions(),
            security_headers: crate::configs::builtin_security_headers(
                false,
                crate::configs::ServerTokens::Full,
            ),
            cors: Some(crate::configs::builtin_cors_headers()),
            project_config_path: PathBuf::new(),
        }
    }

    #[test]
    fn parse_cli_overrides_reads_all_flags() {
        let dir = std::env::temp_dir().join("somewhere");
        let log = std::env::temp_dir().join("logs");
        let args = vec![
            "--listen".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            "9090".to_string(),
            "--dir".to_string(),
            dir.to_string_lossy().into_owned(),
            "--fqdn".to_string(),
            "example.test".to_string(),
            "--log".to_string(),
            log.to_string_lossy().into_owned(),
            "--debug".to_string(),
        ];
        let o = parse_cli_overrides(&args);
        assert_eq!(o.listen.as_deref(), Some("127.0.0.1"));
        assert_eq!(o.port, Some(9090));
        assert_eq!(o.base_dir, Some(dir));
        assert_eq!(o.fqdn.as_deref(), Some("example.test"));
        assert_eq!(o.log_dir, Some(log));
        assert_eq!(o.debug, Some(true));
    }

    #[test]
    fn parse_cli_overrides_defaults_when_no_flags() {
        let o = parse_cli_overrides(&[]);
        assert!(o.listen.is_none());
        assert!(o.port.is_none());
        assert!(o.base_dir.is_none());
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    fn test_context(opts: ServeOptions) -> ServeContext {
        let base_dir = opts.base_dir.clone();
        ServeContext {
            base_dir: Arc::new(base_dir),
            state: Arc::new(RuntimeState {
                opts: Arc::new(opts),
                tls_config: None,
                proxy_target: None,
                logger: Arc::new(Logger::open(&std::env::temp_dir(), "test", true)),
            }),
            stats: Arc::new(info::Stats::new("test")),
        }
    }

    fn request_over_loopback(base_dir: &Path, request_line: &str) -> String {
        request_over_loopback_opts(test_opts(base_dir.to_path_buf()), request_line)
    }

    /// Drives one real cleartext connection end to end through the same
    /// `serve_tcp_connection` the accept loop uses, so these tests exercise
    /// `hyper`'s actual HTTP/1.1 framing rather than a stand-in.
    fn request_over_loopback_opts(opts: ServeOptions, request_line: &str) -> String {
        request_over_loopback_bytes(opts, request_line.as_bytes(), b"Connection: close\r\n\r\n")
    }

    fn request_over_loopback_bytes(opts: ServeOptions, head: &[u8], tail: &[u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let ctx = test_context(opts);
        let handle = std::thread::spawn(move || {
            let (stream, peer) = listener.accept().unwrap();
            // `accept()` hands back a blocking socket even from a
            // non-blocking listener; tokio refuses to adopt one.
            stream.set_nonblocking(true).unwrap();
            block_on(async move {
                let stream = tokio::net::TcpStream::from_std(stream).unwrap();
                serve_tcp_connection(stream, peer, ctx).await.unwrap();
            });
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(head).unwrap();
        client.write_all(tail).unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).unwrap();
        handle.join().unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }

    #[test]
    fn build_response_full_body_includes_headers_and_content() {
        let response = build_response(200, "OK", Bytes::from_static(b"hello"), &[]).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let collected = block_on(response.into_body().collect()).unwrap().to_bytes();
        assert_eq!(collected.as_ref(), b"hello");
    }

    #[test]
    fn build_response_rejects_header_injection_from_script_output() {
        let response = build_response(
            200,
            "OK",
            Bytes::new(),
            &[(
                "X-Bad".to_string(),
                "value\r\nSet-Cookie: injected=1".to_string(),
            )],
        )
        .unwrap();
        assert!(!response.headers().contains_key("set-cookie"));
        assert!(!response.headers().contains_key("x-bad"));
    }

    #[test]
    fn head_request_omits_body_but_keeps_length() {
        let dir = unique_dir("head-only");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("hello.txt"), b"hi there").unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "HEAD /hello.txt HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Length: 8\r\n"));
        assert!(response.ends_with("\r\n\r\n"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn serves_existing_file_with_etag_and_content_type() {
        let dir = unique_dir("serve");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("hello.txt"), b"hi there").unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "GET /hello.txt HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        // hyper title-cases outgoing HTTP/1.1 header names token by token, so
        // the entity tag goes out as `Etag:`. Header names are
        // case-insensitive (RFC 9110 §5.1), so the assertion is too.
        assert!(response.to_ascii_lowercase().contains("\netag:"));
        assert!(response.contains("Content-Type: text/plain"));
        assert!(response.ends_with("hi there"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn server_info_dashboard_is_served_end_to_end() {
        let dir = unique_dir("server-info");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "GET /server-info HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Type: text/html"));
        assert!(response.contains("cashttpd /server-info"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn defaults_root_to_index_html() {
        let dir = unique_dir("index");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("index.html"), b"<html></html>").unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "GET / HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("<html></html>"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn returns_403_for_directory_without_index_and_listing_disabled() {
        let dir = unique_dir("no-index");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "GET / HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn returns_directory_listing_when_enabled() {
        let dir = unique_dir("listing");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.txt"), b"a").unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let mut opts = test_opts(base_dir.clone());
        opts.directory_listing = true;

        let response = request_over_loopback_opts(opts, "GET / HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("a.txt"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn returns_404_for_missing_file() {
        let dir = unique_dir("missing");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "GET /nope.txt HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn blocks_path_traversal_outside_base_dir() {
        let dir = unique_dir("traversal");
        fs::create_dir_all(&dir).unwrap();
        let secret_parent = std::env::temp_dir();
        let secret_name = format!(
            "cashttpd-test-secret-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        fs::write(secret_parent.join(&secret_name), b"top secret").unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let request_line = format!("GET /../{secret_name} HTTP/1.1\r\n");
        let response = request_over_loopback(&base_dir, &request_line);
        assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));

        fs::remove_dir_all(&dir).ok();
        fs::remove_file(secret_parent.join(&secret_name)).ok();
    }

    #[test]
    fn denies_htaccess_as_static_content() {
        let dir = unique_dir("htaccess");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(".htaccess"), b"secret directives").unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "GET /.htaccess HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_unsupported_method() {
        let dir = unique_dir("method");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "POST / HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn head_request_omits_body() {
        let dir = unique_dir("head");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("index.html"), b"<html></html>").unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "HEAD / HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("\r\n\r\n"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn range_request_returns_partial_content() {
        let dir = unique_dir("range");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("data.txt"), b"0123456789").unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response =
            request_over_loopback(&base_dir, "GET /data.txt HTTP/1.1\r\nRange: bytes=2-4\r\n");
        assert!(response.starts_with("HTTP/1.1 206 Partial Content\r\n"));
        assert!(response.contains("Content-Range: bytes 2-4/10"));
        assert!(response.ends_with("234"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn conditional_request_with_matching_etag_returns_304() {
        let dir = unique_dir("conditional");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("data.txt"), b"hello").unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let first = request_over_loopback(&base_dir, "GET /data.txt HTTP/1.1\r\n");
        let etag = first
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("etag:"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .unwrap();

        let second_request = format!("GET /data.txt HTTP/1.1\r\nIf-None-Match: {etag}\r\n");
        let second = request_over_loopback(&base_dir, &second_request);
        assert!(second.starts_with("HTTP/1.1 304 Not Modified\r\n"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_range_handles_suffix_and_open_ended() {
        assert_eq!(parse_range("bytes=0-4", 10), Some((0, 4)));
        assert_eq!(parse_range("bytes=5-", 10), Some((5, 9)));
        assert_eq!(parse_range("bytes=-3", 10), Some((7, 9)));
        assert_eq!(parse_range("bytes=20-30", 10), None);
        assert_eq!(parse_range("garbage", 10), None);
    }

    #[test]
    fn format_http_date_matches_imf_fixdate_shape() {
        // 2024-01-01T00:00:00Z
        let date = format_http_date(1704067200);
        assert_eq!(date, "Mon, 01 Jan 2024 00:00:00 GMT");
    }

    #[test]
    fn content_type_uses_override_when_present() {
        let dir = unique_dir("mime");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let mut opts = test_opts(base_dir);
        opts.mime_types
            .insert("txt".to_string(), "application/x-custom".to_string());
        let path = PathBuf::from("file.txt");
        assert_eq!(content_type_for(&path, &opts), "application/x-custom");
    }

    #[test]
    fn html_escape_escapes_special_characters() {
        assert_eq!(html_escape("<a>&\"b\""), "&lt;a&gt;&amp;&quot;b&quot;");
    }

    #[test]
    fn parse_cgi_output_splits_headers_and_body() {
        let raw = b"Content-Type: text/plain\r\nX-Foo: bar\r\n\r\nhello world";
        let (headers, body) = parse_cgi_output(raw);
        assert_eq!(
            headers,
            vec![
                ("Content-Type".to_string(), "text/plain".to_string()),
                ("X-Foo".to_string(), "bar".to_string()),
            ]
        );
        assert_eq!(body, b"hello world");
    }

    #[test]
    fn parse_cgi_output_falls_back_to_whole_body_without_header_block() {
        let raw = b"just a plain body, no headers here";
        let (headers, body) = parse_cgi_output(raw);
        assert!(headers.is_empty());
        assert_eq!(body, raw);
    }

    #[test]
    fn classify_script_routes_cgi_bin_regardless_of_extension() {
        let dir = unique_dir("classify-cgi-bin");
        fs::create_dir_all(dir.join("cgi-bin")).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let opts = test_opts(base_dir.clone());
        let script = base_dir.join("cgi-bin").join("thing.php");
        fs::write(&script, "#!/bin/sh\n").unwrap();
        assert!(matches!(
            classify_script(&base_dir, &script, &opts),
            Some(ScriptRoute::ExecDirect)
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn classify_script_routes_extension_to_interpreter() {
        let dir = unique_dir("classify-ext");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let mut opts = test_opts(base_dir.clone());
        opts.script_handlers
            .insert("py".to_string(), Some("python3".to_string()));
        let script = base_dir.join("app.py");
        fs::write(&script, "print('hi')\n").unwrap();
        match classify_script(&base_dir, &script, &opts) {
            Some(ScriptRoute::Interpreter(cmd)) => assert_eq!(cmd, "python3"),
            other => panic!("expected Interpreter route, got {other:?}"),
        }
        fs::remove_dir_all(&dir).ok();
    }

    impl std::fmt::Debug for ScriptRoute {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ScriptRoute::ExecDirect => write!(f, "ExecDirect"),
                ScriptRoute::Interpreter(c) => write!(f, "Interpreter({c})"),
            }
        }
    }

    #[test]
    fn classify_script_disabled_entry_serves_as_static() {
        let dir = unique_dir("classify-disabled");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let mut opts = test_opts(base_dir.clone());
        opts.script_handlers.insert("pl".to_string(), None);
        let script = base_dir.join("legacy.pl");
        fs::write(&script, "print \"hi\";\n").unwrap();
        assert!(classify_script(&base_dir, &script, &opts).is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn classify_script_unrecognized_extension_serves_as_static() {
        let dir = unique_dir("classify-static");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let opts = test_opts(base_dir.clone());
        let file = base_dir.join("plain.txt");
        fs::write(&file, "hi").unwrap();
        assert!(classify_script(&base_dir, &file, &opts).is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn find_interpreter_resolves_a_known_path_binary() {
        assert!(find_interpreter("sh").is_some());
    }

    #[test]
    fn find_interpreter_returns_none_for_unknown_binary() {
        assert!(find_interpreter("cashttpd-definitely-not-a-real-binary").is_none());
    }

    #[test]
    fn cgi_bin_script_executes_and_returns_its_output() {
        let dir = unique_dir("cgi-bin-exec");
        fs::create_dir_all(dir.join("cgi-bin")).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let script = base_dir.join("cgi-bin").join("hello.cgi");
        fs::write(
            &script,
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nhello from cgi-bin, method=%s\\n' \"$REQUEST_METHOD\"\n",
        )
        .unwrap();
        let mut perms = fs::metadata(&script).unwrap().permissions();
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o755);
        }
        fs::set_permissions(&script, perms).unwrap();

        let response = request_over_loopback(&base_dir, "GET /cgi-bin/hello.cgi HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Type: text/plain"));
        assert!(response.ends_with("hello from cgi-bin, method=GET\n"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cgi_bin_non_executable_file_returns_500() {
        let dir = unique_dir("cgi-bin-noexec");
        fs::create_dir_all(dir.join("cgi-bin")).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let script = base_dir.join("cgi-bin").join("hello.cgi");
        fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();

        let response = request_over_loopback(&base_dir, "GET /cgi-bin/hello.cgi HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 500 Internal Server Error\r\n"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn interpreter_dispatch_runs_script_and_streams_post_body() {
        let dir = unique_dir("interp-python");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let script = base_dir.join("echo.py");
        fs::write(
            &script,
            "import sys\n\
             body = sys.stdin.read()\n\
             sys.stdout.write('Content-Type: text/plain\\r\\n\\r\\n')\n\
             sys.stdout.write('got:' + body)\n",
        )
        .unwrap();

        let opts = {
            let mut o = test_opts(base_dir.clone());
            o.script_handlers
                .insert("py".to_string(), Some("python3".to_string()));
            o
        };

        let payload = b"ping";
        let request_line = format!(
            "POST /echo.py HTTP/1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        let response = request_over_loopback_bytes(opts, request_line.as_bytes(), payload);

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("got:ping"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_interpreter_returns_503() {
        let dir = unique_dir("interp-missing");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let script = base_dir.join("thing.zz");
        fs::write(&script, "irrelevant").unwrap();
        let mut opts = test_opts(base_dir.clone());
        opts.script_handlers.insert(
            "zz".to_string(),
            Some("cashttpd-definitely-not-a-real-binary".to_string()),
        );

        let response = request_over_loopback_opts(opts, "GET /thing.zz HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(response.contains("cashttpd-definitely-not-a-real-binary is not installed"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn chunked_request_body_decodes_split_chunks() {
        let dir = unique_dir("chunked-body");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let script = base_dir.join("echo.py");
        fs::write(
            &script,
            "import sys\n\
             body = sys.stdin.read()\n\
             sys.stdout.write('Content-Type: text/plain\\r\\n\\r\\n')\n\
             sys.stdout.write('got:' + body)\n",
        )
        .unwrap();

        let opts = {
            let mut o = test_opts(base_dir.clone());
            o.script_handlers
                .insert("py".to_string(), Some("python3".to_string()));
            o
        };

        let request_line =
            "POST /echo.py HTTP/1.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        // Body "pingpongfin" split across three chunks.
        let chunked_body = b"4\r\nping\r\n4\r\npong\r\n3\r\nfin\r\n0\r\n\r\n";
        let response = request_over_loopback_bytes(opts, request_line.as_bytes(), chunked_body);

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("got:pingpongfin"));

        fs::remove_dir_all(&dir).ok();
    }

    /// Malformed chunk framing is rejected as a client error rather than
    /// being partially decoded — `hyper` fails the body stream, and the
    /// request never reaches a handler.
    #[test]
    fn malformed_chunked_body_is_rejected_as_bad_request() {
        let dir = unique_dir("chunked-malformed");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let request_line =
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        let opts = test_opts(base_dir.clone());
        // "zz" is not valid hex, so the chunk-size line is malformed.
        let response =
            request_over_loopback_bytes(opts, request_line.as_bytes(), b"zz\r\nbogus\r\n0\r\n\r\n");

        assert!(
            response.is_empty() || response.starts_with("HTTP/1.1 400 "),
            "unexpected response: {response:?}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn script_with_extra_path_segments_gets_path_info() {
        let dir = unique_dir("path-info");
        fs::create_dir_all(dir.join("cgi-bin")).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let script = base_dir.join("cgi-bin").join("info.sh");
        fs::write(
            &script,
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\n'\nprintf 'PI=%s PT=%s' \"$PATH_INFO\" \"$PATH_TRANSLATED\"\n",
        )
        .unwrap();
        let mut perms = fs::metadata(&script).unwrap().permissions();
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o755);
        }
        fs::set_permissions(&script, perms).unwrap();

        let response =
            request_over_loopback(&base_dir, "GET /cgi-bin/info.sh/extra/path HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        let expected_translated = base_dir.join("extra/path");
        assert!(response.contains(&format!(
            "PI=/extra/path PT={}",
            expected_translated.display()
        )));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn script_with_no_extra_segments_gets_empty_path_info() {
        let dir = unique_dir("path-info-empty");
        fs::create_dir_all(dir.join("cgi-bin")).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let script = base_dir.join("cgi-bin").join("info.sh");
        fs::write(
            &script,
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\n'\nprintf 'PI=[%s] PT=[%s]' \"$PATH_INFO\" \"$PATH_TRANSLATED\"\n",
        )
        .unwrap();
        let mut perms = fs::metadata(&script).unwrap().permissions();
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o755);
        }
        fs::set_permissions(&script, perms).unwrap();

        let response = request_over_loopback(&base_dir, "GET /cgi-bin/info.sh HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("PI=[] PT=[]"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nonexistent_path_with_no_script_ancestor_still_404s() {
        let dir = unique_dir("path-info-404");
        fs::create_dir_all(dir.join("cgi-bin")).unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(
            &base_dir,
            "GET /cgi-bin/does-not-exist.sh/extra HTTP/1.1\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));

        fs::remove_dir_all(&dir).ok();
    }

    // --- Live config-file reload (IDEA.md "Configuration file" → "Live
    // reload") ---

    #[test]
    fn reload_watch_changed_detects_stored_mtime_mismatch() {
        let dir = unique_dir("reload-watch");
        fs::create_dir_all(&dir).unwrap();
        let global = dir.join("config.yaml");
        let project = dir.join("project.yaml");
        fs::write(&global, "debug: false\n").unwrap();
        fs::write(&project, "debug: false\n").unwrap();

        let mut watch = ReloadWatch::new(global.clone(), project.clone());
        assert!(
            !watch.changed(),
            "no change since ReloadWatch::new already captured the current mtimes"
        );

        // Simulate a prior poll that saw an older project-file mtime than
        // the one actually on disk right now — exercises the comparison
        // logic directly, without a real sleep-then-rewrite to force a
        // coarse filesystem's mtime clock forward.
        watch.project_mtime = watch.project_mtime.map(|t| t - Duration::from_secs(5));
        assert!(watch.changed());
        assert!(
            !watch.changed(),
            "second check after re-syncing reports no further change"
        );

        // A watched file disappearing also counts as a change (Some ->
        // None), and reappearing counts again (None -> Some).
        fs::remove_file(&project).unwrap();
        assert!(watch.changed());
        assert!(!watch.changed());
        fs::write(&project, "debug: true\n").unwrap();
        assert!(watch.changed());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_needs_listener_rebind_detects_listen_port_tls_and_fqdn_changes() {
        let base = test_opts(PathBuf::from("."));
        assert!(!config_needs_listener_rebind(&base, &base));

        let mut port_changed = base.clone();
        port_changed.port = base.port.wrapping_add(1);
        assert!(config_needs_listener_rebind(&base, &port_changed));

        let mut listen_changed = base.clone();
        listen_changed.listen = "0.0.0.0".to_string();
        assert!(config_needs_listener_rebind(&base, &listen_changed));

        let mut tls_flipped = base.clone();
        tls_flipped.tls_enabled = true;
        assert!(config_needs_listener_rebind(&base, &tls_flipped));

        // fqdn changing while TLS stays disabled is not a rebind trigger —
        // nothing about the plain-HTTP listener depends on it.
        let mut fqdn_changed_no_tls = base.clone();
        fqdn_changed_no_tls.fqdn = Some("new.test".to_string());
        assert!(!config_needs_listener_rebind(&base, &fqdn_changed_no_tls));

        // fqdn changing while TLS is (or becomes) enabled does need a
        // rebind — the resolved certificate depends on it.
        let mut base_tls = base.clone();
        base_tls.tls_enabled = true;
        base_tls.fqdn = Some("old.test".to_string());
        let mut new_fqdn_tls = base_tls.clone();
        new_fqdn_tls.fqdn = Some("new.test".to_string());
        assert!(config_needs_listener_rebind(&base_tls, &new_fqdn_tls));
    }

    #[test]
    fn config_needs_proxy_restart_detects_proxy_field_changes() {
        let base = test_opts(PathBuf::from("."));
        assert!(!config_needs_proxy_restart(&base, &base));

        let mut other = base.clone();
        other.proxy.upstream = Some("http://127.0.0.1:9999".to_string());
        assert!(config_needs_proxy_restart(&base, &other));
        assert!(!config_needs_listener_rebind(&base, &other));
    }

    #[test]
    fn config_needs_logger_reopen_detects_log_dir_and_rotate_keep_changes() {
        let base = test_opts(PathBuf::from("."));
        assert!(!config_needs_logger_reopen(&base, &base));

        let mut dir_changed = base.clone();
        dir_changed.log_dir = std::env::temp_dir().join("cashttpd-reload-elsewhere");
        assert!(config_needs_logger_reopen(&base, &dir_changed));

        let mut rotate_changed = base.clone();
        rotate_changed.logging_access_rotate = "weekly".to_string();
        assert!(config_needs_logger_reopen(&base, &rotate_changed));

        let mut keep_changed = base.clone();
        keep_changed.logging_error_keep = "7d".to_string();
        assert!(config_needs_logger_reopen(&base, &keep_changed));
    }

    #[test]
    fn hot_appliable_directory_listing_change_needs_no_rebind_proxy_restart_or_logger_reopen() {
        let base = test_opts(PathBuf::from("."));
        let mut reloaded = base.clone();
        reloaded.directory_listing = !base.directory_listing;
        reloaded.debug = !base.debug;

        assert!(!config_needs_listener_rebind(&base, &reloaded));
        assert!(!config_needs_proxy_restart(&base, &reloaded));
        assert!(!config_needs_logger_reopen(&base, &reloaded));
    }

    #[test]
    fn hot_appliable_directory_listing_change_is_reflected_in_a_subsequent_request() {
        let dir = unique_dir("reload-hot-apply");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        fs::write(base_dir.join("secret.txt"), b"shh").unwrap();

        let mut opts = test_opts(base_dir.clone());
        opts.directory_listing = false;
        let before = request_over_loopback_opts(opts.clone(), "GET / HTTP/1.1\r\n");
        assert!(!before.contains("secret.txt"));

        let mut reloaded = opts.clone();
        reloaded.directory_listing = true;
        // Exactly the swap `apply_reload` performs for a change like this:
        // no listener rebind, proxy restart, or logger reopen needed.
        assert!(!config_needs_listener_rebind(&opts, &reloaded));
        assert!(!config_needs_proxy_restart(&opts, &reloaded));
        assert!(!config_needs_logger_reopen(&opts, &reloaded));

        let after = request_over_loopback_opts(reloaded, "GET / HTTP/1.1\r\n");
        assert!(after.contains("secret.txt"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_reload_rejects_conflicting_bind_and_keeps_serving_old_listener() {
        let dir = unique_dir("reload-conflict-base");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();
        let config_home = unique_dir("reload-conflict-config-home");
        std::env::set_var("XDG_CONFIG_HOME", &config_home);

        let cli = crate::configs::CliOverrides {
            base_dir: Some(base_dir.clone()),
            ..Default::default()
        };
        let opts = crate::configs::load(&cli, true).unwrap();

        let mut listener = TcpListener::bind(format_bind_addr(&opts)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let original_addr = listener.local_addr().unwrap();

        // Occupy a distinct free port and point the per-project config at
        // it — the reload's rebind attempt must fail against it.
        let blocker = TcpListener::bind("127.0.0.1:0").unwrap();
        let blocked_port = blocker.local_addr().unwrap().port();
        fs::write(
            &opts.project_config_path,
            format!("listen: \"127.0.0.1\"\nport: {blocked_port}\n"),
        )
        .unwrap();

        let logger = Arc::new(Logger::open(&std::env::temp_dir(), "reload-conflict", true));
        let runtime = Mutex::new(Arc::new(RuntimeState {
            opts: Arc::new(opts.clone()),
            tls_config: None,
            proxy_target: None,
            logger: logger.clone(),
        }));
        let shutdown = signal::ShutdownState::new_for_test();
        let stats = info::Stats::new("test");
        let mut proxy_child: Option<std::process::Child> = None;

        apply_reload(
            &cli,
            &runtime,
            &mut listener,
            &base_dir,
            true,
            &mut proxy_child,
            &shutdown,
            &stats,
        );

        // The listener must still be the original one (rebind rejected) —
        // a client can still connect to it, proving the server kept
        // running rather than panicking/exiting.
        assert_eq!(listener.local_addr().unwrap(), original_addr);
        TcpStream::connect(original_addr).unwrap();

        // The running config's port must remain the old one.
        let snapshot = Arc::clone(&runtime.lock().unwrap());
        assert_eq!(snapshot.opts.port, opts.port);

        // The failure is recorded as a dashboard issue, not silently
        // dropped.
        let dashboard = info::render_dashboard(&stats, &snapshot.opts, None);
        assert!(dashboard.contains("config reload issue"));

        drop(blocker);
        std::env::remove_var("XDG_CONFIG_HOME");
        fs::remove_dir_all(&dir).ok();
        fs::remove_dir_all(&config_home).ok();
    }

    // NOTE: a dedicated "base_dir change via the project config file is
    // ignored and warned about" test was attempted here but dropped: the
    // project config's own `base_dir` key only overrides anything when the
    // *original* `CliOverrides.base_dir` is `None` and `CASHTTPD_BASE_DIR`
    // is unset (config/mod.rs `load`'s documented precedence), which in
    // turn means the very first `configs::load` call also can't be pointed
    // at an isolated per-test directory via `cli`/the env var — it would
    // have to fall back to `base_dir = "."`, i.e. the real process cwd,
    // shared and racy across every test in this binary. The `base_dir`
    // revert branch itself (just above, in `apply_reload`) is a plain
    // three-line "force the field back to `current`'s value and push a
    // warning" — the same pattern this module's listener-rebind-failure
    // branch uses, and that path *is* covered end-to-end by
    // `apply_reload_rejects_conflicting_bind_and_keeps_serving_old_listener`
    // above.
}
