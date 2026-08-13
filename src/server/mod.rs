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
//! Apache-compatible per-directory configuration (`server::htaccess`) —
//! recursive discovery/cascade merge, `AuthType Basic` + bcrypt/apr1/
//! `{SHA}` `.htpasswd` authentication, `Require`/legacy `Order`/`Allow`/
//! `Deny` authorization, `ErrorDocument`, `DirectoryIndex`, `Options
//! Indexes`/`FollowSymLinks`, and `RewriteEngine`/`RewriteRule`/`Redirect`/
//! `RedirectMatch`, applied per the documented 6-phase per-request order.
//!
//! Also implements framework dev-server proxying (`server::proxy`, IDEA.md
//! "Framework dev-server proxying"): auto-detected or explicitly configured
//! requests under a `path_prefix` are relayed to a spawned dev-server child
//! process, streamed both ways, with WebSocket/`Upgrade` support.
//!
//! Still open (tracked in TODO.AI.md): chunked *request* body decoding
//! (`Content-Length` only), the `/server-info` dashboard, and live config
//! reload.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::support::signal;

mod htaccess;
mod proxy;
mod tls;

use tls::Conn;

/// Effective runtime configuration for `serve` — the fully layered result
/// of IDEA.md's "CLI flag > env var > per-project config > global config >
/// built-in default" precedence (see `crate::config::load`).
pub type ServeOptions = crate::config::Resolved;

/// Parses the `serve` subcommand's CLI flags and layers them over
/// environment variables and config-file settings via `crate::config::load`
/// (IDEA.md "Configuration file", "CLI flags (full reference)").
pub fn parse_serve_options(args: &[String]) -> ServeOptions {
    let overrides = parse_cli_overrides(args);
    crate::config::load(&overrides, true).unwrap_or_else(|err| {
        eprintln!("cashttpd: warning: config load failed ({err}); using built-in defaults");
        crate::config::load(&crate::config::CliOverrides::default(), false)
            .unwrap_or_else(|_| fallback_defaults())
    })
}

fn fallback_defaults() -> ServeOptions {
    crate::config::Resolved {
        base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        listen: "::1".to_string(),
        port: 8080,
        log_dir: crate::platform::paths::log_dir(),
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
        project_config_path: PathBuf::new(),
    }
}

/// Parses `--listen`, `--port`, `--dir`, `--fqdn`, `--log`, `--config`,
/// `--debug` into a `CliOverrides` (IDEA.md "CLI flags (full reference)").
/// `--daemon`/`--quiet`/`--config-test` are invocation-shape flags handled
/// by `crate::ui::cli`, not persisted settings — they are not parsed here.
pub fn parse_cli_overrides(args: &[String]) -> crate::config::CliOverrides {
    let mut o = crate::config::CliOverrides::default();
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
pub fn run(opts: ServeOptions, quiet: bool) -> std::io::Result<()> {
    // IDEA.md "TLS certificate resolution": `--fqdn` is required whenever
    // `tls.enabled: true` — fail fast, non-zero exit, no certless/
    // hostnameless HTTPS mode.
    if opts.tls_enabled && opts.fqdn.as_deref().unwrap_or("").is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tls.enabled is true but no --fqdn/fqdn was provided (required whenever TLS is on)",
        ));
    }

    let host = if opts.listen.contains(':') && !opts.listen.starts_with('[') {
        format!("[{}]", opts.listen)
    } else {
        opts.listen.clone()
    };
    let bind_addr = format!("{host}:{}", opts.port);

    let listener = TcpListener::bind(&bind_addr)?;
    listener.set_nonblocking(true)?;

    // TLS certificate resolution can need port 80 (ACME HTTP-01) — resolve
    // it before dropping privileges, not after.
    let tls_config = if opts.tls_enabled {
        let fqdn = opts.fqdn.clone().unwrap_or_default();
        Some(tls::build_server_config(
            &fqdn,
            &opts.listen,
            &opts.base_dir,
            |msg| eprintln!("cashttpd: warning: {msg}"),
        )?)
    } else {
        None
    };

    // Privileged ports (<1024): bind first, then drop privileges — the
    // daemon never continues running as root after binding.
    crate::platform::drop_privileges_if_root()?;

    let shutdown = signal::install_handlers()?;

    let base_dir = Arc::new(
        opts.base_dir
            .canonicalize()
            .unwrap_or_else(|_| opts.base_dir.clone()),
    );
    std::fs::create_dir_all(&opts.log_dir).ok();
    let name = crate::config::derived_name(&base_dir);
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
        "cashttpd {} listening on {bind_addr} (base dir: {}, {})",
        crate::support::version::VERSION,
        base_dir.display(),
        if opts.tls_enabled { "https" } else { "http" }
    );
    if crate::support::color::color_enabled(None) {
        let light_bg = std::env::var("COLORFGBG")
            .ok()
            .and_then(|v| v.rsplit(';').next().map(str::to_string))
            .and_then(|bg| bg.parse::<u8>().ok())
            .is_some_and(|bg| bg >= 8);
        let palette = if light_bg {
            crate::support::color::terminal_palette_light()
        } else {
            crate::support::color::terminal_palette_dark()
        };
        println!("\x1b[38;5;{}m{banner}\x1b[0m", palette.primary);
    } else {
        println!("{banner}");
    }

    let opts = Arc::new(opts);
    let request_count = Arc::new(AtomicU64::new(0));
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

    while !shutdown.is_shutdown_requested() {
        match listener.accept() {
            Ok((stream, addr)) => {
                let base_dir = Arc::clone(&base_dir);
                let request_count = Arc::clone(&request_count);
                let opts = Arc::clone(&opts);
                let logger = Arc::clone(&logger);
                let tls_config = tls_config.clone();
                let proxy_target = proxy_target.clone();
                std::thread::spawn(move || {
                    let conn = match tls_config {
                        Some(config) => match rustls::ServerConnection::new(config) {
                            Ok(session) => {
                                Conn::Tls(Box::new(rustls::StreamOwned::new(session, stream)))
                            }
                            Err(err) => {
                                logger
                                    .error(&format!("TLS session setup failed for {addr}: {err}"));
                                return;
                            }
                        },
                        None => Conn::Plain(stream),
                    };
                    if let Err(err) = serve_connection(
                        conn,
                        &base_dir,
                        &opts,
                        &logger,
                        &addr.to_string(),
                        &request_count,
                        &proxy_target,
                    ) {
                        logger.error(&format!("connection error from {addr}: {err}"));
                    }
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => {
                logger.error(&format!("accept error: {err}"));
            }
        }
    }

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
        crate::support::format::duration(started_at.elapsed().as_secs()),
        crate::support::format::count(request_count.load(Ordering::Relaxed))
    );

    Ok(())
}

/// A parsed HTTP/1.x request line + headers (IDEA.md "Core behavior" /
/// AI.md PART 14 RFC 9110/9112 conformance).
struct Request {
    method: String,
    path: String,
    version: String,
    headers: HashMap<String, String>,
}

fn parse_request(reader: &mut impl BufRead) -> std::io::Result<Option<Request>> {
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(None);
    }
    let request_line = request_line.trim_end();
    if request_line.is_empty() {
        return Ok(None);
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    Ok(Some(Request {
        method,
        path,
        version,
        headers,
    }))
}

/// Serves every keep-alive request on one connection (RFC 9112 §9.3 —
/// HTTP/1.1 connections are persistent unless `Connection: close` is sent).
#[allow(clippy::too_many_arguments)]
fn serve_connection(
    conn: Conn,
    base_dir: &Path,
    opts: &ServeOptions,
    logger: &Logger,
    client: &str,
    request_count: &AtomicU64,
    proxy_target: &Option<Arc<proxy::ProxyTarget>>,
) -> std::io::Result<()> {
    conn.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(conn);

    loop {
        let request = match parse_request(&mut reader) {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(()),
            Err(_) => return Ok(()),
        };
        request_count.fetch_add(1, Ordering::Relaxed);

        let keep_alive = request
            .headers
            .get("connection")
            .map(|v| !v.eq_ignore_ascii_case("close"))
            .unwrap_or_else(|| request.version == "HTTP/1.1");

        // No artificial resource limits (IDEA.md "Security" — a script/CGI
        // request body is read in full per its own `Content-Length`, never
        // capped or streamed with a server-imposed ceiling).
        let content_length: usize = request
            .headers
            .get("content-length")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; content_length];
        if content_length > 0 && reader.read_exact(&mut body).is_err() {
            return Ok(());
        }

        let outcome = handle_request(
            reader.get_mut(),
            base_dir,
            opts,
            &request,
            &body,
            client,
            keep_alive,
            proxy_target,
        );
        let (status, bytes) = match outcome {
            Ok(v) => v,
            Err(err) => {
                logger.error(&format!("{client} request error: {err}"));
                return Ok(());
            }
        };
        logger.access(
            client,
            &request.method,
            &request.path,
            &request.version,
            status,
            bytes,
            &request.headers,
        );

        if !keep_alive || status == 400 {
            return Ok(());
        }
    }
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
fn respond_with_error_document(
    stream: &mut Conn,
    status: u16,
    request: &Request,
    opts: &ServeOptions,
    keep_alive: bool,
    base_dir: &Path,
    rules: &htaccess::Rules,
) -> std::io::Result<(u16, u64)> {
    let head_only = request.method == "HEAD";
    if let Some(target) = rules.error_documents.get(&status) {
        if target.starts_with("http://") || target.starts_with("https://") {
            return write_response(
                stream,
                302,
                "Found",
                &[],
                true,
                keep_alive,
                &[("Location".to_string(), target.clone())],
            );
        }
        let rel = target.trim_start_matches('/');
        if let Ok(resolved) = base_dir.join(rel).canonicalize() {
            if (resolved == base_dir || resolved.starts_with(base_dir)) && resolved.is_file() {
                if let Ok(content) = std::fs::read(&resolved) {
                    let content_type = content_type_for(&resolved, opts);
                    return write_response(
                        stream,
                        status,
                        reason_phrase(status),
                        &content,
                        head_only,
                        keep_alive,
                        &[("Content-Type".to_string(), content_type)],
                    );
                }
            }
        }
    }
    respond_error(stream, status, request, opts, keep_alive)
}

#[allow(clippy::too_many_arguments)]
fn handle_request(
    stream: &mut Conn,
    base_dir: &Path,
    opts: &ServeOptions,
    request: &Request,
    body: &[u8],
    client: &str,
    keep_alive: bool,
    proxy_target: &Option<Arc<proxy::ProxyTarget>>,
) -> std::io::Result<(u16, u64)> {
    let head_only = request.method == "HEAD";
    let known_method = matches!(
        request.method.as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS"
    );
    if !known_method {
        return respond_error(stream, 405, request, opts, keep_alive);
    }

    let raw_path = request.path.split('?').next().unwrap_or("/");
    let query = request.path.split_once('?').map(|x| x.1).unwrap_or("");
    let mut decoded = percent_decode(raw_path);

    if is_ht_path(&decoded) {
        return respond_error(stream, 403, request, opts, keep_alive);
    }

    let remote_ip = client.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(client);

    // Framework dev-server proxying (IDEA.md "Framework dev-server
    // proxying") — a request under `path_prefix` is relayed to the
    // upstream dev server entirely in place of cashttpd's own static/CGI/
    // `.htaccess` pipeline below; everything else still goes through it.
    if let Some(target) = proxy_target {
        if decoded.starts_with(target.path_prefix.as_str()) {
            return proxy::proxy_request(stream, target, request, body, client, opts, keep_alive);
        }
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
            return write_response(
                stream,
                status,
                reason_phrase(status),
                &[],
                true,
                keep_alive,
                &[("Location".to_string(), target)],
            );
        }
        htaccess::RewriteOutcome::Rewritten(new_path) => {
            if is_ht_path(&new_path) {
                return respond_error(stream, 403, request, opts, keep_alive);
            }
            decoded = new_path;
            rules = htaccess_rules_for(base_dir, &decoded);
        }
        htaccess::RewriteOutcome::Unchanged => {}
    }

    // Phase 2: legacy `Order`/`Allow`/`Deny` access control, against the
    // possibly-rewritten target.
    if !htaccess::access_allowed(&rules, remote_ip) {
        return respond_with_error_document(
            stream, 403, request, opts, keep_alive, base_dir, &rules,
        );
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
            return respond_with_error_document(
                stream, 500, request, opts, keep_alive, base_dir, &rules,
            );
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
                return write_response(
                    stream,
                    401,
                    reason_phrase(401),
                    auth_body.as_bytes(),
                    head_only,
                    keep_alive,
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
                    return respond_with_error_document(
                        stream, 403, request, opts, keep_alive, base_dir, &rules,
                    );
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
        return respond_with_error_document(
            stream, 403, request, opts, keep_alive, base_dir, &rules,
        );
    }

    let resolved = match candidate.canonicalize() {
        Ok(p) if p == base_dir || p.starts_with(base_dir) => p,
        _ => {
            return respond_with_error_document(
                stream, 404, request, opts, keep_alive, base_dir, &rules,
            );
        }
    };

    if resolved.is_dir() {
        if request.method != "GET" && request.method != "HEAD" {
            return respond_with_error_document(
                stream, 405, request, opts, keep_alive, base_dir, &rules,
            );
        }
        let default_index = ["index.html".to_string(), "index.htm".to_string()];
        let index_list = rules.directory_index.as_deref().unwrap_or(&default_index);
        for index in index_list {
            let candidate_index = resolved.join(index);
            if candidate_index.is_file() {
                if let Some(route) = classify_script(base_dir, &candidate_index, opts) {
                    return dispatch_script(
                        stream,
                        base_dir,
                        &candidate_index,
                        &route,
                        request,
                        opts,
                        body,
                        client,
                        head_only,
                        keep_alive,
                    );
                }
                return serve_file(
                    stream,
                    &candidate_index,
                    request,
                    opts,
                    head_only,
                    keep_alive,
                );
            }
        }
        // `Options Indexes`/`-Indexes` merges with/overrides the config-file
        // `directory_listing` setting for this subtree (IDEA.md "Options").
        if rules.indexes.unwrap_or(opts.directory_listing) {
            return serve_directory_listing(
                stream, base_dir, &resolved, raw_path, head_only, keep_alive,
            );
        }
        return respond_with_error_document(
            stream, 403, request, opts, keep_alive, base_dir, &rules,
        );
    }

    if let Some(route) = classify_script(base_dir, &resolved, opts) {
        return dispatch_script(
            stream, base_dir, &resolved, &route, request, opts, body, client, head_only, keep_alive,
        );
    }

    if request.method != "GET" && request.method != "HEAD" {
        return respond_with_error_document(
            stream, 405, request, opts, keep_alive, base_dir, &rules,
        );
    }
    serve_file(stream, &resolved, request, opts, head_only, keep_alive)
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
/// `config::builtin_script_handlers`). Returns `None` for plain static
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
/// only used when the script produced no usable output at all).
fn respond_script_failure(
    stream: &mut Conn,
    request: &Request,
    opts: &ServeOptions,
    keep_alive: bool,
    detail: &str,
) -> std::io::Result<(u16, u64)> {
    let body = error_page_with_trace(500, request, opts.debug, Some(detail));
    let head_only = request.method == "HEAD";
    write_response(
        stream,
        500,
        reason_phrase(500),
        body.as_bytes(),
        head_only,
        keep_alive,
        &[(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
    )
}

/// Executes a CGI/script request end-to-end (IDEA.md "Multi-language script
/// execution" → "CGI 1.1 protocol semantics"): resolves the program to run
/// (per `route`), builds the full CGI 1.1 environment, streams the request
/// body to the child's stdin, captures stdout/stderr, and translates the
/// script's CGI-style output into an HTTP response. No execution timeout —
/// "No artificial resource limits" (IDEA.md "Security").
#[allow(clippy::too_many_arguments)]
fn dispatch_script(
    stream: &mut Conn,
    base_dir: &Path,
    script_path: &Path,
    route: &ScriptRoute,
    request: &Request,
    opts: &ServeOptions,
    body: &[u8],
    client: &str,
    head_only: bool,
    keep_alive: bool,
) -> std::io::Result<(u16, u64)> {
    use std::process::{Command, Stdio};

    let (program, fixed_args) = match route {
        ScriptRoute::ExecDirect => {
            if !is_executable_file(script_path) {
                return respond_script_failure(
                    stream,
                    request,
                    opts,
                    keep_alive,
                    &format!(
                        "{} is not marked executable (cgi-bin/exec-directly scripts require \
                         their own executable bit and shebang/native binary)",
                        script_path.display()
                    ),
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
                        stream,
                        request,
                        opts,
                        keep_alive,
                        "script_handlers entry resolved to an empty command",
                    );
                }
            };
            let fixed_args: Vec<String> = parts.map(str::to_string).collect();
            match find_interpreter(bin) {
                Some(p) => (p, fixed_args),
                None => {
                    let msg = format!("{bin} is not installed");
                    return write_response(
                        stream,
                        503,
                        "Service Unavailable",
                        msg.as_bytes(),
                        head_only,
                        keep_alive,
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
    cmd.env("PATH_INFO", "");
    cmd.env("PATH_TRANSLATED", "");
    cmd.env(
        "SERVER_NAME",
        opts.fqdn.clone().unwrap_or_else(|| "localhost".to_string()),
    );
    cmd.env("SERVER_PORT", opts.port.to_string());
    cmd.env("SERVER_PROTOCOL", &request.version);
    cmd.env(
        "SERVER_SOFTWARE",
        format!("cashttpd/{}", crate::support::version::VERSION),
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

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) => {
            return respond_script_failure(
                stream,
                request,
                opts,
                keep_alive,
                &format!("failed to start {}: {err}", program.display()),
            );
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        if !body.is_empty() {
            let _ = stdin.write_all(body);
        }
        drop(stdin);
    }

    let mut stdout_buf = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_end(&mut stdout_buf);
    }
    let mut stderr_buf = Vec::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_end(&mut stderr_buf);
    }
    let wait_result = child.wait();

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
        return respond_script_failure(stream, request, opts, keep_alive, &detail);
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

    write_response(
        stream,
        resp_status,
        &resp_reason,
        cgi_body,
        head_only,
        keep_alive,
        &extra,
    )
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

#[allow(clippy::too_many_arguments)]
fn serve_file(
    stream: &mut Conn,
    path: &Path,
    request: &Request,
    opts: &ServeOptions,
    head_only: bool,
    keep_alive: bool,
) -> std::io::Result<(u16, u64)> {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return respond_error(stream, 404, request, opts, keep_alive),
    };
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let len = metadata.len();
    let etag = etag_for(len, modified);
    let last_modified = http_date(modified);

    if let Some(inm) = request.headers.get("if-none-match") {
        if inm == &etag {
            return write_response(stream, 304, "Not Modified", &[], true, keep_alive, &[]);
        }
    } else if let Some(ims) = request.headers.get("if-modified-since") {
        if ims == &last_modified {
            return write_response(stream, 304, "Not Modified", &[], true, keep_alive, &[]);
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
            let mut file = std::fs::File::open(path)?;
            file.seek_to(start)?;
            let take = (end - start + 1) as usize;
            let mut buf = vec![0u8; take];
            file.read_exact(&mut buf)?;
            let mut range_headers = extra;
            range_headers.push((
                "Content-Range".to_string(),
                format!("bytes {start}-{end}/{len}"),
            ));
            return write_response(
                stream,
                206,
                "Partial Content",
                &buf,
                head_only,
                keep_alive,
                &range_headers,
            );
        }
        return write_response(
            stream,
            416,
            "Range Not Satisfiable",
            &[],
            true,
            keep_alive,
            &[("Content-Range".to_string(), format!("bytes */{len}"))],
        );
    }

    let body = if head_only {
        Vec::new()
    } else {
        std::fs::read(path)?
    };
    write_response(stream, 200, "OK", &body, head_only, keep_alive, &extra)
}

trait SeekExt {
    fn seek_to(&mut self, pos: u64) -> std::io::Result<()>;
}

impl SeekExt for std::fs::File {
    fn seek_to(&mut self, pos: u64) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom};
        self.seek(SeekFrom::Start(pos))?;
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

fn serve_directory_listing(
    stream: &mut Conn,
    base_dir: &Path,
    dir: &Path,
    raw_path: &str,
    head_only: bool,
    keep_alive: bool,
) -> std::io::Result<(u16, u64)> {
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
            let size_label = size.map(crate::support::format::size).unwrap_or_default();
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
    write_response(
        stream,
        200,
        "OK",
        body.as_bytes(),
        head_only,
        keep_alive,
        &[(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
    )
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

fn respond_error(
    stream: &mut Conn,
    status: u16,
    request: &Request,
    opts: &ServeOptions,
    keep_alive: bool,
) -> std::io::Result<(u16, u64)> {
    let body = error_page(status, request, opts.debug);
    let head_only = request.method == "HEAD";
    write_response(
        stream,
        status,
        reason_phrase(status),
        body.as_bytes(),
        head_only,
        keep_alive,
        &[(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
    )
}

fn write_response(
    stream: &mut Conn,
    status: u16,
    reason: &str,
    body: &[u8],
    head_only: bool,
    keep_alive: bool,
    extra_headers: &[(String, String)],
) -> std::io::Result<(u16, u64)> {
    let mut header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: {}\r\n",
        body.len(),
        if keep_alive { "keep-alive" } else { "close" }
    );
    for (k, v) in extra_headers {
        header.push_str(&format!("{k}: {v}\r\n"));
    }
    header.push_str("\r\n");
    stream.write_all(header.as_bytes())?;
    if !head_only {
        stream.write_all(body)?;
    }
    stream.flush()?;
    Ok((status, body.len() as u64))
}

/// One log stream (access or error): its open file handle, path, and
/// rotation/retention state (IDEA.md "Log rotation and retention").
struct LogStream {
    path: PathBuf,
    file: Option<std::fs::File>,
    rotate: crate::support::rotation::RotatePolicy,
    keep: crate::support::rotation::KeepPolicy,
    period_start: u64,
}

impl LogStream {
    fn open(path: PathBuf, rotate_spec: &str, keep_spec: &str) -> Self {
        let rotate = crate::support::rotation::parse_rotate(rotate_spec);
        let keep = crate::support::rotation::parse_keep(keep_spec);
        // Retention is checked once at startup, to catch files that aged
        // out while the server wasn't running (IDEA.md "Retention is
        // checked at each rotation ... and once at server startup").
        crate::support::rotation::apply_retention(&path, keep).ok();
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
        if !crate::support::rotation::should_rotate(&self.rotate, current_len, self.period_start) {
            return;
        }
        self.file = None;
        if crate::support::rotation::rotate_file(&self.path, self.keep).is_ok() {
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
        crate::config::Resolved {
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
            project_config_path: PathBuf::new(),
        }
    }

    #[test]
    fn parse_cli_overrides_reads_all_flags() {
        let args = vec![
            "--listen".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            "9090".to_string(),
            "--dir".to_string(),
            "/tmp/somewhere".to_string(),
            "--fqdn".to_string(),
            "example.test".to_string(),
            "--log".to_string(),
            "/tmp/logs".to_string(),
            "--debug".to_string(),
        ];
        let o = parse_cli_overrides(&args);
        assert_eq!(o.listen.as_deref(), Some("127.0.0.1"));
        assert_eq!(o.port, Some(9090));
        assert_eq!(o.base_dir, Some(PathBuf::from("/tmp/somewhere")));
        assert_eq!(o.fqdn.as_deref(), Some("example.test"));
        assert_eq!(o.log_dir, Some(PathBuf::from("/tmp/logs")));
        assert_eq!(o.debug, Some(true));
    }

    #[test]
    fn parse_cli_overrides_defaults_when_no_flags() {
        let o = parse_cli_overrides(&[]);
        assert!(o.listen.is_none());
        assert!(o.port.is_none());
        assert!(o.base_dir.is_none());
    }

    fn loopback_pair() -> (Conn, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (Conn::Plain(server), client)
    }

    fn request_over_loopback(base_dir: &Path, request_line: &str) -> String {
        request_over_loopback_opts(test_opts(base_dir.to_path_buf()), request_line)
    }

    fn request_over_loopback_opts(opts: ServeOptions, request_line: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base_dir = opts.base_dir.clone();
        let logger = Arc::new(Logger::open(&std::env::temp_dir(), "test", true));
        let count = Arc::new(AtomicU64::new(0));
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(
                Conn::Plain(stream),
                &base_dir,
                &opts,
                &logger,
                "127.0.0.1:1",
                &count,
                &None,
            )
            .unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(request_line.as_bytes()).unwrap();
        client.write_all(b"Connection: close\r\n\r\n").unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).unwrap();
        handle.join().unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }

    #[test]
    fn write_response_full_body_includes_headers_and_content() {
        let (mut server, mut client) = loopback_pair();
        write_response(&mut server, 200, "OK", b"hello", false, false, &[]).unwrap();
        drop(server);
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with("hello"));
    }

    #[test]
    fn write_response_head_only_omits_body() {
        let (mut server, mut client) = loopback_pair();
        write_response(
            &mut server,
            404,
            "Not Found",
            b"Not Found",
            true,
            false,
            &[],
        )
        .unwrap();
        drop(server);
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn serves_existing_file_with_etag_and_content_type() {
        let dir = unique_dir("serve");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("hello.txt"), b"hi there").unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "GET /hello.txt HTTP/1.1\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("ETag:"));
        assert!(response.contains("Content-Type: text/plain"));
        assert!(response.ends_with("hi there"));

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
            .find(|l| l.starts_with("ETag:"))
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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let logger = Arc::new(Logger::open(&std::env::temp_dir(), "test", true));
        let count = Arc::new(AtomicU64::new(0));
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(
                Conn::Plain(stream),
                &base_dir,
                &opts,
                &logger,
                "127.0.0.1:1",
                &count,
                &None,
            )
            .unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(request_line.as_bytes()).unwrap();
        client.write_all(payload).unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).unwrap();
        handle.join().unwrap();
        let response = String::from_utf8_lossy(&buf).to_string();

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
}
