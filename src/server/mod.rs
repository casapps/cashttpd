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
//! Still open (tracked in TODO.AI.md): chunked *request* body decoding,
//! CGI/multi-language script execution, `.htaccess`/`.htpasswd`, TLS,
//! framework dev-server proxying, the `/server-info` dashboard, and
//! scheduled log rotation/retention (files are appended to unconditionally;
//! time/size-based rollover is not yet implemented).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::support::signal;

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
    let host = if opts.listen.contains(':') && !opts.listen.starts_with('[') {
        format!("[{}]", opts.listen)
    } else {
        opts.listen.clone()
    };
    let bind_addr = format!("{host}:{}", opts.port);

    let listener = TcpListener::bind(&bind_addr)?;
    listener.set_nonblocking(true)?;

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
    let logger = Arc::new(Logger::open(&opts.log_dir, &name, quiet));

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

    while !shutdown.is_shutdown_requested() {
        match listener.accept() {
            Ok((stream, addr)) => {
                let base_dir = Arc::clone(&base_dir);
                let request_count = Arc::clone(&request_count);
                let opts = Arc::clone(&opts);
                let logger = Arc::clone(&logger);
                std::thread::spawn(move || {
                    if let Err(err) = serve_connection(
                        stream,
                        &base_dir,
                        &opts,
                        &logger,
                        &addr.to_string(),
                        &request_count,
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
fn serve_connection(
    stream: TcpStream,
    base_dir: &Path,
    opts: &ServeOptions,
    logger: &Logger,
    client: &str,
    request_count: &AtomicU64,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

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

        let outcome = handle_request(&mut writer, base_dir, opts, &request, keep_alive);
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

fn handle_request(
    stream: &mut TcpStream,
    base_dir: &Path,
    opts: &ServeOptions,
    request: &Request,
    keep_alive: bool,
) -> std::io::Result<(u16, u64)> {
    let head_only = request.method == "HEAD";
    if request.method != "GET" && request.method != "HEAD" {
        return respond_error(stream, 405, request, opts, keep_alive);
    }

    let raw_path = request.path.split('?').next().unwrap_or("/");
    let decoded = percent_decode(raw_path);

    // `.htaccess`/`.htpasswd` are never servable as static content, at any
    // depth — non-negotiable trust boundary (IDEA.md ".htaccess"/
    // ".htpasswd" compatibility").
    if decoded.split('/').any(|seg| {
        seg == ".htaccess" || seg == ".htpasswd" || (seg.starts_with(".ht") && seg.len() > 3)
    }) {
        return respond_error(stream, 403, request, opts, keep_alive);
    }

    let requested = decoded.trim_start_matches('/');
    let candidate = if requested.is_empty() {
        base_dir.to_path_buf()
    } else {
        base_dir.join(requested)
    };

    let resolved = match candidate.canonicalize() {
        Ok(p) if p == base_dir || p.starts_with(base_dir) => p,
        _ => return respond_error(stream, 404, request, opts, keep_alive),
    };

    if resolved.is_dir() {
        for index in ["index.html", "index.htm"] {
            let candidate_index = resolved.join(index);
            if candidate_index.is_file() {
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
        if opts.directory_listing {
            return serve_directory_listing(
                stream, base_dir, &resolved, raw_path, head_only, keep_alive,
            );
        }
        return respond_error(stream, 403, request, opts, keep_alive);
    }

    serve_file(stream, &resolved, request, opts, head_only, keep_alive)
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
    stream: &mut TcpStream,
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
    stream: &mut TcpStream,
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
    let reason = reason_phrase(status);
    let detail = if debug {
        "<p class=\"detail\">Debug mode is on: no script/CGI execution has run yet for this \
         request, so there is no interpreter trace to show for this error.</p>"
            .to_string()
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
         .detail{{color:#fbbf24}}</style></head><body><div class=\"card\">\
         <h1>{status}</h1><p class=\"reason\">{reason}</p>\
         <p><code>{method} {path}</code></p>{detail}</div></body></html>",
        method = html_escape(&request.method),
        path = html_escape(&request.path),
    )
}

fn respond_error(
    stream: &mut TcpStream,
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
    stream: &mut TcpStream,
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

/// Unconditional access/error file logging (IDEA.md "Logging") — Apache
/// combined access format and Apache-style error format, written under
/// `{log_dir}/{derived_name}_{access,error}.log`. Scheduled rotation/
/// retention is not yet implemented (see module doc comment).
struct Logger {
    access: std::sync::Mutex<Option<std::fs::File>>,
    error: std::sync::Mutex<Option<std::fs::File>>,
    quiet: bool,
}

impl Logger {
    fn open(log_dir: &Path, name: &str, quiet: bool) -> Self {
        let access = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join(format!("{name}_access.log")))
            .ok();
        let error = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join(format!("{name}_error.log")))
            .ok();
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
            if let Some(f) = guard.as_mut() {
                let _ = f.write_all(line.as_bytes());
            }
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
            if let Some(f) = guard.as_mut() {
                let _ = f.write_all(line.as_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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

    fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (server, client)
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
            serve_connection(stream, &base_dir, &opts, &logger, "127.0.0.1:1", &count).unwrap();
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
}
