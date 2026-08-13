//! Framework dev-server proxying (IDEA.md "Framework dev-server proxying").
//!
//! `resolve_proxy_target` layers the resolved `proxy.*` config
//! (`crate::config::ProxyLayer`) over a built-in table of framework
//! profiles auto-detected from marker files in `base_dir` — any of
//! `enabled`/`command`/`upstream`/`path_prefix` explicitly set in config
//! overrides the corresponding auto-detected value independently; setting
//! `type` alone reuses that profile's other defaults; `command`+`upstream`
//! set with no `type` at all is itself sufficient (no built-in profile
//! required). `enabled: false` always disables proxying regardless of any
//! marker file present.
//!
//! `spawn_child` starts the framework's dev-server process once at `run()`
//! startup (never per-request); its PID is handed to
//! `crate::support::signal::ShutdownState::track_child_process` so it is
//! killed on every signal-driven exit path, including the "second signal
//! forces an immediate exit" escape hatch.
//!
//! `proxy_request` forwards a request whose (percent-decoded) path starts
//! with `path_prefix` to the upstream dev server: the request line/query
//! and every header are forwarded verbatim (`Host` unmodified), with
//! `X-Forwarded-For`/`X-Forwarded-Proto` appended to (never overwriting) any
//! value already present. The response is relayed to the client streamed
//! — status/headers/body unmodified — honoring the upstream's own framing
//! (`Content-Length`, `Transfer-Encoding: chunked`, or read-until-close).
//! A `Connection: Upgrade`/`Upgrade: websocket` request that receives a
//! `101 Switching Protocols` response is relayed via `relay_bidirectional`
//! (RFC 6455) after the handshake headers are forwarded. Until the upstream
//! accepts a TCP connection (bounded liveness probe — the one timeout
//! IDEA.md's "no artificial limits" policy explicitly carves out), requests
//! under `path_prefix` receive an embedded auto-refreshing "starting…" page
//! instead of a hard error.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::tls::Conn;
use super::{Request, ServeOptions};

/// One built-in framework profile: marker-file detection plus its default
/// spawn command / upstream address / path scope, all independently
/// overridable via `proxy.*` config (IDEA.md "Config override").
struct FrameworkProfile {
    name: &'static str,
    command: &'static str,
    upstream: &'static str,
    path_prefix: &'static str,
}

const PROFILES: &[FrameworkProfile] = &[
    FrameworkProfile {
        name: "vite",
        command: "npm run dev",
        upstream: "127.0.0.1:5173",
        path_prefix: "/",
    },
    FrameworkProfile {
        name: "bun",
        command: "bun run dev",
        upstream: "127.0.0.1:3000",
        path_prefix: "/",
    },
    FrameworkProfile {
        name: "deno",
        command: "deno task dev",
        upstream: "127.0.0.1:8000",
        path_prefix: "/",
    },
    FrameworkProfile {
        name: "node",
        command: "npm run dev",
        upstream: "127.0.0.1:3000",
        path_prefix: "/",
    },
    FrameworkProfile {
        name: "rails",
        command: "bundle exec rails server -b 127.0.0.1 -p 3000",
        upstream: "127.0.0.1:3000",
        path_prefix: "/",
    },
    FrameworkProfile {
        name: "django",
        command: "python3 manage.py runserver 127.0.0.1:8000",
        upstream: "127.0.0.1:8000",
        path_prefix: "/",
    },
    FrameworkProfile {
        name: "flask",
        command: "flask run --host 127.0.0.1 --port 5000",
        upstream: "127.0.0.1:5000",
        path_prefix: "/",
    },
    FrameworkProfile {
        name: "fastapi",
        command: "uvicorn main:app --host 127.0.0.1 --port 8000",
        upstream: "127.0.0.1:8000",
        path_prefix: "/",
    },
];

fn find_profile(name: &str) -> Option<&'static FrameworkProfile> {
    PROFILES.iter().find(|p| p.name.eq_ignore_ascii_case(name))
}

fn has_file(base_dir: &Path, rel: &str) -> bool {
    base_dir.join(rel).is_file()
}

fn package_json_mentions(base_dir: &Path, needle: &str) -> bool {
    std::fs::read_to_string(base_dir.join("package.json"))
        .map(|text| text.contains(&format!("\"{needle}\"")))
        .unwrap_or(false)
}

fn package_json_has_script(base_dir: &Path, script_names: &[&str]) -> bool {
    let Ok(text) = std::fs::read_to_string(base_dir.join("package.json")) else {
        return false;
    };
    script_names
        .iter()
        .any(|name| text.contains(&format!("\"{name}\"")))
}

fn python_deps_mention(base_dir: &Path, needle: &str) -> bool {
    for f in ["pyproject.toml", "requirements.txt"] {
        if let Ok(text) = std::fs::read_to_string(base_dir.join(f)) {
            if text.to_ascii_lowercase().contains(needle) {
                return true;
            }
        }
    }
    false
}

/// Auto-detects a framework profile from marker files in `base_dir`, most
/// specific first (a Vite config or a `vite` `package.json` dependency wins
/// over a generic Node project; a `bun.lockb` wins over plain `npm`).
fn detect(base_dir: &Path) -> Option<&'static FrameworkProfile> {
    if has_file(base_dir, "vite.config.js")
        || has_file(base_dir, "vite.config.ts")
        || has_file(base_dir, "vite.config.mjs")
        || has_file(base_dir, "vite.config.mts")
        || package_json_mentions(base_dir, "vite")
    {
        return find_profile("vite");
    }
    if has_file(base_dir, "bun.lockb") && has_file(base_dir, "package.json") {
        return find_profile("bun");
    }
    if has_file(base_dir, "deno.json") || has_file(base_dir, "deno.jsonc") {
        return find_profile("deno");
    }
    if has_file(base_dir, "package.json") && package_json_has_script(base_dir, &["dev", "start"]) {
        return find_profile("node");
    }
    if has_file(base_dir, "Gemfile") && has_file(base_dir, "config.ru") {
        return find_profile("rails");
    }
    if has_file(base_dir, "manage.py") {
        return find_profile("django");
    }
    if has_file(base_dir, "pyproject.toml") || has_file(base_dir, "requirements.txt") {
        if python_deps_mention(base_dir, "fastapi") {
            return find_profile("fastapi");
        }
        if python_deps_mention(base_dir, "flask") {
            return find_profile("flask");
        }
    }
    None
}

/// A fully resolved proxy target — config overrides already merged over
/// (or standing entirely in place of) a built-in framework profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTarget {
    pub kind: String,
    pub command: String,
    pub upstream: String,
    pub path_prefix: String,
}

/// Resolves the effective proxy target for `base_dir`, or `None` when
/// proxying is off (IDEA.md "Framework dev-server proxying" — "Config
/// override"). `enabled: false` always wins; otherwise a `type` override
/// selects a named built-in profile (falling back to detection when
/// omitted), and `command`/`upstream`/`path_prefix` each independently
/// override that profile's default. `command`+`upstream` set directly,
/// with no `type` and no detected profile, is itself sufficient.
pub fn resolve_proxy_target(
    base_dir: &Path,
    layer: &crate::config::ProxyLayer,
) -> Option<ProxyTarget> {
    if layer.enabled == Some(false) {
        return None;
    }

    let profile = match layer.kind.as_deref() {
        Some(k) => find_profile(k),
        None => detect(base_dir),
    };

    let kind = layer
        .kind
        .clone()
        .or_else(|| profile.map(|p| p.name.to_string()))
        .unwrap_or_else(|| "custom".to_string());

    let command = layer
        .command
        .clone()
        .or_else(|| profile.map(|p| p.command.to_string()));

    let upstream = layer
        .upstream
        .clone()
        .or_else(|| profile.map(|p| p.upstream.to_string()));

    let path_prefix = layer
        .path_prefix
        .clone()
        .or_else(|| profile.map(|p| p.path_prefix.to_string()))
        .unwrap_or_else(|| "/".to_string());

    let (command, upstream) = match (command, upstream) {
        (Some(c), Some(u)) => (c, u),
        _ => return None,
    };

    Some(ProxyTarget {
        kind,
        command,
        upstream,
        path_prefix,
    })
}

/// Spawns the framework's dev-server process (IDEA.md "Process/PID
/// management" — spawned once at `run()` startup, never per-request).
/// stdout/stderr are inherited so the dev server's own console output is
/// visible alongside cashttpd's; stdin is closed since nothing feeds it.
pub fn spawn_child(target: &ProxyTarget, base_dir: &Path) -> io::Result<Child> {
    let mut parts = target.command.split_whitespace();
    let program = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "proxy command is empty"))?;
    Command::new(program)
        .args(parts)
        .current_dir(base_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
}

/// Bounded liveness probe (the one timeout IDEA.md's "no artificial
/// resource limits" policy explicitly permits) — used only to decide
/// whether to relay a real request or serve the embedded "starting…" page.
pub fn is_upstream_ready(upstream: &str) -> bool {
    let Ok(mut addrs) = upstream.to_socket_addrs() else {
        return false;
    };
    let Some(addr) = addrs.next() else {
        return false;
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

/// Embedded auto-refreshing "framework is starting…" page, styled to match
/// the dark mobile-first theme of `error_page`/`error_page_with_trace`.
fn starting_page(request: &Request) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta http-equiv=\"refresh\" content=\"1\">\
         <title>Starting…</title>\
         <style>body{{font-family:system-ui,sans-serif;margin:0;padding:2rem 1.25rem;\
         background:#0f172a;color:#e2e8f0;min-height:100vh;box-sizing:border-box}}\
         .card{{max-width:32rem;margin:2rem auto;background:#1e293b;border-radius:.75rem;\
         padding:1.5rem;text-align:center}}h1{{font-size:1.5rem;margin:0 0 .5rem}}\
         .reason{{font-size:1rem;color:#94a3b8;margin:0 0 1rem}}\
         .spinner{{width:2rem;height:2rem;margin:0 auto 1rem;border:.25rem solid #334155;\
         border-top-color:#38bdf8;border-radius:50%;animation:spin 1s linear infinite}}\
         @keyframes spin{{to{{transform:rotate(360deg)}}}}\
         code{{background:#334155;padding:.15rem .4rem;border-radius:.25rem}}</style></head>\
         <body><div class=\"card\"><div class=\"spinner\"></div>\
         <h1>Framework is starting…</h1>\
         <p class=\"reason\">The dev server for this project is still coming up. This page \
         refreshes automatically.</p><p><code>{method} {path}</code></p></div></body></html>",
        method = super::html_escape(&request.method),
        path = super::html_escape(&request.path),
    )
}

/// Forwards `request`/`body` to `target.upstream` and relays the response
/// back to `stream`, streamed rather than buffered. See the module doc
/// comment for the exact request/response fidelity rules.
#[allow(clippy::too_many_arguments)]
pub fn proxy_request(
    stream: &mut Conn,
    target: &ProxyTarget,
    request: &Request,
    body: &[u8],
    client: &str,
    opts: &ServeOptions,
    keep_alive: bool,
) -> io::Result<(u16, u64)> {
    let head_only = request.method == "HEAD";

    if !is_upstream_ready(&target.upstream) {
        let page = starting_page(request);
        return super::write_response(
            stream,
            503,
            "Service Unavailable",
            page.as_bytes(),
            head_only,
            keep_alive,
            &[
                (
                    "Content-Type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                ),
                ("Retry-After".to_string(), "1".to_string()),
            ],
        );
    }

    let is_websocket = request
        .headers
        .get("upgrade")
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        && request
            .headers
            .get("connection")
            .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"));

    let mut upstream = match TcpStream::connect(&target.upstream) {
        Ok(s) => s,
        Err(err) => {
            let detail = format!("failed to connect to upstream {}: {err}", target.upstream);
            return bad_gateway(stream, request, opts, keep_alive, &detail);
        }
    };

    let remote_ip = client.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(client);
    if let Err(err) =
        write_upstream_request(&mut upstream, request, body, remote_ip, opts, is_websocket)
    {
        let detail = format!("failed to write request to upstream: {err}");
        return bad_gateway(stream, request, opts, keep_alive, &detail);
    }

    let mut reader = BufReader::new(&upstream);
    let (status, reason, headers) = match read_upstream_status_and_headers(&mut reader) {
        Ok(v) => v,
        Err(err) => {
            let detail = format!("upstream produced no usable response: {err}");
            return bad_gateway(stream, request, opts, keep_alive, &detail);
        }
    };

    if is_websocket && status == 101 {
        write_status_and_headers(stream, status, &reason, &headers)?;
        stream.flush()?;
        drop(reader);
        let bytes = relay_bidirectional(stream, &mut upstream)?;
        return Ok((status, bytes));
    }

    let framing = response_framing(&headers, head_only, status);
    write_status_and_headers(stream, status, &reason, &headers)?;
    let bytes = if head_only {
        0
    } else {
        stream_body(&mut reader, stream, framing)?
    };
    stream.flush()?;
    Ok((status, bytes))
}

fn bad_gateway(
    stream: &mut Conn,
    request: &Request,
    opts: &ServeOptions,
    keep_alive: bool,
    detail: &str,
) -> io::Result<(u16, u64)> {
    let page = super::error_page_with_trace(502, request, opts.debug, Some(detail));
    super::write_response(
        stream,
        502,
        "Bad Gateway",
        page.as_bytes(),
        request.method == "HEAD",
        keep_alive,
        &[(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
    )
}

#[allow(clippy::too_many_arguments)]
fn write_upstream_request(
    upstream: &mut TcpStream,
    request: &Request,
    body: &[u8],
    remote_ip: &str,
    opts: &ServeOptions,
    is_websocket: bool,
) -> io::Result<()> {
    let mut head = format!("{} {} HTTP/1.1\r\n", request.method, request.path);

    // Hop-by-hop between client and cashttpd only — a fresh connection is
    // opened to the upstream per proxied request (RFC 9110 §7.6.1), so the
    // client's own `Connection` value governs a different hop and is
    // replaced below rather than forwarded. Every other header, including
    // `Host`, is forwarded verbatim (IDEA.md "Request fidelity").
    for (k, v) in &request.headers {
        if k == "connection" {
            continue;
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }

    // X-Forwarded-* — appended to (never overwriting) any value already
    // present from a further upstream hop.
    let xff = match request.headers.get("x-forwarded-for") {
        Some(existing) => format!("{existing}, {remote_ip}"),
        None => remote_ip.to_string(),
    };
    head.push_str(&format!("X-Forwarded-For: {xff}\r\n"));
    let proto = if opts.tls_enabled { "https" } else { "http" };
    let xfp = match request.headers.get("x-forwarded-proto") {
        Some(existing) => format!("{existing}, {proto}"),
        None => proto.to_string(),
    };
    head.push_str(&format!("X-Forwarded-Proto: {xfp}\r\n"));
    head.push_str(if is_websocket {
        "Connection: Upgrade\r\n"
    } else {
        "Connection: close\r\n"
    });
    head.push_str("\r\n");

    upstream.write_all(head.as_bytes())?;
    if !body.is_empty() {
        upstream.write_all(body)?;
    }
    upstream.flush()
}

/// Status code, reason phrase, and ordered (possibly duplicated) headers
/// read from an upstream dev-server response.
type UpstreamResponseHead = (u16, String, Vec<(String, String)>);

fn read_upstream_status_and_headers(
    reader: &mut BufReader<&TcpStream>,
) -> io::Result<UpstreamResponseHead> {
    let mut status_line = String::new();
    if reader.read_line(&mut status_line)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty response from upstream",
        ));
    }
    let status_line = status_line.trim_end();
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next().unwrap_or("HTTP/1.1");
    let status: u16 = parts.next().and_then(|s| s.parse().ok()).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "malformed upstream status line")
    })?;
    let reason = parts.next().unwrap_or("").to_string();

    let mut headers = Vec::new();
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
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, reason, headers))
}

fn write_status_and_headers(
    stream: &mut Conn,
    status: u16,
    reason: &str,
    headers: &[(String, String)],
) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {status} {reason}\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())
}

enum Framing {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

fn response_framing(headers: &[(String, String)], head_only: bool, status: u16) -> Framing {
    if head_only || status == 204 || status == 304 || (100..200).contains(&status) {
        return Framing::None;
    }
    if headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked")
    }) {
        return Framing::Chunked;
    }
    if let Some((_, v)) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        if let Ok(n) = v.trim().parse() {
            return Framing::Length(n);
        }
    }
    Framing::UntilClose
}

/// Streams the response body from `reader` to `out` without buffering it
/// fully in memory, per the framing determined from the upstream's own
/// response headers.
fn stream_body(
    reader: &mut BufReader<&TcpStream>,
    out: &mut Conn,
    framing: Framing,
) -> io::Result<u64> {
    match framing {
        Framing::None => Ok(0),
        Framing::Length(n) => {
            let mut remaining = n;
            let mut buf = [0u8; 65536];
            while remaining > 0 {
                let take = remaining.min(buf.len() as u64) as usize;
                let read = reader.read(&mut buf[..take])?;
                if read == 0 {
                    break;
                }
                out.write_all(&buf[..read])?;
                remaining -= read as u64;
            }
            Ok(n - remaining)
        }
        Framing::Chunked => stream_chunked(reader, out),
        Framing::UntilClose => {
            let mut buf = [0u8; 65536];
            let mut total = 0u64;
            loop {
                let read = reader.read(&mut buf)?;
                if read == 0 {
                    break;
                }
                out.write_all(&buf[..read])?;
                total += read as u64;
            }
            Ok(total)
        }
    }
}

/// Relays a `Transfer-Encoding: chunked` body chunk-by-chunk, verbatim —
/// no decode/re-encode round trip, just the chunk-size lines and payloads
/// (plus any trailer headers) passed straight through.
fn stream_chunked(reader: &mut BufReader<&TcpStream>, out: &mut Conn) -> io::Result<u64> {
    let mut total = 0u64;
    loop {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line)? == 0 {
            break;
        }
        out.write_all(size_line.as_bytes())?;
        let size_str = size_line.trim().split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).unwrap_or(0);
        if size == 0 {
            loop {
                let mut trailer = String::new();
                if reader.read_line(&mut trailer)? == 0 {
                    break;
                }
                out.write_all(trailer.as_bytes())?;
                if trailer.trim().is_empty() {
                    break;
                }
            }
            break;
        }
        let mut data = vec![0u8; size + 2];
        reader.read_exact(&mut data)?;
        out.write_all(&data)?;
        total += size as u64;
    }
    Ok(total)
}

fn is_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Raw bidirectional byte relay after a successful WebSocket/`Upgrade`
/// handshake (RFC 6455). A short-timeout poll loop on the calling thread,
/// rather than one thread per direction: it avoids ever needing two live
/// `&mut` handles onto the same `Conn` — the TLS variant wraps a single
/// `rustls::ServerConnection` state machine that isn't safely splittable
/// across concurrent reader/writer threads without a shared lock, and a
/// lock held across a blocking read would risk one idle direction
/// stalling the other. WebSocket/HMR traffic is low-bandwidth enough that
/// the poll overhead is immaterial.
fn relay_bidirectional(client: &mut Conn, upstream: &mut TcpStream) -> io::Result<u64> {
    client.set_read_timeout(Some(Duration::from_millis(100)))?;
    upstream.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut buf = [0u8; 8192];
    let mut total = 0u64;
    loop {
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                upstream.write_all(&buf[..n])?;
                total += n as u64;
            }
            Err(err) if is_timeout(&err) => {}
            Err(err) => return Err(err),
        }
        match upstream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                client.write_all(&buf[..n])?;
                total += n as u64;
            }
            Err(err) if is_timeout(&err) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn unique_dir(name: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "cashttpd-proxy-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        dir
    }

    fn make_dir(name: &str) -> std::path::PathBuf {
        let dir = unique_dir(name);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_opts(base_dir: std::path::PathBuf) -> ServeOptions {
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
            project_config_path: std::path::PathBuf::new(),
        }
    }

    #[test]
    fn detects_node_from_package_json_scripts() {
        let dir = make_dir("node");
        std::fs::write(
            dir.join("package.json"),
            r#"{"scripts":{"dev":"next dev"}}"#,
        )
        .unwrap();
        assert_eq!(detect(&dir).map(|p| p.name), Some("node"));
    }

    #[test]
    fn detects_vite_from_config_file() {
        let dir = make_dir("vite");
        std::fs::write(dir.join("vite.config.ts"), "export default {}").unwrap();
        assert_eq!(detect(&dir).map(|p| p.name), Some("vite"));
    }

    #[test]
    fn detects_bun_from_lockfile() {
        let dir = make_dir("bun");
        std::fs::write(dir.join("package.json"), "{}").unwrap();
        std::fs::write(dir.join("bun.lockb"), b"").unwrap();
        assert_eq!(detect(&dir).map(|p| p.name), Some("bun"));
    }

    #[test]
    fn detects_deno_from_deno_json() {
        let dir = make_dir("deno");
        std::fs::write(dir.join("deno.json"), "{}").unwrap();
        assert_eq!(detect(&dir).map(|p| p.name), Some("deno"));
    }

    #[test]
    fn detects_rails_from_gemfile_and_config_ru() {
        let dir = make_dir("rails");
        std::fs::write(dir.join("Gemfile"), "source 'https://rubygems.org'").unwrap();
        std::fs::write(dir.join("config.ru"), "run Rails.application").unwrap();
        assert_eq!(detect(&dir).map(|p| p.name), Some("rails"));
    }

    #[test]
    fn detects_django_from_manage_py() {
        let dir = make_dir("django");
        std::fs::write(dir.join("manage.py"), "#!/usr/bin/env python").unwrap();
        assert_eq!(detect(&dir).map(|p| p.name), Some("django"));
    }

    #[test]
    fn detects_fastapi_from_requirements_txt() {
        let dir = make_dir("fastapi");
        std::fs::write(dir.join("requirements.txt"), "fastapi\nuvicorn\n").unwrap();
        assert_eq!(detect(&dir).map(|p| p.name), Some("fastapi"));
    }

    #[test]
    fn detects_flask_from_pyproject_toml() {
        let dir = make_dir("flask");
        std::fs::write(
            dir.join("pyproject.toml"),
            "[project]\ndependencies=[\"flask\"]",
        )
        .unwrap();
        assert_eq!(detect(&dir).map(|p| p.name), Some("flask"));
    }

    #[test]
    fn detects_nothing_without_markers() {
        let dir = make_dir("empty");
        assert!(detect(&dir).is_none());
    }

    #[test]
    fn resolve_returns_none_when_explicitly_disabled_despite_markers() {
        let dir = make_dir("disabled");
        std::fs::write(dir.join("manage.py"), "").unwrap();
        let layer = crate::config::ProxyLayer {
            enabled: Some(false),
            ..Default::default()
        };
        assert!(resolve_proxy_target(&dir, &layer).is_none());
    }

    #[test]
    fn resolve_returns_none_with_no_markers_and_no_overrides() {
        let dir = make_dir("nomarkers");
        let layer = crate::config::ProxyLayer::default();
        assert!(resolve_proxy_target(&dir, &layer).is_none());
    }

    #[test]
    fn resolve_reuses_profile_defaults_from_explicit_type() {
        let dir = make_dir("type-only");
        let layer = crate::config::ProxyLayer {
            kind: Some("django".to_string()),
            ..Default::default()
        };
        let target = resolve_proxy_target(&dir, &layer).unwrap();
        assert_eq!(target.kind, "django");
        assert_eq!(target.upstream, "127.0.0.1:8000");
        assert_eq!(target.command, "python3 manage.py runserver 127.0.0.1:8000");
        assert_eq!(target.path_prefix, "/");
    }

    #[test]
    fn resolve_command_override_keeps_profile_upstream() {
        let dir = make_dir("command-override");
        let layer = crate::config::ProxyLayer {
            kind: Some("node".to_string()),
            command: Some("yarn dev".to_string()),
            ..Default::default()
        };
        let target = resolve_proxy_target(&dir, &layer).unwrap();
        assert_eq!(target.command, "yarn dev");
        assert_eq!(target.upstream, "127.0.0.1:3000");
    }

    #[test]
    fn resolve_fully_explicit_command_and_upstream_needs_no_type() {
        let dir = make_dir("fully-explicit");
        let layer = crate::config::ProxyLayer {
            command: Some("./run-dev-server.sh".to_string()),
            upstream: Some("127.0.0.1:4000".to_string()),
            path_prefix: Some("/app".to_string()),
            ..Default::default()
        };
        let target = resolve_proxy_target(&dir, &layer).unwrap();
        assert_eq!(target.kind, "custom");
        assert_eq!(target.command, "./run-dev-server.sh");
        assert_eq!(target.upstream, "127.0.0.1:4000");
        assert_eq!(target.path_prefix, "/app");
    }

    #[test]
    fn is_upstream_ready_false_for_unbound_port() {
        assert!(!is_upstream_ready("127.0.0.1:1"));
    }

    #[test]
    fn is_upstream_ready_true_for_bound_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(is_upstream_ready(&addr.to_string()));
    }

    #[test]
    fn starting_page_contains_auto_refresh_and_escaped_request() {
        let request = Request {
            method: "GET".to_string(),
            path: "/<app>".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: Default::default(),
        };
        let page = starting_page(&request);
        assert!(page.contains("http-equiv=\"refresh\""));
        assert!(page.contains("&lt;app&gt;"));
    }

    /// Header forwarding correctness — X-Forwarded-For/Proto append rather
    /// than overwrite, Host is forwarded unmodified, and the client's own
    /// `Connection` header is replaced (hop-by-hop) rather than forwarded.
    #[test]
    fn write_upstream_request_appends_forwarded_headers_and_keeps_host() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let mut headers = std::collections::HashMap::new();
        headers.insert("host".to_string(), "app.example.test".to_string());
        headers.insert("x-forwarded-for".to_string(), "10.0.0.1".to_string());
        headers.insert("connection".to_string(), "keep-alive".to_string());
        let request = Request {
            method: "GET".to_string(),
            path: "/api/things?x=1".to_string(),
            version: "HTTP/1.1".to_string(),
            headers,
        };
        let dir = make_dir("write-upstream");
        let opts = test_opts(dir);

        write_upstream_request(&mut client, &request, b"", "192.0.2.5", &opts, false).unwrap();
        drop(client);

        let mut received = Vec::new();
        server.read_to_end(&mut received).unwrap();
        let text = String::from_utf8_lossy(&received);

        assert!(text.starts_with("GET /api/things?x=1 HTTP/1.1\r\n"));
        assert!(text.contains("host: app.example.test\r\n"));
        assert!(text.contains("X-Forwarded-For: 10.0.0.1, 192.0.2.5\r\n"));
        assert!(text.contains("X-Forwarded-Proto: http\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(!text.contains("connection: keep-alive"));
    }

    #[test]
    fn write_upstream_request_uses_upgrade_connection_for_websocket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let mut headers = std::collections::HashMap::new();
        headers.insert("upgrade".to_string(), "websocket".to_string());
        headers.insert("connection".to_string(), "Upgrade".to_string());
        let request = Request {
            method: "GET".to_string(),
            path: "/ws".to_string(),
            version: "HTTP/1.1".to_string(),
            headers,
        };
        let dir = make_dir("write-upstream-ws");
        let opts = test_opts(dir);

        write_upstream_request(&mut client, &request, b"", "192.0.2.5", &opts, true).unwrap();
        drop(client);

        let mut received = Vec::new();
        server.read_to_end(&mut received).unwrap();
        let text = String::from_utf8_lossy(&received);
        assert!(text.contains("Connection: Upgrade\r\n"));
    }
}
