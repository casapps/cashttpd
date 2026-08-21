//! Framework dev-server proxying (IDEA.md "Framework dev-server proxying").
//!
//! `resolve_proxy_target` layers the resolved `proxy.*` config
//! (`crate::configs::ProxyLayer`) over a built-in table of framework
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
//! `crate::supports::signal::ShutdownState::track_child_process` so it is
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

use std::io;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;

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
    layer: &crate::configs::ProxyLayer,
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
pub async fn is_upstream_ready(upstream: &str) -> bool {
    let Ok(mut addrs) = upstream.to_socket_addrs() else {
        return false;
    };
    let Some(addr) = addrs.next() else {
        return false;
    };
    matches!(
        tokio::time::timeout(
            Duration::from_millis(200),
            tokio::net::TcpStream::connect(addr)
        )
        .await,
        Ok(Ok(_))
    )
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

/// Forwards `request`/`body` to `target.upstream` and returns the upstream
/// response for relaying back to the client. See the module doc comment for
/// the exact request/response fidelity rules.
///
/// The response body is handed back as `hyper`'s streaming `Incoming` body
/// rather than being collected, so a large or long-lived (SSE/HMR) upstream
/// response still reaches the client incrementally — the same property the
/// previous hand-rolled chunk relay had, now with `hyper` owning the
/// HTTP/1.1 framing on both hops.
// Each parameter is an independent piece of per-request proxy state (matched
// target, parsed request, already-read body, client address, effective server
// config, and the client's pending protocol upgrade) that the caller already
// has on hand from request dispatch — bundling them into a struct would only
// add an indirection layer without reducing the information this function
// needs.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_request(
    target: &ProxyTarget,
    request: &Request,
    body: &[u8],
    client: &str,
    opts: &ServeOptions,
    upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> io::Result<Response<super::Body>> {
    let head_only = request.method == "HEAD";

    if !is_upstream_ready(&target.upstream).await {
        let page = starting_page(request);
        let mut headers = vec![
            (
                "Content-Type".to_string(),
                "text/html; charset=utf-8".to_string(),
            ),
            ("Retry-After".to_string(), "1".to_string()),
        ];
        if head_only {
            headers.push(("Content-Length".to_string(), page.len().to_string()));
            return super::build_response(503, "Service Unavailable", Bytes::new(), &headers);
        }
        return super::build_response(503, "Service Unavailable", Bytes::from(page), &headers);
    }

    let is_websocket = request
        .headers
        .get("upgrade")
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        && request
            .headers
            .get("connection")
            .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"));

    let remote_ip = client.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(client);
    let upstream_request =
        match build_upstream_request(request, body, remote_ip, opts, is_websocket) {
            Ok(req) => req,
            Err(err) => {
                let detail = format!("could not build upstream request: {err}");
                return bad_gateway(request, opts, &detail);
            }
        };

    let socket = match tokio::net::TcpStream::connect(&target.upstream).await {
        Ok(s) => s,
        Err(err) => {
            let detail = format!("failed to connect to upstream {}: {err}", target.upstream);
            return bad_gateway(request, opts, &detail);
        }
    };
    let _ = socket.set_nodelay(true);

    let (mut sender, connection) =
        match hyper::client::conn::http1::handshake(TokioIo::new(socket)).await {
            Ok(pair) => pair,
            Err(err) => {
                let detail = format!("upstream HTTP/1.1 handshake failed: {err}");
                return bad_gateway(request, opts, &detail);
            }
        };
    // `with_upgrades` keeps the connection task alive past a 101 so the
    // WebSocket relay below can take ownership of the raw socket (RFC 6455
    // §4.2.2); it is harmless for ordinary responses.
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });

    let upstream_response = match sender.send_request(upstream_request).await {
        Ok(resp) => resp,
        Err(err) => {
            let detail = format!("upstream produced no usable response: {err}");
            return bad_gateway(request, opts, &detail);
        }
    };

    let status = upstream_response.status();

    if is_websocket && status == StatusCode::SWITCHING_PROTOCOLS {
        return Ok(relay_upgrade(upstream_response, upgrade));
    }

    // A non-101 response ends this hop's interest in the client's pending
    // upgrade — dropping it makes `hyper` finish the request normally
    // instead of leaving a half-upgraded connection.
    drop(upgrade);

    let (parts, incoming) = upstream_response.into_parts();
    let mut response = Response::new(incoming.map_err(io::Error::other).boxed());
    *response.status_mut() = parts.status;
    copy_relayable_headers(&parts.headers, response.headers_mut(), false);
    Ok(response)
}

/// Completes a WebSocket/`Upgrade` handshake in both directions (RFC 6455
/// §4.2.2): the 101 and its handshake headers go back to the client, and once
/// both sides have finished switching protocols the two raw byte streams are
/// spliced together. `copy_bidirectional` replaces the previous poll loop —
/// with each side owned by an independent async half there is no longer a
/// single non-splittable TLS state machine forcing a timeout-poll design.
fn relay_upgrade(
    mut upstream_response: Response<hyper::body::Incoming>,
    client_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Response<super::Body> {
    let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
    let parts = upstream_response.into_parts().0;

    if let Some(client_upgrade) = client_upgrade {
        tokio::spawn(async move {
            let (Ok(client_io), Ok(upstream_io)) = tokio::join!(client_upgrade, upstream_upgrade)
            else {
                return;
            };
            let mut client_io = TokioIo::new(client_io);
            let mut upstream_io = TokioIo::new(upstream_io);
            let _ = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await;
        });
    }

    let mut response = Response::new(super::full_body(Bytes::new()));
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    // The 101's own `Connection: Upgrade` / `Upgrade:` headers are part of
    // the handshake the client must see, so they are relayed here even though
    // they are hop-by-hop for every other status.
    copy_relayable_headers(&parts.headers, response.headers_mut(), true);
    response
}

/// Copies upstream response headers onto the client-facing response, dropping
/// the hop-by-hop set (RFC 9110 §7.6.1). Forwarding `Transfer-Encoding` or
/// `Content-Length` verbatim would now contradict the framing `hyper` picks
/// for the outgoing message — the classic request/response smuggling
/// desync — and neither is meaningful on HTTP/2 or HTTP/3, where this same
/// response may be sent (RFC 9113 §8.2.2).
fn copy_relayable_headers(from: &http::HeaderMap, into: &mut http::HeaderMap, keep_upgrade: bool) {
    for (name, value) in from.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        let hop_by_hop = matches!(
            lower.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "content-length"
        ) || (lower == "upgrade" && !keep_upgrade);
        if hop_by_hop && !(keep_upgrade && (lower == "connection" || lower == "upgrade")) {
            continue;
        }
        into.append(name.clone(), value.clone());
    }
}

fn bad_gateway(
    request: &Request,
    opts: &ServeOptions,
    detail: &str,
) -> io::Result<Response<super::Body>> {
    let page = super::error_page_with_trace(502, request, opts.debug, Some(detail));
    let mut headers = vec![(
        "Content-Type".to_string(),
        "text/html; charset=utf-8".to_string(),
    )];
    if request.method == "HEAD" {
        headers.push(("Content-Length".to_string(), page.len().to_string()));
        return super::build_response(502, "Bad Gateway", Bytes::new(), &headers);
    }
    super::build_response(502, "Bad Gateway", Bytes::from(page), &headers)
}

/// Header names that describe *this* hop's connection and must never be
/// forwarded to the next one (RFC 9110 §7.6.1). Passing `Transfer-Encoding`
/// or `Content-Length` through while `hyper` independently frames the
/// outgoing request is exactly the TE/CL disagreement that request smuggling
/// exploits, so both are dropped and the framing is recomputed from the body
/// this server actually holds.
fn is_hop_by_hop_request_header(name: &str, is_websocket: bool) -> bool {
    match name {
        "connection"
        | "keep-alive"
        | "proxy-authenticate"
        | "proxy-authorization"
        | "proxy-connection"
        | "te"
        | "trailer"
        | "transfer-encoding"
        | "content-length" => true,
        "upgrade" => !is_websocket,
        _ => false,
    }
}

/// Builds the upstream request: the client's own request line and headers
/// forwarded verbatim (including `Host`), minus the hop-by-hop set, plus the
/// `X-Forwarded-*` pair.
fn build_upstream_request(
    request: &Request,
    body: &[u8],
    remote_ip: &str,
    opts: &ServeOptions,
    is_websocket: bool,
) -> io::Result<hyper::Request<Full<Bytes>>> {
    let method = http::Method::from_bytes(request.method.as_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let uri: http::Uri = request
        .path
        .parse()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .version(http::Version::HTTP_11);

    if let Some(headers) = builder.headers_mut() {
        for (k, v) in &request.headers {
            if is_hop_by_hop_request_header(k, is_websocket) {
                continue;
            }
            let Ok(name) = http::header::HeaderName::from_bytes(k.as_bytes()) else {
                continue;
            };
            let Ok(value) = http::HeaderValue::from_str(v) else {
                continue;
            };
            headers.append(name, value);
        }

        // X-Forwarded-* — appended to (never overwriting) any value already
        // present from a further upstream hop.
        let xff = match request.headers.get("x-forwarded-for") {
            Some(existing) => format!("{existing}, {remote_ip}"),
            None => remote_ip.to_string(),
        };
        if let Ok(value) = http::HeaderValue::from_str(&xff) {
            headers.insert("x-forwarded-for", value);
        }
        let proto = if opts.tls_enabled { "https" } else { "http" };
        let xfp = match request.headers.get("x-forwarded-proto") {
            Some(existing) => format!("{existing}, {proto}"),
            None => proto.to_string(),
        };
        if let Ok(value) = http::HeaderValue::from_str(&xfp) {
            headers.insert("x-forwarded-proto", value);
        }
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static(if is_websocket { "Upgrade" } else { "close" }),
        );
    }

    builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
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
        let layer = crate::configs::ProxyLayer {
            enabled: Some(false),
            ..Default::default()
        };
        assert!(resolve_proxy_target(&dir, &layer).is_none());
    }

    #[test]
    fn resolve_returns_none_with_no_markers_and_no_overrides() {
        let dir = make_dir("nomarkers");
        let layer = crate::configs::ProxyLayer::default();
        assert!(resolve_proxy_target(&dir, &layer).is_none());
    }

    #[test]
    fn resolve_reuses_profile_defaults_from_explicit_type() {
        let dir = make_dir("type-only");
        let layer = crate::configs::ProxyLayer {
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
        let layer = crate::configs::ProxyLayer {
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
        let layer = crate::configs::ProxyLayer {
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

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn is_upstream_ready_false_for_unbound_port() {
        assert!(!block_on(is_upstream_ready("127.0.0.1:1")));
    }

    #[test]
    fn is_upstream_ready_true_for_bound_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(block_on(is_upstream_ready(&addr.to_string())));
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
    fn build_upstream_request_appends_forwarded_headers_and_keeps_host() {
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
        let dir = make_dir("build-upstream");
        let opts = test_opts(dir);

        let built = build_upstream_request(&request, b"", "192.0.2.5", &opts, false).unwrap();

        assert_eq!(built.method(), http::Method::GET);
        assert_eq!(built.uri().path_and_query().unwrap(), "/api/things?x=1");
        assert_eq!(built.headers()["host"], "app.example.test");
        assert_eq!(built.headers()["x-forwarded-for"], "10.0.0.1, 192.0.2.5");
        assert_eq!(built.headers()["x-forwarded-proto"], "http");
        assert_eq!(built.headers()["connection"], "close");
    }

    #[test]
    fn build_upstream_request_uses_upgrade_connection_for_websocket() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("upgrade".to_string(), "websocket".to_string());
        headers.insert("connection".to_string(), "Upgrade".to_string());
        let request = Request {
            method: "GET".to_string(),
            path: "/ws".to_string(),
            version: "HTTP/1.1".to_string(),
            headers,
        };
        let dir = make_dir("build-upstream-ws");
        let opts = test_opts(dir);

        let built = build_upstream_request(&request, b"", "192.0.2.5", &opts, true).unwrap();
        assert_eq!(built.headers()["connection"], "Upgrade");
        assert_eq!(built.headers()["upgrade"], "websocket");
    }

    /// Hop-by-hop request headers must never reach the upstream: forwarding
    /// `Transfer-Encoding` or `Content-Length` alongside the body `hyper`
    /// re-frames is the TE/CL disagreement request smuggling relies on.
    #[test]
    fn build_upstream_request_drops_hop_by_hop_framing_headers() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("transfer-encoding".to_string(), "chunked".to_string());
        headers.insert("content-length".to_string(), "9999".to_string());
        headers.insert("te".to_string(), "trailers".to_string());
        headers.insert("upgrade".to_string(), "h2c".to_string());
        let request = Request {
            method: "POST".to_string(),
            path: "/submit".to_string(),
            version: "HTTP/1.1".to_string(),
            headers,
        };
        let dir = make_dir("build-upstream-smuggle");
        let opts = test_opts(dir);

        let built = build_upstream_request(&request, b"hello", "192.0.2.5", &opts, false).unwrap();
        assert!(!built.headers().contains_key("transfer-encoding"));
        assert!(!built.headers().contains_key("te"));
        assert!(!built.headers().contains_key("upgrade"));
        assert_eq!(built.headers().get("content-length"), None);
    }

    /// Hop-by-hop response headers are stripped on the way back for the same
    /// reason, except on a 101 where `Connection`/`Upgrade` are the handshake.
    #[test]
    fn copy_relayable_headers_strips_hop_by_hop_except_on_upgrade() {
        let mut from = http::HeaderMap::new();
        from.insert("content-type", http::HeaderValue::from_static("text/html"));
        from.insert(
            "transfer-encoding",
            http::HeaderValue::from_static("chunked"),
        );
        from.insert("connection", http::HeaderValue::from_static("Upgrade"));
        from.insert("upgrade", http::HeaderValue::from_static("websocket"));

        let mut plain = http::HeaderMap::new();
        copy_relayable_headers(&from, &mut plain, false);
        assert_eq!(plain["content-type"], "text/html");
        assert!(!plain.contains_key("transfer-encoding"));
        assert!(!plain.contains_key("connection"));
        assert!(!plain.contains_key("upgrade"));

        let mut switching = http::HeaderMap::new();
        copy_relayable_headers(&from, &mut switching, true);
        assert_eq!(switching["connection"], "Upgrade");
        assert_eq!(switching["upgrade"], "websocket");
        assert!(!switching.contains_key("transfer-encoding"));
    }
}
