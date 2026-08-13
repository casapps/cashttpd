//! HTTP/HTTPS listener, routing, and request handling (IDEA.md
//! "Core behavior", "Security / access control model"). Serves `base_dir`
//! with strict canonicalize-then-check path safety — no traversal outside
//! `base_dir` under any circumstance.
//!
//! This is a minimal HTTP/1.1 GET/HEAD static-file server — enough to
//! exercise the full daemon lifecycle end to end (dual-stack bind,
//! bind-then-drop privileges, signal-driven graceful shutdown). Full RFC
//! 9110/9112 conformance (request headers, keep-alive, chunked transfer,
//! CGI/script execution, `.htaccess`/`.htpasswd`, TLS, framework dev-server
//! proxying, `/server-info` dashboard, Apache-combined access logging) is
//! the single largest remaining gap in this project and is tracked in
//! TODO.AI.md — this module never claims RFC conformance.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::support::signal;

/// Effective runtime options for `serve` (subset of IDEA.md's full CLI
/// flags table — the remaining flags are tracked in TODO.AI.md pending
/// full config-file loading).
pub struct ServeOptions {
    pub listen: String,
    pub port: u16,
    pub base_dir: PathBuf,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            listen: "::".to_string(),
            port: 8080,
            base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }
}

/// Parses `--listen`, `--port`, `--dir` from the `serve` subcommand's
/// arguments. Full config-file layering (CLI > env > per-project config >
/// global config > built-in default, per IDEA.md "Configuration file") is
/// tracked in TODO.AI.md; this covers the CLI-flag layer only.
pub fn parse_serve_options(args: &[String]) -> ServeOptions {
    let mut opts = ServeOptions::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                if let Some(v) = args.get(i + 1) {
                    opts.listen = v.clone();
                    i += 1;
                }
            }
            "--port" => {
                if let Some(v) = args.get(i + 1) {
                    if let Ok(p) = v.parse() {
                        opts.port = p;
                    }
                    i += 1;
                }
            }
            "--dir" => {
                if let Some(v) = args.get(i + 1) {
                    opts.base_dir = PathBuf::from(v);
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    opts
}

/// Runs the `serve` daemon (AI.md PART 14 "Runtime Model"): binds a
/// dual-stack listener, drops root privileges once bound ("Sockets, Ports
/// & Privileges" — bind-then-drop), installs signal handlers, and serves
/// static files from `base_dir` until shutdown is requested. `SIGHUP` is a
/// terminating signal here, not a reload, per IDEA.md's documented
/// deviation from this PART's generic default.
pub fn run(opts: ServeOptions) -> std::io::Result<()> {
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

    let banner = format!(
        "cashttpd {} listening on {bind_addr} (base dir: {})",
        crate::support::version::VERSION,
        opts.base_dir.display()
    );
    if crate::support::color::color_enabled(None) {
        // `COLORFGBG` (set by many terminal emulators) reports
        // "foreground;background" ANSI indices; a background index below 8
        // is conventionally a dark background. Absent that hint, default to
        // the dark palette (the common terminal default).
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

    let base_dir = Arc::new(opts.base_dir.canonicalize().unwrap_or(opts.base_dir));
    let request_count = Arc::new(AtomicU64::new(0));
    let started_at = Instant::now();

    while !shutdown.is_shutdown_requested() {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let base_dir = Arc::clone(&base_dir);
                let request_count = Arc::clone(&request_count);
                std::thread::spawn(move || {
                    request_count.fetch_add(1, Ordering::Relaxed);
                    if let Err(err) = handle_connection(stream, &base_dir) {
                        eprintln!("cashttpd: connection error: {err}");
                    }
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => {
                eprintln!("cashttpd: accept error: {err}");
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

fn handle_connection(mut stream: TcpStream, base_dir: &Path) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf)?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let request_line = request.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_path = parts.next().unwrap_or("/");

    if method != "GET" && method != "HEAD" {
        return write_response(
            &mut stream,
            405,
            "Method Not Allowed",
            b"",
            method == "HEAD",
        );
    }

    let requested = raw_path.trim_start_matches('/');
    let requested = if requested.is_empty() {
        "index.html"
    } else {
        requested
    };
    let candidate = base_dir.join(requested);

    let resolved = match candidate.canonicalize() {
        Ok(p) if p.starts_with(base_dir) => p,
        _ => {
            return write_response(
                &mut stream,
                404,
                "Not Found",
                b"Not Found",
                method == "HEAD",
            );
        }
    };

    match std::fs::read(&resolved) {
        Ok(body) => {
            let size_note = crate::support::format::size(body.len() as u64);
            eprintln!("cashttpd: 200 {raw_path} ({size_note})");
            write_response(&mut stream, 200, "OK", &body, method == "HEAD")
        }
        Err(_) => write_response(
            &mut stream,
            404,
            "Not Found",
            b"Not Found",
            method == "HEAD",
        ),
    }
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
    head_only: bool,
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    if !head_only {
        stream.write_all(body)?;
    }
    Ok(())
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

    #[test]
    fn parse_serve_options_defaults_when_no_flags() {
        let opts = parse_serve_options(&[]);
        let default = ServeOptions::default();
        assert_eq!(opts.listen, default.listen);
        assert_eq!(opts.port, default.port);
        assert_eq!(opts.base_dir, default.base_dir);
    }

    #[test]
    fn parse_serve_options_reads_all_flags() {
        let args = vec![
            "--listen".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            "9090".to_string(),
            "--dir".to_string(),
            "/tmp/somewhere".to_string(),
        ];
        let opts = parse_serve_options(&args);
        assert_eq!(opts.listen, "127.0.0.1");
        assert_eq!(opts.port, 9090);
        assert_eq!(opts.base_dir, PathBuf::from("/tmp/somewhere"));
    }

    #[test]
    fn parse_serve_options_ignores_unparseable_port() {
        let args = vec!["--port".to_string(), "not-a-number".to_string()];
        let opts = parse_serve_options(&args);
        assert_eq!(opts.port, ServeOptions::default().port);
    }

    #[test]
    fn parse_serve_options_ignores_trailing_flag_without_value() {
        let args = vec!["--listen".to_string()];
        let opts = parse_serve_options(&args);
        assert_eq!(opts.listen, ServeOptions::default().listen);
    }

    fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (server, client)
    }

    #[test]
    fn write_response_full_body_includes_headers_and_content() {
        let (mut server, mut client) = loopback_pair();
        write_response(&mut server, 200, "OK", b"hello", false).unwrap();
        drop(server);
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(text.ends_with("hello"));
    }

    #[test]
    fn write_response_head_only_omits_body() {
        let (mut server, mut client) = loopback_pair();
        write_response(&mut server, 404, "Not Found", b"Not Found", true).unwrap();
        drop(server);
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    fn request_over_loopback(base_dir: &Path, request_line: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base_dir = base_dir.to_path_buf();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream, &base_dir).unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(request_line.as_bytes()).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).unwrap();
        handle.join().unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }

    #[test]
    fn handle_connection_serves_existing_file() {
        let dir = unique_dir("serve");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("hello.txt"), b"hi there").unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "GET /hello.txt HTTP/1.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("hi there"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn handle_connection_defaults_root_to_index_html() {
        let dir = unique_dir("index");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("index.html"), b"<html></html>").unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "GET / HTTP/1.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("<html></html>"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn handle_connection_returns_404_for_missing_file() {
        let dir = unique_dir("missing");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "GET /nope.txt HTTP/1.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn handle_connection_blocks_path_traversal_outside_base_dir() {
        let dir = unique_dir("traversal");
        fs::create_dir_all(&dir).unwrap();
        // A file that genuinely exists on disk just outside base_dir — the
        // canonicalize()+starts_with() check must still reject it, proving
        // the traversal guard runs (not just a missing-file 404).
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

        let request_line = format!("GET /../{secret_name} HTTP/1.1\r\n\r\n");
        let response = request_over_loopback(&base_dir, &request_line);
        assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));

        fs::remove_dir_all(&dir).ok();
        fs::remove_file(secret_parent.join(&secret_name)).ok();
    }

    #[test]
    fn handle_connection_rejects_unsupported_method() {
        let dir = unique_dir("method");
        fs::create_dir_all(&dir).unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "POST / HTTP/1.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn handle_connection_head_request_omits_body() {
        let dir = unique_dir("head");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("index.html"), b"<html></html>").unwrap();
        let base_dir = dir.canonicalize().unwrap();

        let response = request_over_loopback(&base_dir, "HEAD / HTTP/1.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("\r\n\r\n"));

        fs::remove_dir_all(&dir).ok();
    }
}
