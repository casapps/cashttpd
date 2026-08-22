//! HTTP/3 (RFC 9114) over QUIC (RFC 9000/9001).
//!
//! IDEA.md "Core behavior" → "Protocol version negotiation": when
//! `tls.enabled: true`, HTTP/3 is served on a UDP socket bound to the same
//! port number as the TCP listener and advertised to TCP clients through the
//! `Alt-Svc: h3=":{port}"` header that `servers::finish_response` attaches.
//! There is no cleartext HTTP/3 — QUIC mandates TLS 1.3 — so this module is
//! never started when TLS is off.
//!
//! Requests arriving here are normalised into the same `servers::Request`
//! shape the HTTP/1.1 and HTTP/2 paths produce and handed to the shared
//! `servers::dispatch`, so `.htaccess`/`.htpasswd`, path-traversal
//! containment, CGI, framework proxying, statistics, and access logging are
//! byte-for-byte the same logic on all three protocol versions.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use http_body_util::BodyExt;

use super::{Request, ServeContext, MAX_REQUEST_BODY};

/// Concurrent QUIC connections accepted at once. QUIC connections are cheap
/// to open and expensive to keep (each holds congestion-control and packet
/// state), so an explicit ceiling is what stops a connection flood from
/// growing memory without bound; excess connections wait rather than being
/// dropped, which keeps the retry behaviour ordinary from a client's view.
const MAX_QUIC_CONNECTIONS: usize = 512;

/// Per-connection request-stream ceiling (RFC 9114 §6.1 — one bidirectional
/// stream per request), the HTTP/3 analogue of the HTTP/2
/// `max_concurrent_streams` limit that mitigates CVE-2023-44487-style stream
/// churn.
const MAX_BIDI_STREAMS: u32 = 128;

/// Control/QPACK unidirectional streams only (RFC 9114 §6.2) — three are
/// mandated, the small allowance leaves room for a future extension stream
/// without permitting unidirectional-stream flooding.
const MAX_UNI_STREAMS: u32 = 8;

/// Idle connections are reclaimed rather than held forever (RFC 9000 §10.1).
const MAX_IDLE_MS: u32 = 60_000;

/// A running HTTP/3 listener. Dropping the handle does not stop the
/// listener — `shutdown` does, and is called explicitly on server shutdown
/// and whenever a live config reload rebinds the TCP listener.
pub struct Handle {
    endpoint: quinn::Endpoint,
    task: tokio::task::JoinHandle<()>,
}

impl Handle {
    /// Closes the QUIC endpoint with an application-level "going away" and
    /// aborts the accept loop. Existing connections are told to close rather
    /// than being silently blackholed, which is what lets a browser fall
    /// back to the still-listening TCP socket immediately.
    pub fn shutdown(self) {
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"cashttpd shutting down");
        self.task.abort();
    }
}

/// Binds the QUIC endpoint on `addr` (the TCP listener's own resolved local
/// address) and starts accepting HTTP/3 connections.
pub fn spawn(
    addr: SocketAddr,
    quic: Arc<rustls::ServerConfig>,
    ctx: ServeContext,
) -> std::io::Result<Handle> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(quic)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));

    // Every value here is at least as strict as quinn's own default. Quinn
    // already enforces RFC 9000 §8 address validation and the 3x
    // anti-amplification limit before a peer's address is confirmed; nothing
    // below relaxes that, and no retry/validation setting is overridden.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(MAX_BIDI_STREAMS.into());
    transport.max_concurrent_uni_streams(MAX_UNI_STREAMS.into());
    transport.max_idle_timeout(Some(quinn::VarInt::from_u32(MAX_IDLE_MS).into()));
    server_config.transport_config(Arc::new(transport));

    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    let accept_endpoint = endpoint.clone();
    let task = tokio::spawn(async move {
        accept_loop(accept_endpoint, ctx).await;
    });
    Ok(Handle { endpoint, task })
}

async fn accept_loop(endpoint: quinn::Endpoint, ctx: ServeContext) {
    // `quinn` has no built-in concurrent-connection ceiling, so the cap is
    // enforced here: a permit is held for the whole life of a connection and
    // the accept loop stops pulling new handshakes off the socket once they
    // run out.
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_QUIC_CONNECTIONS));
    while let Some(incoming) = endpoint.accept().await {
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
            return;
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let connection = match incoming.await {
                Ok(connection) => connection,
                // A failed handshake is an ordinary event on a public UDP
                // port (stray packets, probes, version mismatch) and is not
                // worth an error-log line per occurrence.
                Err(_) => return,
            };
            let client = connection.remote_address().to_string();
            if let Err(err) = serve_connection(connection, ctx.clone(), client.clone()).await {
                ctx.state
                    .logger
                    .error(&format!("HTTP/3 connection error from {client}: {err}"));
            }
        });
    }
}

async fn serve_connection(
    connection: quinn::Connection,
    ctx: ServeContext,
    client: String,
) -> std::io::Result<()> {
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(std::io::Error::other)?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let ctx = ctx.clone();
                let client = client.clone();
                tokio::spawn(async move {
                    if let Err(err) = serve_stream(resolver, ctx.clone(), client.clone()).await {
                        ctx.state
                            .logger
                            .error(&format!("HTTP/3 stream error from {client}: {err}"));
                    }
                });
            }
            // Clean end of the connection.
            Ok(None) => return Ok(()),
            Err(err) => {
                if err.is_h3_no_error() {
                    return Ok(());
                }
                return Err(std::io::Error::other(err));
            }
        }
    }
}

async fn serve_stream(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    ctx: ServeContext,
    client: String,
) -> std::io::Result<()> {
    let (head, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(std::io::Error::other)?;
    let (parts, ()) = head.into_parts();
    let request = Request::from_parts(&parts);

    // The same body ceiling the HTTP/1.1 and HTTP/2 paths enforce. Counting
    // as the chunks arrive (rather than trusting `content-length`) is what
    // makes the limit real on a protocol where the length header is advisory.
    let mut body = Vec::new();
    let mut oversized = false;
    while let Some(chunk) = stream.recv_data().await.map_err(std::io::Error::other)? {
        if oversized {
            continue;
        }
        let mut chunk = chunk;
        let remaining = chunk.remaining();
        if body.len() as u64 + remaining as u64 > MAX_REQUEST_BODY {
            oversized = true;
            body.clear();
            continue;
        }
        body.extend_from_slice(chunk.copy_to_bytes(remaining).as_ref());
    }

    let response = if oversized {
        super::dispatch_status(&ctx, &request, &client, 413, 0).await
    } else {
        super::dispatch(&ctx, &request, Bytes::from(body), &client, None).await
    };

    let head_only = request.method == "HEAD";
    let (parts, response_body) = response.into_parts();
    stream
        .send_response(http::Response::from_parts(parts, ()))
        .await
        .map_err(std::io::Error::other)?;

    // RFC 9110 §9.3.2: a HEAD response carries the headers a GET would have
    // produced but no body, so the body is dropped rather than streamed.
    if !head_only {
        let mut response_body = response_body;
        while let Some(frame) = response_body.frame().await {
            let frame = frame?;
            if let Ok(data) = frame.into_data() {
                stream
                    .send_data(data)
                    .await
                    .map_err(std::io::Error::other)?;
            }
        }
    }
    stream.finish().await.map_err(std::io::Error::other)?;
    Ok(())
}
