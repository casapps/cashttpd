//! TLS certificate resolution and connection termination (IDEA.md "TLS
//! certificate resolution"). Three-tier resolution, first match wins:
//!   1. an existing, currently-valid Let's Encrypt live cert for `{fqdn}`
//!      under `/etc/letsencrypt/live/**` (used in place, never copied);
//!   2. a fresh Let's Encrypt cert obtained via ACME v2 HTTP-01, only when
//!      `--listen` resolves to a public/routable address;
//!   3. a self-signed cert (10-year validity) generated with `rcgen`.
//!
//! Self-generated/obtained certs are stored under
//! `{data_dir}/certs/{derived_name}/`. This module never touches `base_dir`.
//!
//! The Let's-Encrypt-live-cert validity check and the ACME HTTP-01 client's
//! HTTP/1.1 framing are both hand-rolled rather than pulled in via
//! `x509-parser`/`ureq` — see the long comment above the `rustls` block in
//! `Cargo.toml` for why: this project's mandated Docker toolchain
//! (`casjaysdev/rust:latest`) cannot compile proc-macro crates at all
//! (`rustc -vV` reports a musl host), and both of those crates pull one in
//! transitively.

use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Either half of a connection this server terminates — a plain TCP socket,
/// or one wrapped in a TLS server session. Read/Write are delegated so the
/// rest of `server::mod` (request parsing, response writing, CGI plumbing)
/// stays oblivious to whether TLS is in play.
pub enum Conn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}

impl Conn {
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            Conn::Plain(s) => s.set_read_timeout(dur),
            Conn::Tls(s) => s.sock.set_read_timeout(dur),
        }
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// `{data_dir}/certs/{derived_name}/` — where self-generated/obtained certs
/// live (IDEA.md "TLS certificate resolution"). Never `base_dir`.
pub fn cert_dir(base_dir: &Path) -> PathBuf {
    crate::platform::paths::data_dir()
        .join("certs")
        .join(crate::config::derived_name(base_dir))
}

/// Builds the `rustls::ServerConfig` to terminate HTTPS with, running the
/// full three-tier resolution. Requires `fqdn` — callers must already have
/// enforced the `--fqdn`-required-when-`tls.enabled` fail-fast rule.
pub fn build_server_config(
    fqdn: &str,
    listen: &str,
    base_dir: &Path,
    log_warning: impl Fn(&str),
) -> io::Result<Arc<rustls::ServerConfig>> {
    let dir = cert_dir(base_dir);
    let (chain, key) = resolve_certificate(fqdn, listen, &dir, &log_warning)?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|err| io::Error::other(format!("invalid TLS certificate/key: {err}")))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn resolve_certificate(
    fqdn: &str,
    listen: &str,
    dir: &Path,
    log_warning: &impl Fn(&str),
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    if let Some(found) = scan_letsencrypt_live(fqdn) {
        if let Ok(loaded) = load_cert_key(&found.0, &found.1) {
            return Ok(loaded);
        }
        log_warning(&format!(
            "found Let's Encrypt live cert for {fqdn} but failed to load it; falling through"
        ));
    }

    if is_public_addr(listen) {
        match acme::obtain_certificate(fqdn, dir) {
            Ok(()) => {
                if let Ok(loaded) =
                    load_cert_key(&dir.join("fullchain.pem"), &dir.join("privkey.pem"))
                {
                    return Ok(loaded);
                }
            }
            Err(err) => {
                log_warning(&format!(
                    "ACME certificate request for {fqdn} failed ({err}); falling back to a self-signed certificate"
                ));
            }
        }
    }

    generate_self_signed(fqdn, dir)?;
    load_cert_key(&dir.join("fullchain.pem"), &dir.join("privkey.pem"))
}

/// Tier 1: scan `/etc/letsencrypt/live/**`, resolving each `live/{name}`
/// entry's symlinks (they point into `../../archive/{name}/`), and return
/// the `(fullchain, privkey)` paths for the first entry whose cert both
/// covers `fqdn` (by directory name — Certbot names live dirs after the
/// primary domain) and is currently valid.
fn scan_letsencrypt_live(fqdn: &str) -> Option<(PathBuf, PathBuf)> {
    let live_root = Path::new("/etc/letsencrypt/live");
    let entries = std::fs::read_dir(live_root).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name != fqdn {
            continue;
        }
        let dir = entry.path();
        let fullchain = dir.join("fullchain.pem");
        let privkey = dir.join("privkey.pem");
        let resolved_full = std::fs::canonicalize(&fullchain).ok()?;
        let resolved_key = std::fs::canonicalize(&privkey).ok()?;
        let pem = std::fs::read(&resolved_full).ok()?;
        let der = first_pem_cert_der(&pem)?;
        if cert_is_currently_valid(&der) {
            return Some((resolved_full, resolved_key));
        }
    }
    None
}

fn first_pem_cert_der(pem: &[u8]) -> Option<Vec<u8>> {
    let mut reader = std::io::Cursor::new(pem);
    match rustls_pemfile::certs(&mut reader).next() {
        Some(Ok(cert)) => Some(cert.as_ref().to_vec()),
        _ => None,
    }
}

fn load_cert_key(
    fullchain: &Path,
    privkey: &Path,
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_pem = std::fs::read(fullchain)?;
    let mut reader = std::io::Cursor::new(&cert_pem);
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|c| c.into_owned())
        .collect();
    if chain.is_empty() {
        return Err(io::Error::other("no certificates found in fullchain PEM"));
    }

    let key_pem = std::fs::read(privkey)?;
    let mut reader = std::io::Cursor::new(&key_pem);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| io::Error::other("no private key found in PEM"))?
        .clone_key();

    Ok((chain, key))
}

/// `true` when `listen` resolves to an address that could plausibly be
/// publicly reachable — not loopback, not link-local, not RFC 1918 / ULA
/// private space. Unspecified addresses (`0.0.0.0`, `::`) bind every local
/// interface, which may include a public one, so they count as eligible.
fn is_public_addr(listen: &str) -> bool {
    let trimmed = listen.trim_start_matches('[').trim_end_matches(']');
    let ip: IpAddr = match trimmed.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                return true;
            }
            !(v4.is_loopback() || v4.is_private() || v4.is_link_local())
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                return true;
            }
            let is_unique_local = (v6.segments()[0] & 0xfe00) == 0xfc00;
            let is_link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            !(v6.is_loopback() || is_unique_local || is_link_local)
        }
    }
}

/// Tier 3: a 10-year self-signed cert, saved to `dir/{fullchain,privkey}.pem`.
fn generate_self_signed(fqdn: &str, dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;

    let mut params = rcgen::CertificateParams::new(vec![fqdn.to_string()])
        .map_err(|err| io::Error::other(format!("invalid certificate params: {err}")))?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(3650);

    let key_pair = rcgen::KeyPair::generate()
        .map_err(|err| io::Error::other(format!("key generation failed: {err}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|err| io::Error::other(format!("self-signed cert generation failed: {err}")))?;

    write_private(&dir.join("fullchain.pem"), cert.pem().as_bytes())?;
    write_private(
        &dir.join("privkey.pem"),
        key_pair.serialize_pem().as_bytes(),
    )?;
    Ok(())
}

fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hand-rolled DER validity-date parsing (RFC 5280 `Validity`), used to
// decide whether a Let's-Encrypt-live cert found on disk is still usable
// without pulling in `x509-parser` (see module doc comment for why).
// ---------------------------------------------------------------------------

/// Reads one DER TLV at the front of `data`, returning `(tag, content,
/// remainder)`. Only supports the definite-length forms DER itself requires.
fn der_read_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *data.first()?;
    let len_byte = *data.get(1)?;
    let (len, header_len) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 2usize)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = data.get(2..2 + n)?;
        let mut len = 0usize;
        for b in bytes {
            len = (len << 8) | *b as usize;
        }
        (len, 2 + n)
    };
    let content = data.get(header_len..header_len + len)?;
    let rest = data.get(header_len + len..)?;
    Some((tag, content, rest))
}

/// Extracts `(not_before, not_after)` as Unix timestamps from a DER-encoded
/// X.509 certificate (RFC 5280 `Certificate` -> `TBSCertificate` ->
/// `Validity`).
fn parse_validity(cert_der: &[u8]) -> Option<(i64, i64)> {
    let (tag, cert_content, _) = der_read_tlv(cert_der)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, mut rest, _) = der_read_tlv(cert_content)?;
    if tag != 0x30 {
        return None;
    }
    // Optional `[0] EXPLICIT Version`.
    let (tag, _, next) = der_read_tlv(rest)?;
    if tag == 0xa0 {
        rest = next;
    }
    // serialNumber (INTEGER), signature (AlgorithmIdentifier SEQUENCE),
    // issuer (Name SEQUENCE) — skip all three positionally.
    let (_, _, rest) = der_read_tlv(rest)?;
    let (_, _, rest) = der_read_tlv(rest)?;
    let (_, _, rest) = der_read_tlv(rest)?;
    // validity (SEQUENCE of two Time values).
    let (tag, validity_content, _) = der_read_tlv(rest)?;
    if tag != 0x30 {
        return None;
    }
    let (tag_nb, nb_content, rest_v) = der_read_tlv(validity_content)?;
    let not_before = parse_asn1_time(tag_nb, nb_content)?;
    let (tag_na, na_content, _) = der_read_tlv(rest_v)?;
    let not_after = parse_asn1_time(tag_na, na_content)?;
    Some((not_before, not_after))
}

fn parse_asn1_time(tag: u8, content: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(content).ok()?;
    let s = s.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSS
            if s.len() != 12 {
                return None;
            }
            let yy: i64 = s.get(0..2)?.parse().ok()?;
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            (year, &s[2..])
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSS
            if s.len() != 14 {
                return None;
            }
            let year: i64 = s.get(0..4)?.parse().ok()?;
            (year, &s[4..])
        }
        _ => return None,
    };
    let month: u32 = rest.get(0..2)?.parse().ok()?;
    let day: u32 = rest.get(2..4)?.parse().ok()?;
    let hour: i64 = rest.get(4..6)?.parse().ok()?;
    let minute: i64 = rest.get(6..8)?.parse().ok()?;
    let second: i64 = rest.get(8..10)?.parse().ok()?;

    let days = days_from_civil(year, month, day);
    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

/// Howard Hinnant's `days_from_civil` — proleptic-Gregorian civil date to a
/// day count relative to the Unix epoch. The inverse of
/// `support::rotation::civil_date_from_unix`.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn cert_is_currently_valid(cert_der: &[u8]) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    match parse_validity(cert_der) {
        Some((not_before, not_after)) => now >= not_before && now <= not_after,
        None => false,
    }
}

// ---------------------------------------------------------------------------
// ACME v2 (RFC 8555) HTTP-01 client. Hand-rolled HTTPS request/response
// framing (see module doc comment for why `ureq` isn't used); JWS signing
// via `ring` (ECDSA P-256); JSON via `serde_json`; CSR generation via
// `rcgen`. Modeled on `server::parse_request`'s own hand-rolled HTTP/1.1
// framing.
// ---------------------------------------------------------------------------
mod acme {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    use serde_json::{Value, json};
    use std::collections::HashMap;

    const DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

    pub fn obtain_certificate(fqdn: &str, out_dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(out_dir)?;
        let rng = SystemRandom::new();
        let account_key_pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .map_err(|_| io::Error::other("ACME account key generation failed"))?;
        let account_key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            account_key_pkcs8.as_ref(),
            &rng,
        )
        .map_err(|_| io::Error::other("ACME account key load failed"))?;

        let directory = get_json(DIRECTORY_URL)?;
        let new_nonce_url = url_str(&directory, "newNonce")?;
        let new_account_url = url_str(&directory, "newAccount")?;
        let new_order_url = url_str(&directory, "newOrder")?;

        let mut nonce = fetch_nonce(&new_nonce_url)?;

        let jwk = jwk_from_key(&account_key)?;
        let account_payload = json!({ "termsOfServiceAgreed": true });
        let (status, body, next_nonce) = jws_post(
            &new_account_url,
            &account_key,
            &jwk,
            None,
            &nonce,
            &account_payload,
        )?;
        if !(200..300).contains(&status) {
            return Err(io::Error::other(format!(
                "ACME newAccount failed: HTTP {status} {}",
                String::from_utf8_lossy(&body)
            )));
        }
        nonce = next_nonce;

        let order_payload = json!({ "identifiers": [{ "type": "dns", "value": fqdn }] });
        let kid = new_account_url.clone();
        let (status, body, next_nonce) = jws_post(
            &new_order_url,
            &account_key,
            &jwk,
            Some(&kid),
            &nonce,
            &order_payload,
        )?;
        if !(200..300).contains(&status) {
            return Err(io::Error::other(format!(
                "ACME newOrder failed: HTTP {status} {}",
                String::from_utf8_lossy(&body)
            )));
        }
        nonce = next_nonce;
        let order: Value = serde_json::from_slice(&body)
            .map_err(|err| io::Error::other(format!("ACME newOrder response: {err}")))?;
        let authz_url = order["authorizations"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .ok_or_else(|| io::Error::other("ACME newOrder response missing authorizations"))?
            .to_string();
        let finalize_url = order["finalize"]
            .as_str()
            .ok_or_else(|| io::Error::other("ACME newOrder response missing finalize URL"))?
            .to_string();

        let (status, body, next_nonce) = jws_post_as_get(&authz_url, &account_key, &kid, &nonce)?;
        if !(200..300).contains(&status) {
            return Err(io::Error::other(format!(
                "ACME authorization fetch failed: HTTP {status} {}",
                String::from_utf8_lossy(&body)
            )));
        }
        nonce = next_nonce;
        let authz: Value = serde_json::from_slice(&body)
            .map_err(|err| io::Error::other(format!("ACME authorization response: {err}")))?;
        let challenge = authz["challenges"]
            .as_array()
            .and_then(|list| list.iter().find(|c| c["type"] == "http-01"))
            .ok_or_else(|| io::Error::other("ACME authorization has no http-01 challenge"))?;
        let token = challenge["token"]
            .as_str()
            .ok_or_else(|| io::Error::other("ACME challenge missing token"))?
            .to_string();
        let challenge_url = challenge["url"]
            .as_str()
            .ok_or_else(|| io::Error::other("ACME challenge missing url"))?
            .to_string();

        let thumbprint = jwk_thumbprint(&jwk);
        let key_authorization = format!("{token}.{thumbprint}");

        let challenge_server = serve_http01_challenge(&token, &key_authorization)?;
        let (status, body, next_nonce) = jws_post(
            &challenge_url,
            &account_key,
            &jwk,
            Some(&kid),
            &nonce,
            &json!({}),
        )?;
        if !(200..300).contains(&status) {
            drop(challenge_server);
            return Err(io::Error::other(format!(
                "ACME challenge trigger failed: HTTP {status} {}",
                String::from_utf8_lossy(&body)
            )));
        }
        nonce = next_nonce;

        let mut authz_status = String::new();
        for _ in 0..20 {
            std::thread::sleep(Duration::from_secs(2));
            let (status, body, next_nonce) =
                jws_post_as_get(&authz_url, &account_key, &kid, &nonce)?;
            nonce = next_nonce;
            if !(200..300).contains(&status) {
                continue;
            }
            let authz: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            authz_status = authz["status"].as_str().unwrap_or("").to_string();
            if authz_status == "valid" || authz_status == "invalid" {
                break;
            }
        }
        drop(challenge_server);
        if authz_status != "valid" {
            return Err(io::Error::other(format!(
                "ACME authorization did not become valid (status: {authz_status})"
            )));
        }

        let csr_params = rcgen::CertificateParams::new(vec![fqdn.to_string()])
            .map_err(|err| io::Error::other(format!("CSR params: {err}")))?;
        let cert_key = rcgen::KeyPair::generate()
            .map_err(|err| io::Error::other(format!("cert key generation: {err}")))?;
        let csr = csr_params
            .serialize_request(&cert_key)
            .map_err(|err| io::Error::other(format!("CSR generation: {err}")))?;
        let csr_b64 = base64_url(csr.der());

        let (status, body, next_nonce) = jws_post(
            &finalize_url,
            &account_key,
            &jwk,
            Some(&kid),
            &nonce,
            &json!({ "csr": csr_b64 }),
        )?;
        if !(200..300).contains(&status) {
            return Err(io::Error::other(format!(
                "ACME finalize failed: HTTP {status} {}",
                String::from_utf8_lossy(&body)
            )));
        }
        let mut nonce = next_nonce;

        let order_status_url = finalize_url.replace("/finalize/", "/order/");
        let mut cert_url = String::new();
        let mut finalize_body = body;
        for _ in 0..20 {
            let finalized: Value = serde_json::from_slice(&finalize_body).unwrap_or(Value::Null);
            if let Some(url) = finalized["certificate"].as_str() {
                cert_url = url.to_string();
                break;
            }
            std::thread::sleep(Duration::from_secs(2));
            let (_status, poll_body, next_nonce) =
                jws_post_as_get(&order_status_url, &account_key, &kid, &nonce)?;
            nonce = next_nonce;
            finalize_body = poll_body;
        }
        if cert_url.is_empty() {
            return Err(io::Error::other(
                "ACME order never produced a certificate URL",
            ));
        }

        let (status, cert_body, _) = jws_post_as_get(&cert_url, &account_key, &kid, &nonce)?;
        if !(200..300).contains(&status) {
            return Err(io::Error::other(format!(
                "ACME certificate download failed: HTTP {status}"
            )));
        }

        super::write_private(&out_dir.join("fullchain.pem"), &cert_body)?;
        super::write_private(
            &out_dir.join("privkey.pem"),
            cert_key.serialize_pem().as_bytes(),
        )?;
        Ok(())
    }

    /// Binds port 80 and answers exactly the well-known HTTP-01 challenge
    /// path in a background thread until the returned guard is dropped.
    fn serve_http01_challenge(token: &str, key_authorization: &str) -> io::Result<ChallengeGuard> {
        let listener = TcpListener::bind(("0.0.0.0", 80))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let token = token.to_string();
        let key_authorization = key_authorization.to_string();
        let expected_path = format!("/.well-known/acme-challenge/{token}");
        let handle = std::thread::spawn(move || {
            while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                        let mut buf = [0u8; 2048];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let matched = req
                            .lines()
                            .next()
                            .map(|line| line.contains(&expected_path))
                            .unwrap_or(false);
                        let response = if matched {
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                key_authorization.len(),
                                key_authorization
                            )
                        } else {
                            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                .to_string()
                        };
                        stream.write_all(response.as_bytes()).ok();
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(ChallengeGuard {
            stop,
            handle: Some(handle),
        })
    }

    struct ChallengeGuard {
        stop: Arc<std::sync::atomic::AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for ChallengeGuard {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                handle.join().ok();
            }
        }
    }

    fn url_str(directory: &Value, key: &str) -> io::Result<String> {
        directory[key]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| io::Error::other(format!("ACME directory missing '{key}'")))
    }

    fn get_json(url: &str) -> io::Result<Value> {
        let (status, _headers, body) = https_request(url, "GET", None, &[])?;
        if !(200..300).contains(&status) {
            return Err(io::Error::other(format!("GET {url} failed: HTTP {status}")));
        }
        serde_json::from_slice(&body)
            .map_err(|err| io::Error::other(format!("invalid JSON from {url}: {err}")))
    }

    fn fetch_nonce(new_nonce_url: &str) -> io::Result<String> {
        let (status, headers, _body) = https_request(new_nonce_url, "HEAD", None, &[])?;
        if !(200..300).contains(&status) {
            return Err(io::Error::other("ACME newNonce failed"));
        }
        headers
            .get("replay-nonce")
            .cloned()
            .ok_or_else(|| io::Error::other("ACME newNonce response missing Replay-Nonce"))
    }

    fn jwk_from_key(key: &EcdsaKeyPair) -> io::Result<Value> {
        let pub_key = key.public_key().as_ref();
        // Uncompressed SEC1 point: 0x04 || X(32) || Y(32).
        if pub_key.len() != 65 || pub_key[0] != 0x04 {
            return Err(io::Error::other("unexpected ECDSA public key encoding"));
        }
        let x = base64_url(&pub_key[1..33]);
        let y = base64_url(&pub_key[33..65]);
        Ok(json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y }))
    }

    fn jwk_thumbprint(jwk: &Value) -> String {
        // RFC 7638: JCS-canonical JSON of required members only, in this
        // exact key order, SHA-256 hashed then base64url-encoded.
        let canonical = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            jwk["x"].as_str().unwrap_or_default(),
            jwk["y"].as_str().unwrap_or_default()
        );
        let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
        base64_url(digest.as_ref())
    }

    fn base64_url(data: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    }

    fn sign_jws(key: &EcdsaKeyPair, protected: &Value, payload: &str) -> io::Result<Value> {
        let protected_b64 = base64_url(protected.to_string().as_bytes());
        let signing_input = format!("{protected_b64}.{payload}");
        let rng = SystemRandom::new();
        let signature = key
            .sign(&rng, signing_input.as_bytes())
            .map_err(|_| io::Error::other("JWS signing failed"))?;
        Ok(json!({
            "protected": protected_b64,
            "payload": payload,
            "signature": base64_url(signature.as_ref()),
        }))
    }

    /// Sends a JWS-signed POST, returning `(status, body, next_nonce)`. When
    /// `kid` is `None` the request is signed with the embedded `jwk` (only
    /// valid for `newAccount`); otherwise signed with `kid`.
    fn jws_post(
        url: &str,
        key: &EcdsaKeyPair,
        jwk: &Value,
        kid: Option<&str>,
        nonce: &str,
        payload: &Value,
    ) -> io::Result<(u16, Vec<u8>, String)> {
        let mut protected = json!({ "alg": "ES256", "nonce": nonce, "url": url });
        if let Some(kid) = kid {
            protected["kid"] = json!(kid);
        } else {
            protected["jwk"] = jwk.clone();
        }
        let payload_b64 = base64_url(payload.to_string().as_bytes());
        let jws = sign_jws(key, &protected, &payload_b64)?;
        let body = jws.to_string();
        let (status, headers, resp_body) = https_request(
            url,
            "POST",
            Some(body.as_bytes()),
            &[("Content-Type", "application/jose+json")],
        )?;
        let next_nonce = headers
            .get("replay-nonce")
            .cloned()
            .unwrap_or_else(|| nonce.to_string());
        Ok((status, resp_body, next_nonce))
    }

    /// POST-as-GET (RFC 8555 6.3): JWS-signed POST with an empty string
    /// payload, used to fetch authenticated resources.
    fn jws_post_as_get(
        url: &str,
        key: &EcdsaKeyPair,
        kid: &str,
        nonce: &str,
    ) -> io::Result<(u16, Vec<u8>, String)> {
        let protected = json!({ "alg": "ES256", "nonce": nonce, "url": url, "kid": kid });
        let payload_b64 = String::new();
        let jws = sign_jws(key, &protected, &payload_b64)?;
        let body = jws.to_string();
        let (status, headers, resp_body) = https_request(
            url,
            "POST",
            Some(body.as_bytes()),
            &[("Content-Type", "application/jose+json")],
        )?;
        let next_nonce = headers
            .get("replay-nonce")
            .cloned()
            .unwrap_or_else(|| nonce.to_string());
        Ok((status, resp_body, next_nonce))
    }

    /// A single hand-rolled HTTPS request over `rustls::ClientConnection` +
    /// `TcpStream` (mirrors `server::parse_request`'s own HTTP/1.1 framing).
    /// Always opens a fresh connection and sends `Connection: close`.
    fn https_request(
        url: &str,
        method: &str,
        body: Option<&[u8]>,
        extra_headers: &[(&str, &str)],
    ) -> io::Result<(u16, HashMap<String, String>, Vec<u8>)> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| io::Error::other("only https:// URLs are supported"))?;
        let (host_port, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        let (host, port) = match host_port.split_once(':') {
            Some((h, p)) => (h, p.parse().unwrap_or(443)),
            None => (host_port, 443),
        };

        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let server_name = host
            .to_string()
            .try_into()
            .map_err(|_| io::Error::other("invalid TLS server name"))?;
        let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|err| io::Error::other(format!("TLS setup failed: {err}")))?;
        let sock = TcpStream::connect((host, port))?;
        sock.set_read_timeout(Some(Duration::from_secs(30)))?;
        let mut tls = rustls::StreamOwned::new(conn, sock);

        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
        for (k, v) in extra_headers {
            request.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some(body) = body {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        request.push_str("\r\n");
        tls.write_all(request.as_bytes())?;
        if let Some(body) = body {
            tls.write_all(body)?;
        }

        let mut raw = Vec::new();
        tls.read_to_end(&mut raw).ok();
        parse_http_response(&raw)
    }

    fn parse_http_response(raw: &[u8]) -> io::Result<(u16, HashMap<String, String>, Vec<u8>)> {
        let header_end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| io::Error::other("malformed HTTP response (no header terminator)"))?;
        let header_text = String::from_utf8_lossy(&raw[..header_end]);
        let mut lines = header_text.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io::Error::other("malformed HTTP status line"))?;

        let mut headers = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        let mut body = raw[header_end + 4..].to_vec();
        if headers
            .get("transfer-encoding")
            .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
        {
            body = dechunk(&body);
        } else if let Some(len) = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
        {
            body.truncate(len);
        }
        Ok((status, headers, body))
    }

    fn dechunk(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = data;
        while let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") {
            let size_str = String::from_utf8_lossy(&rest[..line_end]);
            let size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);
            if size == 0 {
                break;
            }
            let chunk_start = line_end + 2;
            let chunk_end = chunk_start + size;
            if chunk_end > rest.len() {
                break;
            }
            out.extend_from_slice(&rest[chunk_start..chunk_end]);
            rest = &rest[(chunk_end + 2).min(rest.len())..];
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_public_addr_rejects_loopback_and_private() {
        assert!(!is_public_addr("127.0.0.1"));
        assert!(!is_public_addr("::1"));
        assert!(!is_public_addr("10.0.0.5"));
        assert!(!is_public_addr("172.16.0.5"));
        assert!(!is_public_addr("192.168.1.5"));
        assert!(!is_public_addr("169.254.1.1"));
        assert!(!is_public_addr("fe80::1"));
        assert!(!is_public_addr("fc00::1"));
    }

    #[test]
    fn is_public_addr_accepts_unspecified_and_public() {
        assert!(is_public_addr("0.0.0.0"));
        assert!(is_public_addr("::"));
        assert!(is_public_addr("203.0.113.5"));
        assert!(is_public_addr("2001:db8::1"));
    }

    #[test]
    fn is_public_addr_rejects_unparsable() {
        assert!(!is_public_addr("not-an-ip"));
    }

    #[test]
    fn days_from_civil_matches_known_epoch_offsets() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
    }

    #[test]
    fn parse_asn1_time_reads_utc_and_generalized() {
        // 2024-01-15T10:20:30Z via UTCTime.
        let utc = parse_asn1_time(0x17, b"240115102030Z");
        assert_eq!(utc, Some(1705314030));
        // Same instant via GeneralizedTime.
        let generalized = parse_asn1_time(0x18, b"20240115102030Z");
        assert_eq!(generalized, utc);
    }

    #[test]
    fn parse_asn1_time_rejects_malformed_input() {
        assert_eq!(parse_asn1_time(0x17, b"not-a-time!!"), None);
        assert_eq!(parse_asn1_time(0x19, b"240115102030"), None);
    }

    #[test]
    fn self_signed_cert_round_trips_and_parses_as_valid() {
        let dir = std::env::temp_dir().join(format!("cashttpd-tls-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        generate_self_signed("example.test", &dir).unwrap();

        let (chain, _key) =
            load_cert_key(&dir.join("fullchain.pem"), &dir.join("privkey.pem")).unwrap();
        assert!(!chain.is_empty());
        assert!(cert_is_currently_valid(chain[0].as_ref()));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cert_dir_is_scoped_under_data_dir_certs() {
        let dir = cert_dir(Path::new("/tmp/some-project"));
        assert!(dir.to_string_lossy().contains("certs"));
    }
}
