//! Response compression (IDEA.md "Response compression").
//!
//! Builtin and always on — there is no config toggle and no module to
//! enable, matching this project's "everything is builtin, there is no
//! module system" model. Negotiation is per response, from the request's
//! standard `Accept-Encoding` field, preferring `br` (Brotli) over `gzip`;
//! a client that advertises neither gets the response uncompressed, never
//! a forced encoding.
//!
//! Eligibility is deliberately narrow. Only text-shaped media types are
//! compressed — already-compressed binary payloads (images, video, audio,
//! archives, fonts) are served byte-for-byte as they are, because
//! recompressing them burns CPU for no size benefit. A `206 Partial
//! Content` response is never compressed either: `Range` is defined over
//! the representation's byte offsets, and compressing would move them, so
//! the two are mutually exclusive here exactly as they are in Apache and
//! nginx. A response that already carries its own `Content-Encoding` (a CGI
//! script or proxied upstream that compressed itself) is left alone.
//!
//! A compressed response always gains `Content-Encoding` and
//! `Vary: Accept-Encoding`, so a shared cache cannot hand a Brotli body to
//! a client that only speaks gzip. `Vary` is added even when the negotiated
//! answer is "no compression", because the response still varies by that
//! request header.

use std::io::Write;

use bytes::Bytes;
use http::header;
use hyper::Response;

use super::{full_body, Body};

/// The content codings this server can produce, in the preference order
/// IDEA.md specifies. Brotli wins over gzip whenever the client accepts
/// both, since it compresses text materially better at comparable cost for
/// the one-shot buffered bodies served here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Br,
    Gzip,
}

impl Encoding {
    /// The `Content-Encoding` token for this coding.
    pub fn token(self) -> &'static str {
        match self {
            Self::Br => "br",
            Self::Gzip => "gzip",
        }
    }
}

/// Bodies below this size are not worth compressing: framing overhead
/// (roughly 10 bytes for a gzip header/trailer, a few for Brotli) can make
/// a very short response grow, and the round trip is dominated by headers
/// anyway. nginx applies the same idea via `gzip_min_length`.
const MIN_COMPRESSIBLE_BODY: usize = 256;

/// Brotli quality/window/block parameters. Quality 5 is the standard
/// on-the-fly serving setting (nginx's `brotli_comp_level` default is 6 for
/// static, 5 is the common dynamic choice) — near-maximal ratio on text at
/// a fraction of the CPU of quality 11, which is meant for precompressed
/// assets, not per-request encoding. A 22-bit window is Brotli's default.
const BROTLI_QUALITY: u32 = 5;
const BROTLI_WINDOW: u32 = 22;
const BROTLI_BUFFER: usize = 4096;

/// Picks the best coding this server can produce from an `Accept-Encoding`
/// field value, honouring RFC 9110 §12.5.3 quality values: a coding with
/// `q=0` is explicitly rejected and never selected, and `*` acts as a
/// fallback for codings the field does not name outright.
///
/// Returns `None` when the client advertises nothing this server produces,
/// which is the "send it uncompressed" answer.
pub fn negotiate(accept_encoding: &str) -> Option<Encoding> {
    let mut wildcard: Option<f32> = None;
    let mut br: Option<f32> = None;
    let mut gzip: Option<f32> = None;

    for part in accept_encoding.split(',') {
        let mut fields = part.split(';');
        let Some(name) = fields.next() else { continue };
        let name = name.trim().to_ascii_lowercase();
        let mut quality = 1.0f32;
        for param in fields {
            let param = param.trim();
            if let Some(value) = param.strip_prefix("q=") {
                quality = value.trim().parse().unwrap_or(0.0);
            }
        }
        match name.as_str() {
            "br" => br = Some(quality),
            "gzip" | "x-gzip" => gzip = Some(quality),
            "*" => wildcard = Some(quality),
            _ => {}
        }
    }

    // An explicitly named coding always decides its own fate; only a coding
    // the field never mentions falls back to the wildcard.
    let acceptable = |explicit: Option<f32>| match explicit {
        Some(q) => q > 0.0,
        None => wildcard.is_some_and(|q| q > 0.0),
    };

    if acceptable(br) {
        Some(Encoding::Br)
    } else if acceptable(gzip) {
        Some(Encoding::Gzip)
    } else {
        None
    }
}

/// Whether a media type is worth compressing. Text-shaped types are (HTML,
/// CSS, JavaScript, JSON, XML, SVG, plain text, and the `+json`/`+xml`
/// structured-suffix families); everything else is assumed to be already
/// compressed and is passed through untouched.
pub fn is_compressible(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if essence.starts_with("text/") {
        return true;
    }
    if essence.ends_with("+json") || essence.ends_with("+xml") {
        return true;
    }
    matches!(
        essence.as_str(),
        "application/json"
            | "application/javascript"
            | "application/x-javascript"
            | "application/ecmascript"
            | "application/xml"
            | "application/xhtml+xml"
            | "application/rss+xml"
            | "application/atom+xml"
            | "application/manifest+json"
            | "application/wasm"
            | "image/svg+xml"
    )
}

/// Encodes `data` with `encoding`.
pub fn encode(encoding: Encoding, data: &[u8]) -> std::io::Result<Vec<u8>> {
    match encoding {
        Encoding::Gzip => {
            let mut writer =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            writer.write_all(data)?;
            writer.finish()
        }
        Encoding::Br => {
            let mut out = Vec::new();
            {
                let mut writer = brotli::CompressorWriter::new(
                    &mut out,
                    BROTLI_BUFFER,
                    BROTLI_QUALITY,
                    BROTLI_WINDOW,
                );
                writer.write_all(data)?;
            }
            Ok(out)
        }
    }
}

/// Applies content coding to an outgoing response in place, if and only if
/// every condition in this module's documentation holds. Anything that does
/// not qualify is left exactly as it was, so this is safe to call on every
/// response from every handler.
///
/// The body is replaced wholesale rather than wrapped in a streaming
/// encoder, which is why only fully-buffered bodies are eligible: a relayed
/// upstream body has no exact size hint and must not be collected into
/// memory, since its length is unbounded. That case is a documented gap
/// (see TODO.AI.md), not silent breakage — the response still goes out, it
/// just goes out uncompressed.
pub async fn maybe_compress(response: &mut Response<Body>, accept_encoding: Option<&str>) {
    // `Vary` is correct regardless of the outcome: the response body this
    // server produced does depend on `Accept-Encoding`, so a cache keyed
    // without it would eventually serve the wrong variant.
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !is_compressible(&content_type) {
        return;
    }
    add_vary(response);

    if response.headers().contains_key(header::CONTENT_ENCODING) {
        return;
    }
    // `206`/`416` are byte-offset answers over the uncompressed
    // representation; `304` and other bodiless statuses have nothing to
    // encode.
    let status = response.status().as_u16();
    if status == 206 || status == 416 || status == 304 || status == 204 {
        return;
    }

    let Some(encoding) = accept_encoding.and_then(negotiate) else {
        return;
    };

    use hyper::body::Body as _;
    let Some(exact) = response.body().size_hint().exact() else {
        return;
    };
    if (exact as usize) < MIN_COMPRESSIBLE_BODY {
        return;
    }

    use http_body_util::BodyExt;
    let body = std::mem::replace(response.body_mut(), full_body(Bytes::new()));
    let Ok(collected) = body.collect().await else {
        return;
    };
    let raw = collected.to_bytes();
    let Ok(encoded) = encode(encoding, &raw) else {
        // Re-attach the original bytes: a failed encode must never turn a
        // good response into an empty one.
        *response.body_mut() = full_body(raw);
        return;
    };
    if encoded.len() >= raw.len() {
        *response.body_mut() = full_body(raw);
        return;
    }

    let len = encoded.len();
    *response.body_mut() = full_body(Bytes::from(encoded));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_ENCODING,
        http::HeaderValue::from_static(encoding.token()),
    );
    // A `Content-Length` written by the handler (HEAD responses, CGI
    // passthrough) described the uncompressed body and is now wrong.
    if let Ok(value) = http::HeaderValue::from_str(&len.to_string()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }
    headers.remove(header::ACCEPT_RANGES);
}

/// Appends `Accept-Encoding` to `Vary` without clobbering a `Vary` the
/// handler already set (a proxied upstream commonly varies by `Origin` or
/// `Accept-Language` as well).
fn add_vary(response: &mut Response<Body>) {
    let existing = response
        .headers()
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if existing
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("accept-encoding"))
    {
        return;
    }
    let merged = if existing.trim().is_empty() {
        "Accept-Encoding".to_string()
    } else {
        format!("{existing}, Accept-Encoding")
    };
    if let Ok(value) = http::HeaderValue::from_str(&merged) {
        response.headers_mut().insert(header::VARY, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_response(body: &[u8]) -> Response<Body> {
        Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .body(full_body(Bytes::copy_from_slice(body)))
            .unwrap()
    }

    fn filler() -> Vec<u8> {
        "<p>cashttpd compression fixture</p>"
            .repeat(64)
            .into_bytes()
    }

    #[test]
    fn negotiate_prefers_brotli_over_gzip() {
        assert_eq!(negotiate("gzip, deflate, br"), Some(Encoding::Br));
        assert_eq!(negotiate("br;q=1.0, gzip;q=0.8"), Some(Encoding::Br));
    }

    #[test]
    fn negotiate_falls_back_to_gzip_when_brotli_is_absent_or_rejected() {
        assert_eq!(negotiate("gzip, deflate"), Some(Encoding::Gzip));
        assert_eq!(negotiate("br;q=0, gzip"), Some(Encoding::Gzip));
    }

    #[test]
    fn negotiate_returns_none_when_no_supported_coding_is_acceptable() {
        assert_eq!(negotiate(""), None);
        assert_eq!(negotiate("deflate, zstd"), None);
        assert_eq!(negotiate("br;q=0, gzip;q=0"), None);
        assert_eq!(negotiate("identity"), None);
    }

    #[test]
    fn negotiate_uses_wildcard_only_for_unnamed_codings() {
        assert_eq!(negotiate("*"), Some(Encoding::Br));
        assert_eq!(negotiate("br;q=0, *"), Some(Encoding::Gzip));
        assert_eq!(negotiate("*;q=0"), None);
    }

    #[test]
    fn compressible_types_are_text_shaped_only() {
        assert!(is_compressible("text/html; charset=utf-8"));
        assert!(is_compressible("application/json"));
        assert!(is_compressible("image/svg+xml"));
        assert!(is_compressible("application/vnd.api+json"));
        assert!(!is_compressible("image/png"));
        assert!(!is_compressible("video/mp4"));
        assert!(!is_compressible("font/woff2"));
        assert!(!is_compressible(""));
    }

    #[test]
    fn encoded_output_round_trips_for_both_codings() {
        let data = filler();
        let gz = encode(Encoding::Gzip, &data).unwrap();
        let mut decoded = Vec::new();
        {
            use std::io::Read;
            flate2::read::GzDecoder::new(&gz[..])
                .read_to_end(&mut decoded)
                .unwrap();
        }
        assert_eq!(decoded, data);

        let br = encode(Encoding::Br, &data).unwrap();
        let mut decoded = Vec::new();
        {
            use std::io::Read;
            brotli::Decompressor::new(&br[..], BROTLI_BUFFER)
                .read_to_end(&mut decoded)
                .unwrap();
        }
        assert_eq!(decoded, data);
    }

    #[tokio::test]
    async fn compressible_response_gains_content_encoding_and_vary() {
        let mut response = text_response(&filler());
        maybe_compress(&mut response, Some("gzip, br")).await;
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "br");
        assert_eq!(response.headers()[header::VARY], "Accept-Encoding");
    }

    #[tokio::test]
    async fn uncompressed_response_still_advertises_vary() {
        let mut response = text_response(&filler());
        maybe_compress(&mut response, None).await;
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(response.headers()[header::VARY], "Accept-Encoding");
    }

    #[tokio::test]
    async fn binary_content_type_is_never_compressed_or_varied() {
        let mut response = Response::builder()
            .status(200)
            .header("content-type", "image/png")
            .body(full_body(Bytes::from(filler())))
            .unwrap();
        maybe_compress(&mut response, Some("br, gzip")).await;
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
        assert!(!response.headers().contains_key(header::VARY));
    }

    #[tokio::test]
    async fn range_response_is_never_compressed() {
        let mut response = Response::builder()
            .status(206)
            .header("content-type", "text/plain; charset=utf-8")
            .header("content-range", "bytes 0-1023/4096")
            .body(full_body(Bytes::from(filler())))
            .unwrap();
        maybe_compress(&mut response, Some("br, gzip")).await;
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
    }

    #[tokio::test]
    async fn response_with_its_own_content_encoding_is_left_alone() {
        let mut response = Response::builder()
            .status(200)
            .header("content-type", "text/plain; charset=utf-8")
            .header("content-encoding", "gzip")
            .body(full_body(Bytes::from(filler())))
            .unwrap();
        maybe_compress(&mut response, Some("br")).await;
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");
    }

    #[tokio::test]
    async fn tiny_body_is_left_uncompressed() {
        let mut response = text_response(b"hi");
        maybe_compress(&mut response, Some("br, gzip")).await;
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
    }

    #[tokio::test]
    async fn compressed_body_decodes_back_to_the_original_bytes() {
        let data = filler();
        let mut response = text_response(&data);
        maybe_compress(&mut response, Some("gzip")).await;
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");
        use http_body_util::BodyExt;
        let sent = std::mem::replace(response.body_mut(), full_body(Bytes::new()))
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH],
            sent.len().to_string().as_str()
        );
        let mut decoded = Vec::new();
        {
            use std::io::Read;
            flate2::read::GzDecoder::new(&sent[..])
                .read_to_end(&mut decoded)
                .unwrap();
        }
        assert_eq!(decoded, data);
    }
}
