//! Default response headers: security headers, the `Server` header, and
//! CORS (IDEA.md "Default security headers").
//!
//! All three are builtin and on by default — there is no module to enable,
//! matching this project's "everything is builtin" model. The effective
//! header sets are resolved once at config-load time
//! (`crate::configs::load`, which merges `security_headers`/`server_tokens`/
//! `cors` over the built-in defaults), so this module only decides *whether*
//! to attach an already-resolved header to a given response and computes the
//! one part that genuinely depends on the request: the CORS preflight echo.
//!
//! The governing rule for every header here is that the response wins: a
//! header a CGI script, an SSI page, or a proxied upstream already set is
//! never overwritten. That is what keeps a script able to send its own
//! `X-Frame-Options: DENY` or a stricter `Referrer-Policy` without the
//! server silently reverting it.
//!
//! Deliberately *not* set by default, and documented as such in IDEA.md:
//! `Content-Security-Policy` and `X-XSS-Protection` (the former needs
//! per-project tuning to avoid breaking framework dev tooling, the latter is
//! a removed browser feature), and any `Cache-Control`/`Expires` — a
//! stale-cached asset fights the edit-and-reload workflow this project
//! exists for. All three are addable through the `security_headers` config
//! key, which despite its name is the general per-header override mechanism.

use bytes::Bytes;
use http::header;
use hyper::Response;

use super::{full_body, Body, Request, ServeOptions};

/// Header a browser sends on a CORS preflight to announce the method the
/// real request will use; its presence is what makes an `OPTIONS` a
/// preflight rather than an ordinary capability query.
const REQUEST_METHOD: &str = "access-control-request-method";
/// Companion preflight header announcing the non-simple request headers the
/// real request will carry.
const REQUEST_HEADERS: &str = "access-control-request-headers";

/// Answers a CORS preflight directly (IDEA.md "Default security headers" →
/// "CORS"): an `OPTIONS` carrying `Access-Control-Request-Method` never
/// names a resource to act on, so it is answered before path resolution with
/// `204 No Content` and the echo headers `apply` attaches.
///
/// Without this, a preflight would fall through to the static/script
/// pipeline and be answered `405 Method Not Allowed`, which browsers treat
/// as a failed preflight and which would make the permissive default
/// useless in practice. Returns `None` when CORS is disabled (`cors: false`)
/// or the request is not a preflight, leaving the normal pipeline to handle
/// it.
pub fn preflight_response(request: &Request, opts: &ServeOptions) -> Option<Response<Body>> {
    if opts.cors.is_none() || request.method != "OPTIONS" {
        return None;
    }
    if !request.headers.contains_key(REQUEST_METHOD) {
        return None;
    }
    let mut response = Response::new(full_body(Bytes::new()));
    *response.status_mut() = hyper::StatusCode::NO_CONTENT;
    Some(response)
}

/// Attaches the effective default headers to an outgoing response: the
/// resolved `security_headers` set (which includes `Server` and, when TLS is
/// on, `Strict-Transport-Security`), then the CORS headers and the
/// request-dependent preflight echo. Every insertion is conditional on the
/// header being absent, per the response-wins rule above.
pub fn apply(response: &mut Response<Body>, request: &Request, opts: &ServeOptions) {
    for (name, value) in &opts.security_headers {
        insert_if_absent(response, name, value);
    }

    let Some(cors) = &opts.cors else {
        return;
    };
    for (name, value) in cors {
        insert_if_absent(response, name, value);
    }

    // The preflight echo mirrors exactly what the browser asked for rather
    // than advertising a fixed list, which is what makes the default
    // permissive without the server having to know a project's routes. It
    // is only meaningful on a preflight, so it is keyed on the presence of
    // the request headers, not on the method.
    if let Some(methods) = request.headers.get(REQUEST_METHOD) {
        insert_if_absent(response, "Access-Control-Allow-Methods", methods);
    }
    if let Some(requested) = request.headers.get(REQUEST_HEADERS) {
        insert_if_absent(response, "Access-Control-Allow-Headers", requested);
    }
}

/// Sets one header only when the response does not already carry it, and
/// only when both name and value are representable on the wire — an
/// unrepresentable override from a config file is skipped rather than
/// panicking or truncating the response.
fn insert_if_absent(response: &mut Response<Body>, name: &str, value: &str) {
    let Ok(name) = header::HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    if response.headers().contains_key(&name) {
        return;
    }
    let Ok(value) = header::HeaderValue::from_str(value) else {
        return;
    };
    response.headers_mut().insert(name, value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configs::{builtin_cors_headers, builtin_security_headers, ServerTokens};
    use std::collections::HashMap;

    fn options(tls: bool, tokens: ServerTokens) -> ServeOptions {
        let mut opts = super::super::fallback_defaults();
        opts.tls_enabled = tls;
        opts.security_headers = builtin_security_headers(tls, tokens);
        opts.cors = Some(builtin_cors_headers());
        opts
    }

    fn request(method: &str, headers: &[(&str, &str)]) -> Request {
        Request {
            method: method.to_string(),
            path: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<String, String>>(),
        }
    }

    fn response() -> Response<Body> {
        Response::new(full_body(Bytes::from_static(b"body")))
    }

    #[test]
    fn defaults_are_present_on_a_plain_http_response() {
        let mut r = response();
        apply(
            &mut r,
            &request("GET", &[]),
            &options(false, ServerTokens::Full),
        );
        assert_eq!(r.headers()["x-content-type-options"], "nosniff");
        assert_eq!(r.headers()["x-frame-options"], "SAMEORIGIN");
        assert_eq!(r.headers()["referrer-policy"], "no-referrer-when-downgrade");
        assert!(r.headers().contains_key("server"));
    }

    #[test]
    fn csp_xss_and_cache_control_are_never_defaulted() {
        let mut r = response();
        apply(
            &mut r,
            &request("GET", &[]),
            &options(false, ServerTokens::Full),
        );
        assert!(!r.headers().contains_key("content-security-policy"));
        assert!(!r.headers().contains_key("x-xss-protection"));
        assert!(!r.headers().contains_key("cache-control"));
        assert!(!r.headers().contains_key("expires"));
    }

    #[test]
    fn hsts_is_added_only_when_tls_is_enabled() {
        let mut plain = response();
        apply(
            &mut plain,
            &request("GET", &[]),
            &options(false, ServerTokens::Full),
        );
        assert!(!plain.headers().contains_key("strict-transport-security"));

        let mut secure = response();
        apply(
            &mut secure,
            &request("GET", &[]),
            &options(true, ServerTokens::Full),
        );
        assert_eq!(
            secure.headers()["strict-transport-security"],
            "max-age=31536000; includeSubDomains"
        );
    }

    #[test]
    fn a_header_the_response_already_set_is_never_overwritten() {
        let mut r = response();
        r.headers_mut()
            .insert("x-frame-options", header::HeaderValue::from_static("DENY"));
        r.headers_mut()
            .insert("server", header::HeaderValue::from_static("upstream/1.0"));
        apply(
            &mut r,
            &request("GET", &[]),
            &options(false, ServerTokens::Full),
        );
        assert_eq!(r.headers()["x-frame-options"], "DENY");
        assert_eq!(r.headers()["server"], "upstream/1.0");
    }

    #[test]
    fn security_headers_override_removes_a_default() {
        let mut opts = options(false, ServerTokens::Full);
        opts.security_headers.remove("Server");
        opts.security_headers
            .insert("X-Frame-Options".to_string(), "DENY".to_string());
        let mut r = response();
        apply(&mut r, &request("GET", &[]), &opts);
        assert!(!r.headers().contains_key("server"));
        assert_eq!(r.headers()["x-frame-options"], "DENY");
    }

    #[test]
    fn cors_default_is_permissive_and_never_credentialed() {
        let mut r = response();
        apply(
            &mut r,
            &request("GET", &[]),
            &options(false, ServerTokens::Full),
        );
        assert_eq!(r.headers()["access-control-allow-origin"], "*");
        assert!(!r.headers().contains_key("access-control-allow-credentials"));
    }

    #[test]
    fn cors_disabled_emits_no_cors_headers() {
        let mut opts = options(false, ServerTokens::Full);
        opts.cors = None;
        let mut r = response();
        apply(&mut r, &request("GET", &[]), &opts);
        assert!(!r.headers().contains_key("access-control-allow-origin"));
    }

    #[test]
    fn preflight_echoes_the_requested_method_and_headers() {
        let opts = options(false, ServerTokens::Full);
        let req = request(
            "OPTIONS",
            &[
                (REQUEST_METHOD, "PUT"),
                (REQUEST_HEADERS, "content-type, x-token"),
            ],
        );
        let mut r = preflight_response(&req, &opts).expect("preflight is answered directly");
        assert_eq!(r.status(), 204);
        apply(&mut r, &req, &opts);
        assert_eq!(r.headers()["access-control-allow-methods"], "PUT");
        assert_eq!(
            r.headers()["access-control-allow-headers"],
            "content-type, x-token"
        );
    }

    #[test]
    fn a_plain_options_request_is_not_treated_as_a_preflight() {
        let opts = options(false, ServerTokens::Full);
        assert!(preflight_response(&request("OPTIONS", &[]), &opts).is_none());
        assert!(preflight_response(&request("GET", &[(REQUEST_METHOD, "PUT")]), &opts).is_none());
    }

    #[test]
    fn preflight_is_not_answered_when_cors_is_disabled() {
        let mut opts = options(false, ServerTokens::Full);
        opts.cors = None;
        let req = request("OPTIONS", &[(REQUEST_METHOD, "PUT")]);
        assert!(preflight_response(&req, &opts).is_none());
    }

    #[test]
    fn server_tokens_levels_render_apaches_exact_verbosity_ladder() {
        let version = crate::supports::version::VERSION;
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        let mut parts = version.split('.');
        let major = parts.next().unwrap_or("0");
        let minor = parts.next().unwrap_or("0");

        assert_eq!(
            ServerTokens::Full.header_value(),
            format!("cashttpd/{version} ({os}; {arch})")
        );
        assert_eq!(
            ServerTokens::Os.header_value(),
            format!("cashttpd/{version} ({os})")
        );
        assert_eq!(
            ServerTokens::Minor.header_value(),
            format!("cashttpd/{major}.{minor}")
        );
        assert_eq!(
            ServerTokens::Major.header_value(),
            format!("cashttpd/{major}")
        );
        assert_eq!(
            ServerTokens::Min.header_value(),
            format!("cashttpd/{version}")
        );
        assert_eq!(ServerTokens::Prod.header_value(), "cashttpd");
    }

    #[test]
    fn server_tokens_parse_is_case_insensitive_and_defaults_to_full() {
        assert_eq!(ServerTokens::parse("prod"), ServerTokens::Prod);
        assert_eq!(ServerTokens::parse("ProductOnly"), ServerTokens::Prod);
        assert_eq!(ServerTokens::parse("  MIN "), ServerTokens::Min);
        assert_eq!(ServerTokens::parse("os"), ServerTokens::Os);
        assert_eq!(ServerTokens::parse("nonsense"), ServerTokens::Full);
    }

    #[test]
    fn resolved_server_header_follows_server_tokens() {
        let mut r = response();
        apply(
            &mut r,
            &request("GET", &[]),
            &options(false, ServerTokens::Prod),
        );
        assert_eq!(r.headers()["server"], "cashttpd");
    }
}
