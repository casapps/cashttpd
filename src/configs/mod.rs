//! Configuration loading and defaults (IDEA.md "Configuration file",
//! "CLI flags (full reference)"). Layering: CLI flag > environment variable
//! > per-project config > global config > built-in default.
//!
//! Parses/emits YAML via `serde_yaml::Value` directly rather than
//! `#[derive(Deserialize)]` — this project's toolchain container
//! (`casjaysdev/rust:latest`) has a musl host target that cannot build
//! proc-macro crate types, so `serde_derive` is unusable here.
//!
//! Live reload (re-watching the global/per-project files while `serve` is
//! running and hot-applying changes, including listener rebind) is
//! implemented in `crate::servers::run` via mtime polling of the same two
//! files this module loads — `load()` itself is reused verbatim for each
//! reload (see `config_paths` below for the path-derivation logic the
//! watcher shares with it). This module covers load-time layering,
//! autogeneration, and `--config-test` syntax validation.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_yaml::Value;

/// One raw YAML config layer (global or per-project) — every key optional
/// so unset keys fall through to the next layer, per IDEA.md's precedence
/// rule. Mirrors the "Full schema" table in IDEA.md "Configuration file".
#[derive(Debug, Default, Clone)]
pub struct Layer {
    pub base_dir: Option<PathBuf>,
    pub listen: Option<String>,
    pub port: Option<u16>,
    pub log_dir: Option<PathBuf>,
    pub debug: Option<bool>,
    pub fqdn: Option<String>,
    pub tls_enabled: Option<bool>,
    pub directory_listing: Option<bool>,
    pub mime_types: BTreeMap<String, String>,
    pub script_handlers: BTreeMap<String, Option<String>>,
    pub ssi_extensions: Option<Vec<String>>,
    pub security_headers: BTreeMap<String, Option<String>>,
    pub server_tokens: Option<String>,
    pub cors: Option<CorsLayer>,
    pub proxy: ProxyLayer,
    pub logging_access: LogStreamLayer,
    pub logging_error: LogStreamLayer,
}

/// The `cors` config key's two shapes (IDEA.md "Default security headers" →
/// "CORS"): a header map that overrides/adds to the permissive built-in set,
/// or the literal `false`, which disables CORS response headers entirely.
/// A missing key is `None` on the `Layer` and falls through to the next
/// layer — distinct from `Some(CorsLayer::Disabled)`, which is an explicit
/// "off" that the lower layer must not undo.
#[derive(Debug, Clone)]
pub enum CorsLayer {
    Disabled,
    Headers(BTreeMap<String, Option<String>>),
}

#[derive(Debug, Default, Clone)]
pub struct ProxyLayer {
    pub enabled: Option<bool>,
    pub kind: Option<String>,
    pub command: Option<String>,
    pub upstream: Option<String>,
    pub path_prefix: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct LogStreamLayer {
    pub format: Option<String>,
    pub rotate: Option<String>,
    pub keep: Option<String>,
}

fn s(v: &Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(str::to_string)
}
fn b(v: &Value, key: &str) -> Option<bool> {
    v.get(key)?.as_bool()
}
fn u16_val(v: &Value, key: &str) -> Option<u16> {
    v.get(key)?.as_u64().and_then(|n| u16::try_from(n).ok())
}
fn path_val(v: &Value, key: &str) -> Option<PathBuf> {
    s(v, key).map(PathBuf::from)
}
fn str_map(v: &Value, key: &str) -> BTreeMap<String, String> {
    v.get(key)
        .and_then(Value::as_mapping)
        .map(|m| {
            m.iter()
                .filter_map(|(k, val)| Some((k.as_str()?.to_string(), val.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default()
}
fn opt_str_map(v: &Value, key: &str) -> BTreeMap<String, Option<String>> {
    v.get(key)
        .and_then(Value::as_mapping)
        .map(|m| {
            m.iter()
                .filter_map(|(k, val)| {
                    let key = k.as_str()?.to_string();
                    Some((key, val.as_str().map(str::to_string)))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn str_list(v: &Value, key: &str) -> Option<Vec<String>> {
    let seq = v.get(key)?.as_sequence()?;
    Some(
        seq.iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
    )
}

fn cors_layer(v: &Value) -> Option<CorsLayer> {
    let raw = v.get("cors")?;
    if raw.as_bool() == Some(false) {
        return Some(CorsLayer::Disabled);
    }
    // `cors: true` is accepted as a synonym for "keep the permissive
    // built-in set" so a config that spells the toggle out explicitly still
    // parses, rather than being silently read as an empty override map.
    if raw.as_bool() == Some(true) {
        return Some(CorsLayer::Headers(BTreeMap::new()));
    }
    raw.as_mapping().map(|m| {
        CorsLayer::Headers(
            m.iter()
                .filter_map(|(k, val)| {
                    Some((k.as_str()?.to_string(), val.as_str().map(str::to_string)))
                })
                .collect(),
        )
    })
}

/// Built-in Server-Side Includes extension list (IDEA.md "Server-Side
/// Includes (SSI)"). The `ssi_extensions` config key adds to this list, with
/// an empty list as the documented way to disable SSI entirely for a project
/// (see the merge in `load`).
pub fn builtin_ssi_extensions() -> Vec<String> {
    vec![".shtml".to_string()]
}

/// The `Server` response header's verbosity, mirroring Apache's
/// `ServerTokens` directive and its exact option set (IDEA.md "Default
/// security headers" → "`Server` header").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerTokens {
    Full,
    Os,
    Minor,
    Major,
    Min,
    Prod,
}

impl ServerTokens {
    /// Parses a config value case-insensitively. Apache's `ProductOnly` is
    /// accepted as the documented alias for `Prod`. An unrecognized value
    /// falls back to the `Full` default rather than failing startup, since
    /// a typo here must not take a local dev server down.
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "os" => Self::Os,
            "minor" => Self::Minor,
            "major" => Self::Major,
            "min" => Self::Min,
            "prod" | "productonly" => Self::Prod,
            _ => Self::Full,
        }
    }

    /// Renders the `Server` header value for this verbosity level. `{os}`
    /// and `{arch}` come from the compile-time target triple constants, so
    /// they describe the binary that is actually running.
    pub fn header_value(self) -> String {
        let version = crate::supports::version::VERSION;
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        let mut parts = version.split('.');
        let major = parts.next().unwrap_or("0");
        let minor = parts.next().unwrap_or("0");
        match self {
            Self::Full => format!("cashttpd/{version} ({os}; {arch})"),
            Self::Os => format!("cashttpd/{version} ({os})"),
            Self::Minor => format!("cashttpd/{major}.{minor}"),
            Self::Major => format!("cashttpd/{major}"),
            Self::Min => format!("cashttpd/{version}"),
            Self::Prod => "cashttpd".to_string(),
        }
    }
}

/// Built-in response headers set on every response unless the response
/// already carries them (IDEA.md "Default security headers"). `Server` is
/// part of this set so the `security_headers` override mechanism is the one
/// way to change or remove any default header, including it.
///
/// `Strict-Transport-Security` is included only when TLS is on — HSTS on a
/// plain-HTTP response is meaningless and actively wrong.
/// `Content-Security-Policy` and `X-XSS-Protection` are deliberately absent:
/// CSP needs per-project tuning to avoid breaking framework dev tooling, and
/// `X-XSS-Protection` is a removed browser feature. Both are addable through
/// `security_headers`.
pub fn builtin_security_headers(
    tls_enabled: bool,
    server_tokens: ServerTokens,
) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("Server".to_string(), server_tokens.header_value());
    m.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
    m.insert("X-Frame-Options".to_string(), "SAMEORIGIN".to_string());
    m.insert(
        "Referrer-Policy".to_string(),
        "no-referrer-when-downgrade".to_string(),
    );
    if tls_enabled {
        m.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000; includeSubDomains".to_string(),
        );
    }
    m
}

/// Built-in permissive CORS response headers (IDEA.md "Default security
/// headers" → "CORS"). Only the wildcard origin is unconditional; the
/// preflight `Access-Control-Allow-Methods`/`-Headers` echo is request-
/// dependent and is added by `crate::servers::headers` at response time.
/// `Access-Control-Allow-Credentials` is deliberately absent — `true`
/// combined with a wildcard origin is invalid per the Fetch spec and
/// browsers reject the response outright.
pub fn builtin_cors_headers() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("Access-Control-Allow-Origin".to_string(), "*".to_string());
    m
}

/// Applies one override layer's `name -> value | null` map onto a resolved
/// header map: a value replaces or adds the header, and an empty/`null`
/// value removes it. Shared by `security_headers` and `cors`, which IDEA.md
/// documents as using the same override-merge pattern.
///
/// Matching against the built-in set is case-insensitive because HTTP field
/// names are (RFC 9110 §5.1) — `server: null` in a config file has to remove
/// the same header `Server` added, not add a second one. The built-in
/// spelling is kept when a key matches an existing one so the wire output
/// stays canonically cased.
fn merge_header_overrides(
    base: &mut BTreeMap<String, String>,
    overrides: &BTreeMap<String, Option<String>>,
) {
    for (name, value) in overrides {
        let existing = base
            .keys()
            .find(|k| k.eq_ignore_ascii_case(name))
            .cloned()
            .unwrap_or_else(|| name.clone());
        match value {
            Some(v) if !v.is_empty() => {
                base.insert(existing, v.clone());
            }
            _ => {
                base.remove(&existing);
            }
        }
    }
}

/// Built-in extension → interpreter command table (IDEA.md "Multi-language
/// script execution" → "Built-in table"). `script_handlers` config
/// (global then per-project) merges on top of this key-by-key — it never
/// wholesale-replaces it. The reserved value `exec` (used here for `.cgi`)
/// opts an extension into exec-directly mode, matching a `cgi-bin/` file.
pub fn builtin_script_handlers() -> BTreeMap<String, Option<String>> {
    let mut m = BTreeMap::new();
    m.insert("php".to_string(), Some("php-cgi".to_string()));
    m.insert("py".to_string(), Some("python3".to_string()));
    m.insert("pl".to_string(), Some("perl".to_string()));
    m.insert("lua".to_string(), Some("lua".to_string()));
    m.insert("rb".to_string(), Some("ruby".to_string()));
    m.insert("cgi".to_string(), Some("exec".to_string()));
    m
}

fn parse_layer(value: &Value) -> Layer {
    let tls_enabled = value.get("tls").and_then(|t| b(t, "enabled"));
    let proxy_raw = value.get("proxy");
    let proxy = ProxyLayer {
        enabled: proxy_raw.and_then(|p| b(p, "enabled")),
        kind: proxy_raw.and_then(|p| s(p, "type")),
        command: proxy_raw.and_then(|p| s(p, "command")),
        upstream: proxy_raw.and_then(|p| s(p, "upstream")),
        path_prefix: proxy_raw.and_then(|p| s(p, "path_prefix")),
    };
    let logging_raw = value.get("logging");
    let access_raw = logging_raw.and_then(|l| l.get("access"));
    let error_raw = logging_raw.and_then(|l| l.get("error"));
    let logging_access = LogStreamLayer {
        format: access_raw.and_then(|a| s(a, "format")),
        rotate: access_raw.and_then(|a| s(a, "rotate")),
        keep: access_raw.and_then(|a| s(a, "keep")),
    };
    let logging_error = LogStreamLayer {
        format: error_raw.and_then(|e| s(e, "format")),
        rotate: error_raw.and_then(|e| s(e, "rotate")),
        keep: error_raw.and_then(|e| s(e, "keep")),
    };

    Layer {
        base_dir: path_val(value, "base_dir"),
        listen: s(value, "listen"),
        port: u16_val(value, "port"),
        log_dir: path_val(value, "log_dir"),
        debug: b(value, "debug"),
        fqdn: s(value, "fqdn"),
        tls_enabled,
        directory_listing: b(value, "directory_listing"),
        mime_types: str_map(value, "mime_types"),
        script_handlers: opt_str_map(value, "script_handlers"),
        ssi_extensions: str_list(value, "ssi_extensions"),
        security_headers: opt_str_map(value, "security_headers"),
        server_tokens: s(value, "server_tokens"),
        cors: cors_layer(value),
        proxy,
        logging_access,
        logging_error,
    }
}

/// The fully resolved, concrete configuration `serve` actually runs with,
/// after applying CLI > env > per-project > global > built-in-default
/// precedence to every key in `Layer`.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub base_dir: PathBuf,
    pub listen: String,
    pub port: u16,
    pub log_dir: PathBuf,
    pub debug: bool,
    pub fqdn: Option<String>,
    pub tls_enabled: bool,
    pub directory_listing: bool,
    pub mime_types: BTreeMap<String, String>,
    pub script_handlers: BTreeMap<String, Option<String>>,
    /// Extensions (leading dot included) whose responses get Server-Side
    /// Includes processing; empty disables SSI for this project.
    pub ssi_extensions: Vec<String>,
    /// The effective default response headers, already merged: built-in
    /// defaults (including `Server` and the TLS-conditional HSTS header)
    /// with the `security_headers` overrides applied and removals dropped.
    pub security_headers: BTreeMap<String, String>,
    /// Effective CORS response headers, or `None` when `cors: false`
    /// disabled them. The request-dependent preflight echo is added on top
    /// of this at response time by `crate::servers::headers`.
    pub cors: Option<BTreeMap<String, String>>,
    pub proxy: ProxyLayer,
    // The access/error log *format* keys are parsed and resolved in full per
    // IDEA.md's schema, but `supports::rotation`-driven logging currently
    // emits only the documented `combined`/`standard` defaults — custom
    // format strings are still open (see TODO.AI.md), so nothing reads these
    // two fields yet. The `allow` keeps that gap explicit rather than
    // silently dropping the parsed values.
    #[allow(dead_code)]
    pub logging_access_format: String,
    pub logging_access_rotate: String,
    pub logging_access_keep: String,
    // Same gap as `logging_access_format` above: resolved per the schema,
    // not yet consumed by the error-log writer.
    #[allow(dead_code)]
    pub logging_error_format: String,
    pub logging_error_rotate: String,
    pub logging_error_keep: String,
    // The per-project config path is resolved here so a caller can report
    // which file a setting came from; the live-reload watcher derives the
    // same path independently via `config_paths` (which it must, since it
    // has to poll both files before any `Resolved` exists), so this copy has
    // no reader today. Kept because it is part of the resolved configuration
    // a future `--config-test`/`/server-info` detail view reports verbatim.
    #[allow(dead_code)]
    pub project_config_path: PathBuf,
}

/// Derives `{derived_name}` from a `base_dir` (IDEA.md "Core behavior"):
/// the absolute path with every `/` replaced by `_`.
pub fn derived_name(base_dir: &Path) -> String {
    let resolved = base_dir
        .canonicalize()
        .unwrap_or_else(|_| base_dir.to_path_buf());
    let text = resolved.to_string_lossy().replace('\\', "/");
    let trimmed = text.trim_start_matches('/');
    if trimmed.is_empty() {
        "root".to_string()
    } else {
        trimmed.replace('/', "_")
    }
}

fn pick_string(cli: Option<&str>, env: &str) -> Option<String> {
    if let Some(v) = cli {
        return Some(v.to_string());
    }
    std::env::var(env).ok()
}

fn pick_bool_env(env: &str) -> Option<bool> {
    std::env::var(env).ok().map(|v| {
        let v = v.trim().to_ascii_lowercase();
        v == "1" || v == "true" || v == "yes" || v == "on"
    })
}

fn read_layer(path: &Path) -> io::Result<Layer> {
    if !path.exists() {
        return Ok(Layer::default());
    }
    let text = fs::read_to_string(path)?;
    if text.trim().is_empty() {
        return Ok(Layer::default());
    }
    let value: Value = serde_yaml::from_str(&text).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: {err}", path.display()),
        )
    })?;
    Ok(parse_layer(&value))
}

#[cfg(unix)]
fn write_owner_only(path: &Path, contents: &str) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    use std::io::Write;
    f.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, contents: &str) -> io::Result<()> {
    fs::write(path, contents)
}

fn ensure_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// CLI-flag values actually supplied on this invocation (highest-precedence
/// layer, per IDEA.md's "CLI flag > env > per-project > global > default").
#[derive(Debug, Default, Clone)]
pub struct CliOverrides {
    pub base_dir: Option<PathBuf>,
    pub listen: Option<String>,
    pub port: Option<u16>,
    pub log_dir: Option<PathBuf>,
    pub debug: Option<bool>,
    pub fqdn: Option<String>,
    pub config_path: Option<PathBuf>,
}

fn autogenerated_yaml(resolved: &Resolved) -> String {
    let mut root = serde_yaml::Mapping::new();
    root.insert(
        "base_dir".into(),
        resolved.base_dir.to_string_lossy().to_string().into(),
    );
    root.insert("listen".into(), resolved.listen.clone().into());
    root.insert("port".into(), (resolved.port as u64).into());
    root.insert(
        "log_dir".into(),
        resolved.log_dir.to_string_lossy().to_string().into(),
    );
    root.insert("debug".into(), resolved.debug.into());
    if let Some(fqdn) = &resolved.fqdn {
        root.insert("fqdn".into(), fqdn.clone().into());
    }
    let mut tls = serde_yaml::Mapping::new();
    tls.insert("enabled".into(), resolved.tls_enabled.into());
    root.insert("tls".into(), Value::Mapping(tls));
    root.insert(
        "directory_listing".into(),
        resolved.directory_listing.into(),
    );
    serde_yaml::to_string(&Value::Mapping(root)).unwrap_or_default()
}

/// Derives the two file paths `load()` reads (global config, then the
/// active per-project config) from `cli`, without touching the filesystem.
/// Factored out so `crate::servers::run`'s live-reload mtime watcher can
/// poll the exact same two files `load()` itself will re-read on the next
/// call, rather than re-deriving (and risking drift from) this logic.
pub fn config_paths(cli: &CliOverrides) -> (PathBuf, PathBuf) {
    let config_dir = crate::platforms::paths::config_dir();
    let projects_dir = config_dir.join("projects");
    let global_path = config_dir.join("config.yaml");

    // base_dir is resolved before the project config can be located (its
    // filename is derived from base_dir) — CLI > env > default "."; the
    // project config's own `base_dir` key (if present) can still override
    // once loaded (see `load`), but that override never changes *which*
    // file is the active per-project config for this invocation.
    let base_dir_str = pick_string(
        cli.base_dir.as_deref().and_then(|p| p.to_str()),
        "CASHTTPD_BASE_DIR",
    );
    let mut base_dir = base_dir_str
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base_dir = base_dir.canonicalize().unwrap_or(base_dir);

    let name = derived_name(&base_dir);
    let project_path = cli
        .config_path
        .clone()
        .unwrap_or_else(|| projects_dir.join(format!("{name}.yaml")));
    (global_path, project_path)
}

/// Loads and merges the effective configuration for `serve`/`--config-test`,
/// autogenerating the global and per-project config files on first run when
/// `autogenerate` is true (skipped for `--config-test`, which must never
/// write to disk).
pub fn load(cli: &CliOverrides, autogenerate: bool) -> io::Result<Resolved> {
    let config_dir = crate::platforms::paths::config_dir();
    let projects_dir = config_dir.join("projects");
    if autogenerate {
        ensure_dir(&config_dir)?;
        ensure_dir(&projects_dir)?;
    }

    let (global_path, project_path) = config_paths(cli);
    let global = read_layer(&global_path)?;

    let base_dir_str = pick_string(
        cli.base_dir.as_deref().and_then(|p| p.to_str()),
        "CASHTTPD_BASE_DIR",
    );
    let mut base_dir = base_dir_str
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base_dir = base_dir.canonicalize().unwrap_or(base_dir);

    let mut project = read_layer(&project_path)?;

    if cli.base_dir.is_none() && std::env::var("CASHTTPD_BASE_DIR").is_err() {
        if let Some(p) = project.base_dir.take() {
            base_dir = p.canonicalize().unwrap_or(p);
        }
    }

    let listen = pick_string(cli.listen.as_deref(), "CASHTTPD_LISTEN")
        .or_else(|| project.listen.clone())
        .or_else(|| global.listen.clone())
        .unwrap_or_else(|| {
            if listen_v6_available() {
                "::1".to_string()
            } else {
                "127.0.0.1".to_string()
            }
        });

    let port = cli
        .port
        .or_else(|| {
            std::env::var("CASHTTPD_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
        })
        .or(project.port)
        .or(global.port)
        .unwrap_or_else(random_port);

    let log_dir = cli
        .log_dir
        .clone()
        .or_else(|| std::env::var_os("CASHTTPD_LOG_DIR").map(PathBuf::from))
        .or_else(|| project.log_dir.clone())
        .or_else(|| global.log_dir.clone())
        .unwrap_or_else(crate::platforms::paths::log_dir);

    let debug = cli
        .debug
        .or_else(|| pick_bool_env("CASHTTPD_DEBUG"))
        .or(project.debug)
        .or(global.debug)
        .unwrap_or(false);

    let fqdn = pick_string(cli.fqdn.as_deref(), "CASHTTPD_FQDN")
        .or_else(|| project.fqdn.clone())
        .or_else(|| global.fqdn.clone());

    let tls_enabled = pick_bool_env("CASHTTPD_TLS_ENABLED")
        .or(project.tls_enabled)
        .or(global.tls_enabled)
        .unwrap_or(false);

    let directory_listing = pick_bool_env("CASHTTPD_DIRECTORY_LISTING")
        .or(project.directory_listing)
        .or(global.directory_listing)
        .unwrap_or(false);

    let mut mime_types = global.mime_types.clone();
    mime_types.extend(project.mime_types.clone());

    let mut script_handlers = builtin_script_handlers();
    script_handlers.extend(global.script_handlers.clone());
    script_handlers.extend(project.script_handlers.clone());

    // `ssi_extensions` *adds* to the built-in set rather than replacing it,
    // with the one special case IDEA.md calls out explicitly: an empty list
    // disables SSI entirely, so it clears the set instead of being a no-op
    // union. Later layers still apply after a clear, which is what lets a
    // project re-enable SSI over a global `ssi_extensions: []`.
    let mut ssi_extensions = builtin_ssi_extensions();
    for layer in [&global.ssi_extensions, &project.ssi_extensions] {
        let Some(list) = layer else { continue };
        if list.is_empty() {
            ssi_extensions.clear();
            continue;
        }
        // Every entry is normalized to a leading dot and lowercased so
        // `shtml`, `.shtml`, and `.SHTML` all name the same extension, and
        // a repeat across layers collapses instead of accumulating.
        for ext in list {
            let ext = ext.trim().to_ascii_lowercase();
            let ext = if ext.starts_with('.') {
                ext
            } else {
                format!(".{ext}")
            };
            if !ssi_extensions.contains(&ext) {
                ssi_extensions.push(ext);
            }
        }
    }

    let server_tokens = pick_string(None, "CASHTTPD_SERVER_TOKENS")
        .or_else(|| project.server_tokens.clone())
        .or_else(|| global.server_tokens.clone())
        .map(|v| ServerTokens::parse(&v))
        .unwrap_or(ServerTokens::Full);

    let mut security_headers = builtin_security_headers(tls_enabled, server_tokens);
    merge_header_overrides(&mut security_headers, &global.security_headers);
    merge_header_overrides(&mut security_headers, &project.security_headers);

    // An explicit `cors: false` at either layer disables CORS; the
    // per-project layer still wins, so a project can re-enable it over a
    // global `false` by supplying its own header map.
    let cors = match (global.cors.clone(), project.cors.clone()) {
        (_, Some(CorsLayer::Disabled)) | (Some(CorsLayer::Disabled), None) => None,
        (global_cors, project_cors) => {
            let mut headers = builtin_cors_headers();
            if let Some(CorsLayer::Headers(overrides)) = global_cors {
                merge_header_overrides(&mut headers, &overrides);
            }
            if let Some(CorsLayer::Headers(overrides)) = project_cors {
                merge_header_overrides(&mut headers, &overrides);
            }
            Some(headers)
        }
    };

    let proxy = ProxyLayer {
        enabled: project.proxy.enabled.or(global.proxy.enabled),
        kind: project
            .proxy
            .kind
            .clone()
            .or_else(|| global.proxy.kind.clone()),
        command: project
            .proxy
            .command
            .clone()
            .or_else(|| global.proxy.command.clone()),
        upstream: project
            .proxy
            .upstream
            .clone()
            .or_else(|| global.proxy.upstream.clone()),
        path_prefix: project
            .proxy
            .path_prefix
            .clone()
            .or_else(|| global.proxy.path_prefix.clone()),
    };

    let logging_access_format = project
        .logging_access
        .format
        .clone()
        .or_else(|| global.logging_access.format.clone())
        .unwrap_or_else(|| "combined".to_string());
    let logging_access_rotate = project
        .logging_access
        .rotate
        .clone()
        .or_else(|| global.logging_access.rotate.clone())
        .unwrap_or_else(|| "daily".to_string());
    let logging_access_keep = project
        .logging_access
        .keep
        .clone()
        .or_else(|| global.logging_access.keep.clone())
        .unwrap_or_else(|| "30d".to_string());
    let logging_error_format = project
        .logging_error
        .format
        .clone()
        .or_else(|| global.logging_error.format.clone())
        .unwrap_or_else(|| "standard".to_string());
    let logging_error_rotate = project
        .logging_error
        .rotate
        .clone()
        .or_else(|| global.logging_error.rotate.clone())
        .unwrap_or_else(|| "daily".to_string());
    let logging_error_keep = project
        .logging_error
        .keep
        .clone()
        .or_else(|| global.logging_error.keep.clone())
        .unwrap_or_else(|| "30d".to_string());

    let resolved = Resolved {
        base_dir,
        listen,
        port,
        log_dir,
        debug,
        fqdn,
        tls_enabled,
        directory_listing,
        mime_types,
        script_handlers,
        ssi_extensions,
        security_headers,
        cors,
        proxy,
        logging_access_format,
        logging_access_rotate,
        logging_access_keep,
        logging_error_format,
        logging_error_rotate,
        logging_error_keep,
        project_config_path: project_path.clone(),
    };

    if autogenerate {
        if !global_path.exists() {
            write_owner_only(
                &global_path,
                "# cashttpd global config — see IDEA.md \"Configuration file\"\n",
            )?;
        }
        if !project_path.exists() {
            write_owner_only(&project_path, &autogenerated_yaml(&resolved))?;
        }
    }

    Ok(resolved)
}

fn listen_v6_available() -> bool {
    std::net::TcpListener::bind("[::1]:0").is_ok()
}

fn random_port() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    59000 + (nanos % 1000) as u16
}

/// Parse and validate the effective configuration without touching sockets
/// or running state — backs `--config-test` / `-t` (AI.md PART 14
/// "Signals & Lifecycle"). Only checks YAML syntax of whichever global/
/// per-project files exist (or the explicit `--config` override) — it never
/// creates or modifies files, matching the "never touches sockets/running
/// state" requirement.
pub fn validate(cli: &CliOverrides) -> Result<(), String> {
    let config_dir = crate::platforms::paths::config_dir();
    let global_path = config_dir.join("config.yaml");
    read_layer(&global_path).map_err(|err| err.to_string())?;

    let base_dir = cli
        .base_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("."))
        .canonicalize()
        .unwrap_or_else(|_| cli.base_dir.clone().unwrap_or_else(|| PathBuf::from(".")));
    let name = derived_name(&base_dir);
    let project_path = cli
        .config_path
        .clone()
        .unwrap_or_else(|| config_dir.join("projects").join(format!("{name}.yaml")));
    read_layer(&project_path).map_err(|err| err.to_string())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn unique_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "cashttpd-cfg-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        dir
    }

    #[test]
    fn validate_reports_success_when_no_config_files_exist() {
        let overrides = CliOverrides {
            base_dir: Some(unique_dir("validate-missing")),
            ..Default::default()
        };
        assert_eq!(validate(&overrides), Ok(()));
    }

    #[test]
    fn validate_reports_error_for_malformed_yaml() {
        let dir = unique_dir("validate-bad");
        fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("bad.yaml");
        fs::write(&bad, "not: [valid: yaml").unwrap();
        let overrides = CliOverrides {
            base_dir: Some(dir.clone()),
            config_path: Some(bad),
            ..Default::default()
        };
        assert!(validate(&overrides).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn derived_name_replaces_separators_with_underscores() {
        let dir = unique_dir("derived");
        fs::create_dir_all(&dir).unwrap();
        let name = derived_name(&dir);
        assert!(!name.contains('/'));
        assert!(!name.is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_autogenerates_project_config_with_resolved_settings() {
        let dir = unique_dir("load-autogen");
        fs::create_dir_all(&dir).unwrap();
        let config_home = unique_dir("load-autogen-config-home");
        // Isolate this test's config_dir from the real per-user location by
        // pointing XDG_CONFIG_HOME (used on the non-macOS/Windows path this
        // test runs under in CI) at a private scratch directory.
        std::env::set_var("XDG_CONFIG_HOME", &config_home);

        let overrides = CliOverrides {
            base_dir: Some(dir.clone()),
            listen: Some("127.0.0.1".to_string()),
            port: Some(12345),
            ..Default::default()
        };
        let resolved = load(&overrides, true).unwrap();
        assert_eq!(resolved.listen, "127.0.0.1");
        assert_eq!(resolved.port, 12345);
        assert!(resolved.project_config_path.exists());

        let reloaded = load(&overrides, false).unwrap();
        assert_eq!(reloaded.port, 12345);

        std::env::remove_var("XDG_CONFIG_HOME");
        fs::remove_dir_all(&dir).ok();
        fs::remove_dir_all(&config_home).ok();
    }

    #[test]
    fn load_cli_override_wins_over_env_var() {
        let dir = unique_dir("load-precedence");
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var("CASHTTPD_PORT", "9999");
        let overrides = CliOverrides {
            base_dir: Some(dir.clone()),
            port: Some(1111),
            ..Default::default()
        };
        let resolved = load(&overrides, false).unwrap();
        assert_eq!(resolved.port, 1111);
        std::env::remove_var("CASHTTPD_PORT");
        fs::remove_dir_all(&dir).ok();
    }
}
