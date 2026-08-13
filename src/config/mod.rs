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
//! running and hot-applying changes, including listener rebind) is not yet
//! implemented — tracked in TODO.AI.md. This module covers load-time
//! layering, autogeneration, and `--config-test` syntax validation.

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
    pub proxy: ProxyLayer,
    pub logging_access: LogStreamLayer,
    pub logging_error: LogStreamLayer,
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
        proxy,
        logging_access,
        logging_error,
    }
}

/// The fully resolved, concrete configuration `serve` actually runs with,
/// after applying CLI > env > per-project > global > built-in-default
/// precedence to every key in `Layer`.
// `script_handlers`, `proxy`, the `logging_*` format/rotate/keep fields, and
// `project_config_path` are parsed and resolved in full per IDEA.md's
// schema, but nothing consumes them yet — CGI/script execution, dev-server
// proxying, custom access/error log formats, and scheduled log rotation are
// still open (see TODO.AI.md). `#[allow(dead_code)]` here documents that
// gap explicitly rather than silently dropping the parsed values.
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
    #[allow(dead_code)]
    pub script_handlers: BTreeMap<String, Option<String>>,
    #[allow(dead_code)]
    pub proxy: ProxyLayer,
    #[allow(dead_code)]
    pub logging_access_format: String,
    #[allow(dead_code)]
    pub logging_access_rotate: String,
    #[allow(dead_code)]
    pub logging_access_keep: String,
    #[allow(dead_code)]
    pub logging_error_format: String,
    #[allow(dead_code)]
    pub logging_error_rotate: String,
    #[allow(dead_code)]
    pub logging_error_keep: String,
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

/// Loads and merges the effective configuration for `serve`/`--config-test`,
/// autogenerating the global and per-project config files on first run when
/// `autogenerate` is true (skipped for `--config-test`, which must never
/// write to disk).
pub fn load(cli: &CliOverrides, autogenerate: bool) -> io::Result<Resolved> {
    let config_dir = crate::platform::paths::config_dir();
    let projects_dir = config_dir.join("projects");
    if autogenerate {
        ensure_dir(&config_dir)?;
        ensure_dir(&projects_dir)?;
    }

    let global_path = config_dir.join("config.yaml");
    let global = read_layer(&global_path)?;

    // base_dir is resolved before the project config can be located (its
    // filename is derived from base_dir) — CLI > env > default "."; the
    // project config's own `base_dir` key (if present) can still override
    // once loaded, matching "base_dir is meaningful only in a per-project
    // config" from IDEA.md.
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
        .unwrap_or_else(crate::platform::paths::log_dir);

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

    let mut script_handlers = global.script_handlers.clone();
    script_handlers.extend(project.script_handlers.clone());

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
    let config_dir = crate::platform::paths::config_dir();
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
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_home);
        }

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

        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        fs::remove_dir_all(&dir).ok();
        fs::remove_dir_all(&config_home).ok();
    }

    #[test]
    fn load_cli_override_wins_over_env_var() {
        let dir = unique_dir("load-precedence");
        fs::create_dir_all(&dir).unwrap();
        unsafe {
            std::env::set_var("CASHTTPD_PORT", "9999");
        }
        let overrides = CliOverrides {
            base_dir: Some(dir.clone()),
            port: Some(1111),
            ..Default::default()
        };
        let resolved = load(&overrides, false).unwrap();
        assert_eq!(resolved.port, 1111);
        unsafe {
            std::env::remove_var("CASHTTPD_PORT");
        }
        fs::remove_dir_all(&dir).ok();
    }
}
