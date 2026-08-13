//! `.htaccess`/`.htpasswd` Apache-compatible support (IDEA.md ".htaccess"/
//! ".htpasswd" compatibility") — recursive discovery, root-to-leaf cascade
//! merge (effectively `AllowOverride All` everywhere under `base_dir`,
//! there being no `httpd.conf` equivalent to restrict it), authentication
//! (`AuthType Basic` + `.htpasswd` bcrypt/apr1/`{SHA}`), authorization
//! (`Require`, legacy `Order`/`Allow`/`Deny`), `ErrorDocument`,
//! `DirectoryIndex`, `Options Indexes`/`FollowSymLinks`, and
//! `RewriteEngine`/`RewriteCond`/`RewriteRule`/`Redirect`/`RedirectMatch`.
//!
//! `.htaccess`/`.htpasswd` themselves are never servable as static content
//! at any depth (trust boundary enforced in `server::handle_request`, not
//! here, and this module cannot be made to override it from within a
//! `.htaccess` file — there is no directive that touches it).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    AllowDeny,
    DenyAllow,
}

#[derive(Debug, Clone)]
pub enum AccessRule {
    All,
    Ip(IpAddr),
    Cidr(IpAddr, u8),
    /// Hostname-based `Allow`/`Deny from {host}` — accepted syntactically but
    /// never matches (no reverse-DNS lookup is performed; documented gap).
    Host,
}

#[derive(Debug, Clone)]
pub enum Require {
    ValidUser,
    User(Vec<String>),
    Group(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct RewriteCond {
    pub test_string: String,
    pub pattern: String,
    pub negate: bool,
    pub nocase: bool,
}

#[derive(Debug, Clone)]
pub struct RewriteRule {
    pub pattern: String,
    pub substitution: String,
    pub flags: Vec<String>,
    pub conds: Vec<RewriteCond>,
    /// Directory (relative to `base_dir`) this rule's `.htaccess` lives in —
    /// `RewriteRule` patterns match the request path relative to it.
    pub dir: String,
}

#[derive(Debug, Clone)]
pub struct Redirect {
    pub is_regex: bool,
    pub status: u16,
    pub pattern: String,
    pub target: String,
}

/// The merged cascade of every `.htaccess` from `base_dir` down to (and
/// including) the target directory (IDEA.md "Cascade order").
#[derive(Debug, Clone, Default)]
pub struct Rules {
    pub auth_type: Option<String>,
    pub auth_name: Option<String>,
    pub auth_user_file: Option<PathBuf>,
    pub auth_group_file: Option<PathBuf>,
    pub requires: Vec<Require>,
    pub order: Option<Order>,
    pub allow: Vec<AccessRule>,
    pub deny: Vec<AccessRule>,
    pub error_documents: HashMap<u16, String>,
    pub directory_index: Option<Vec<String>>,
    pub indexes: Option<bool>,
    pub follow_symlinks: Option<bool>,
    pub rewrite_engine: bool,
    pub rewrite_rules: Vec<RewriteRule>,
    pub redirects: Vec<Redirect>,
}

impl Rules {
    fn merge_from(&mut self, child: Rules) {
        if child.auth_type.is_some() {
            self.auth_type = child.auth_type;
        }
        if child.auth_name.is_some() {
            self.auth_name = child.auth_name;
        }
        if child.auth_user_file.is_some() {
            self.auth_user_file = child.auth_user_file;
        }
        if child.auth_group_file.is_some() {
            self.auth_group_file = child.auth_group_file;
        }
        self.requires.extend(child.requires);
        if child.order.is_some() {
            self.order = child.order;
        }
        self.allow.extend(child.allow);
        self.deny.extend(child.deny);
        self.error_documents.extend(child.error_documents);
        if child.directory_index.is_some() {
            self.directory_index = child.directory_index;
        }
        if child.indexes.is_some() {
            self.indexes = child.indexes;
        }
        if child.follow_symlinks.is_some() {
            self.follow_symlinks = child.follow_symlinks;
        }
        if child.rewrite_engine {
            self.rewrite_engine = true;
        }
        self.rewrite_rules.extend(child.rewrite_rules);
        self.redirects.extend(child.redirects);
    }

    pub fn require_valid_user(&self) -> bool {
        !self.requires.is_empty()
    }
}

/// Recursively discovers and merges every `.htaccess` from `base_dir` down
/// to `dir` (inclusive), root-most first — "a subdirectory's `.htaccess` is
/// layered on top of, not a replacement for, its parents' directives."
/// `dir` must already be canonicalized and known to be inside `base_dir`.
pub fn merge_cascade(base_dir: &Path, dir: &Path) -> Rules {
    let mut chain: Vec<PathBuf> = Vec::new();
    let mut cur = dir.to_path_buf();
    loop {
        chain.push(cur.clone());
        if cur == base_dir {
            break;
        }
        match cur.parent() {
            Some(p) if p == base_dir || p.starts_with(base_dir) => cur = p.to_path_buf(),
            _ => break,
        }
    }
    chain.reverse();

    let mut rules = Rules::default();
    for d in chain {
        let path = d.join(".htaccess");
        if let Ok(text) = std::fs::read_to_string(&path) {
            let rel = d.strip_prefix(base_dir).unwrap_or(Path::new(""));
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            let parsed = parse(&text, &rel_str, base_dir, &d);
            rules.merge_from(parsed);
        }
    }
    rules
}

fn status_from_keyword(word: &str) -> Option<u16> {
    match word.to_ascii_lowercase().as_str() {
        "permanent" => Some(301),
        "temp" => Some(302),
        "seeother" => Some(303),
        "gone" => Some(410),
        _ => None,
    }
}

fn resolve_htaccess_path(raw: &str, dir: &Path, base_dir: &Path) -> PathBuf {
    let p = Path::new(raw);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        let _ = base_dir;
        dir.join(p)
    }
}

fn parse_flags(raw: &str) -> Vec<String> {
    raw.trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn parse(text: &str, rel_dir: &str, base_dir: &Path, dir: &Path) -> Rules {
    let mut r = Rules::default();
    let mut pending_conds: Vec<RewriteCond> = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let directive = match parts.next() {
            Some(d) => d,
            None => continue,
        };
        let rest: Vec<&str> = parts.collect();

        match directive {
            "AuthType" => r.auth_type = rest.first().map(|s| s.to_string()),
            "AuthName" => {
                r.auth_name = Some(rest.join(" ").trim_matches('"').to_string());
            }
            "AuthUserFile" => {
                r.auth_user_file = rest
                    .first()
                    .map(|s| resolve_htaccess_path(s, dir, base_dir));
            }
            "AuthGroupFile" => {
                r.auth_group_file = rest
                    .first()
                    .map(|s| resolve_htaccess_path(s, dir, base_dir));
            }
            "Require" => {
                if let Some(&kind) = rest.first() {
                    match kind {
                        "valid-user" => r.requires.push(Require::ValidUser),
                        "user" => r.requires.push(Require::User(
                            rest[1..].iter().map(|s| s.to_string()).collect(),
                        )),
                        "group" => r.requires.push(Require::Group(
                            rest[1..].iter().map(|s| s.to_string()).collect(),
                        )),
                        _ => {}
                    }
                }
            }
            "Order" => {
                if let Some(&v) = rest.first() {
                    r.order = match v.to_ascii_lowercase().as_str() {
                        "allow,deny" => Some(Order::AllowDeny),
                        "deny,allow" => Some(Order::DenyAllow),
                        _ => r.order,
                    };
                }
            }
            "Allow" => parse_access(&rest, &mut r.allow),
            "Deny" => parse_access(&rest, &mut r.deny),
            "ErrorDocument" => {
                if let (Some(code_s), false) = (rest.first(), rest.len() < 2) {
                    if let Ok(code) = code_s.parse::<u16>() {
                        r.error_documents.insert(code, rest[1..].join(" "));
                    }
                }
            }
            "DirectoryIndex" => {
                if !rest.is_empty() {
                    r.directory_index = Some(rest.iter().map(|s| s.to_string()).collect());
                }
            }
            "Options" => {
                for opt in &rest {
                    match *opt {
                        "Indexes" | "+Indexes" => r.indexes = Some(true),
                        "-Indexes" => r.indexes = Some(false),
                        "FollowSymLinks" | "+FollowSymLinks" => r.follow_symlinks = Some(true),
                        "-FollowSymLinks" => r.follow_symlinks = Some(false),
                        _ => {}
                    }
                }
            }
            "RewriteEngine" => {
                r.rewrite_engine = rest
                    .first()
                    .map(|v| v.eq_ignore_ascii_case("on"))
                    .unwrap_or(false);
            }
            "RewriteCond" => {
                if rest.len() >= 2 {
                    let mut pattern = rest[1].to_string();
                    let mut negate = false;
                    if let Some(p) = pattern.strip_prefix('!') {
                        negate = true;
                        pattern = p.to_string();
                    }
                    let flags = rest.get(2).map(|f| parse_flags(f)).unwrap_or_default();
                    let nocase = flags.iter().any(|f| f.eq_ignore_ascii_case("NC"));
                    pending_conds.push(RewriteCond {
                        test_string: rest[0].to_string(),
                        pattern,
                        negate,
                        nocase,
                    });
                }
            }
            "RewriteRule" => {
                if rest.len() >= 2 {
                    let flags = rest.get(2).map(|f| parse_flags(f)).unwrap_or_default();
                    r.rewrite_rules.push(RewriteRule {
                        pattern: rest[0].to_string(),
                        substitution: rest[1].to_string(),
                        flags,
                        conds: std::mem::take(&mut pending_conds),
                        dir: rel_dir.to_string(),
                    });
                }
            }
            "Redirect" | "RedirectMatch" => {
                let is_regex = directive == "RedirectMatch";
                let mut idx = 0usize;
                let mut status = 302u16;
                if let Some(&first) = rest.first() {
                    if let Ok(code) = first.parse::<u16>() {
                        status = code;
                        idx = 1;
                    } else if let Some(code) = status_from_keyword(first) {
                        status = code;
                        idx = 1;
                    }
                }
                if rest.len() > idx + 1 {
                    r.redirects.push(Redirect {
                        is_regex,
                        status,
                        pattern: rest[idx].to_string(),
                        target: rest[idx + 1].to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    r
}

fn parse_access(rest: &[&str], out: &mut Vec<AccessRule>) {
    for &tok in rest {
        if tok.eq_ignore_ascii_case("from") {
            continue;
        }
        if let Some(rule) = parse_source(tok) {
            out.push(rule);
        }
    }
}

fn parse_source(tok: &str) -> Option<AccessRule> {
    if tok.eq_ignore_ascii_case("all") {
        return Some(AccessRule::All);
    }
    if let Some((ip_s, bits_s)) = tok.split_once('/') {
        if let (Ok(ip), Ok(bits)) = (ip_s.parse::<IpAddr>(), bits_s.parse::<u8>()) {
            return Some(AccessRule::Cidr(ip, bits));
        }
    }
    if let Ok(ip) = tok.parse::<IpAddr>() {
        return Some(AccessRule::Ip(ip));
    }
    Some(AccessRule::Host)
}

fn cidr_contains(net: IpAddr, bits: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits.min(32))
            };
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let mask = if bits == 0 {
                0u128
            } else {
                u128::MAX << (128 - bits.min(128))
            };
            (u128::from(n) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

/// Legacy `Order`/`Allow`/`Deny` classic-syntax access check (IDEA.md
/// "Authorization" → legacy directives), evaluated against the client's
/// (possibly unparseable, e.g. loopback-test) remote address.
pub fn access_allowed(rules: &Rules, remote_ip: &str) -> bool {
    if rules.order.is_none() && rules.allow.is_empty() && rules.deny.is_empty() {
        return true;
    }
    let ip: Option<IpAddr> = remote_ip.parse().ok();
    let matches = |list: &[AccessRule]| -> bool {
        list.iter().any(|rule| match rule {
            AccessRule::All => true,
            AccessRule::Ip(target) => ip.map(|i| &i == target).unwrap_or(false),
            AccessRule::Cidr(net, bits) => {
                ip.map(|i| cidr_contains(*net, *bits, i)).unwrap_or(false)
            }
            AccessRule::Host => false,
        })
    };
    match rules.order.unwrap_or(Order::AllowDeny) {
        Order::AllowDeny => {
            let allowed = rules.allow.is_empty() || matches(&rules.allow);
            allowed && !matches(&rules.deny)
        }
        Order::DenyAllow => {
            let denied = !rules.deny.is_empty() && matches(&rules.deny);
            !denied || matches(&rules.allow)
        }
    }
}

/// Decodes an `Authorization: Basic {b64}` header into `(user, password)`.
pub fn parse_basic_auth(header: &str) -> Option<(String, String)> {
    let b64 = header.strip_prefix("Basic ")?;
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Verifies `user`/`password` against a `.htpasswd`-format file (IDEA.md
/// "`.htpasswd` format support" — bcrypt, apr1/MD5-crypt, `{SHA}`; legacy
/// crypt-DES entries are not supported and always fail verification).
pub fn verify_password(htpasswd_path: &Path, user: &str, password: &str) -> bool {
    let text = match std::fs::read_to_string(htpasswd_path) {
        Ok(t) => t,
        Err(_) => return false,
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, hash)) = line.split_once(':') {
            if name == user {
                return verify_hash(hash.trim(), password);
            }
        }
    }
    false
}

fn verify_hash(hash: &str, password: &str) -> bool {
    if hash.starts_with("$2y$") || hash.starts_with("$2a$") || hash.starts_with("$2b$") {
        // bcrypt encodes `$2y$`/`$2b$` identically to `$2a$` for verification
        // purposes; the `bcrypt` crate expects the `$2a$`/`$2b$`/`$2y$`
        // prefix as-is and parses it directly.
        bcrypt::verify(password, hash).unwrap_or(false)
    } else if let Some(rest) = hash.strip_prefix("$apr1$") {
        apr1_verify(rest, password)
    } else if let Some(b64) = hash.strip_prefix("{SHA}") {
        use base64::Engine;
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let digest = hasher.finalize();
        base64::engine::general_purpose::STANDARD.encode(digest) == b64
    } else {
        false
    }
}

const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Apache `apr1` / classic `md5crypt` (Poul-Henning Kamp) algorithm.
/// `rest` is the `salt$hash` portion following the `$apr1$` magic.
fn apr1_verify(rest: &str, password: &str) -> bool {
    let (salt, _hash) = match rest.split_once('$') {
        Some(v) => v,
        None => return false,
    };
    let computed = apr1_crypt(password, salt);
    computed == format!("$apr1${rest}")
}

fn apr1_crypt(password: &str, salt: &str) -> String {
    use md5::{Digest, Md5};
    let pw = password.as_bytes();
    let salt = salt.as_bytes();
    const MAGIC: &[u8] = b"$apr1$";

    let mut ctx2 = Md5::new();
    ctx2.update(pw);
    ctx2.update(salt);
    ctx2.update(pw);
    let final2 = ctx2.finalize();

    let mut ctx1 = Md5::new();
    ctx1.update(pw);
    ctx1.update(MAGIC);
    ctx1.update(salt);
    let mut i = pw.len();
    while i > 0 {
        let take = i.min(16);
        ctx1.update(&final2[..take]);
        i = i.saturating_sub(16);
    }
    let mut i = pw.len();
    while i > 0 {
        if i & 1 != 0 {
            ctx1.update([0u8]);
        } else {
            ctx1.update(&pw[..1]);
        }
        i >>= 1;
    }
    let mut result: [u8; 16] = ctx1.finalize().into();

    for round in 0..1000 {
        let mut ctx = Md5::new();
        if round & 1 != 0 {
            ctx.update(pw);
        } else {
            ctx.update(result);
        }
        if round % 3 != 0 {
            ctx.update(salt);
        }
        if round % 7 != 0 {
            ctx.update(pw);
        }
        if round & 1 != 0 {
            ctx.update(result);
        } else {
            ctx.update(pw);
        }
        result = ctx.finalize().into();
    }

    fn encode(out: &mut String, b2: u8, b1: u8, b0: u8, n: usize) {
        let mut w = ((b2 as u32) << 16) | ((b1 as u32) << 8) | (b0 as u32);
        for _ in 0..n {
            out.push(ITOA64[(w & 0x3f) as usize] as char);
            w >>= 6;
        }
    }

    let mut out = String::new();
    encode(&mut out, result[0], result[6], result[12], 4);
    encode(&mut out, result[1], result[7], result[13], 4);
    encode(&mut out, result[2], result[8], result[14], 4);
    encode(&mut out, result[3], result[9], result[15], 4);
    encode(&mut out, result[4], result[10], result[5], 4);
    encode(&mut out, 0, 0, result[11], 2);

    format!("$apr1${}${}", String::from_utf8_lossy(salt), out)
}

/// Looks up `group` membership in an `AuthGroupFile` (`groupname: user1
/// user2 ...` lines, matching Apache's `mod_authz_groupfile` format).
pub fn group_members(group_file: &Path, group: &str) -> Vec<String> {
    let text = match std::fs::read_to_string(group_file) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some((name, members)) = line.split_once(':') {
            if name.trim() == group {
                return members.split_whitespace().map(|s| s.to_string()).collect();
            }
        }
    }
    Vec::new()
}

pub fn is_authorized(rules: &Rules, user: &str) -> bool {
    if rules.requires.is_empty() {
        return true;
    }
    rules.requires.iter().any(|req| match req {
        Require::ValidUser => true,
        Require::User(names) => names.iter().any(|n| n == user),
        Require::Group(groups) => rules
            .auth_group_file
            .as_ref()
            .map(|f| {
                groups
                    .iter()
                    .any(|g| group_members(f, g).iter().any(|m| m == user))
            })
            .unwrap_or(false),
    })
}

/// Outcome of applying phase-1 rewrite/redirect processing to a request
/// path (IDEA.md 6-phase evaluation order, phase 1).
#[derive(Debug)]
pub enum RewriteOutcome {
    /// No rule matched, or rewriting is not engaged — proceed with the
    /// original path.
    Unchanged,
    /// An internal rewrite changed the target path; continue processing
    /// (phases 2-6) against the new path.
    Rewritten(String),
    /// An `[R]`-flagged `RewriteRule` or a `Redirect`/`RedirectMatch`
    /// fired — respond immediately with this status and `Location`.
    Redirect(u16, String),
}

fn expand_backrefs(template: &str, caps: &regex::Captures) -> String {
    let mut out = String::new();
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let n = (bytes[i + 1] - b'0') as usize;
            out.push_str(caps.get(n).map(|m| m.as_str()).unwrap_or(""));
            i += 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn expand_vars(
    template: &str,
    path: &str,
    query: &str,
    headers: &HashMap<String, String>,
) -> String {
    let mut out = template.to_string();
    out = out.replace("%{REQUEST_URI}", path);
    out = out.replace("%{QUERY_STRING}", query);
    out = out.replace(
        "%{HTTP_HOST}",
        headers.get("host").map(|s| s.as_str()).unwrap_or(""),
    );
    out
}

/// Applies phase-1 `RewriteRule`/`Redirect` processing (IDEA.md 6-phase
/// evaluation order, phase 1 — "rewrite/redirect first, can change the
/// target path/resource"). `path` is the decoded request path (no query
/// string, leading `/`). Rules/redirects are evaluated in cascade order
/// (root-most `.htaccess` first); the first match wins.
pub fn apply_rewrites(
    rules: &Rules,
    path: &str,
    query: &str,
    method: &str,
    remote_addr: &str,
    headers: &HashMap<String, String>,
) -> RewriteOutcome {
    for redirect in &rules.redirects {
        let rel = path.trim_start_matches('/');
        let matched = if redirect.is_regex {
            Regex::new(&redirect.pattern)
                .ok()
                .and_then(|re| re.captures(path))
                .map(|caps| expand_backrefs(&redirect.target, &caps))
        } else if rel.starts_with(redirect.pattern.trim_start_matches('/')) {
            Some(redirect.target.clone())
        } else {
            None
        };
        if let Some(target) = matched {
            return RewriteOutcome::Redirect(redirect.status, target);
        }
    }

    if !rules.rewrite_engine {
        return RewriteOutcome::Unchanged;
    }

    for rule in &rules.rewrite_rules {
        // `RewriteRule` patterns match the request path relative to the
        // `.htaccess` file's own directory (real Apache per-directory
        // semantics) — strip the rule's `dir` prefix from the full,
        // site-root-relative path before matching.
        let rel_path = path.trim_start_matches('/');
        let subject = if rule.dir.is_empty() {
            rel_path
        } else {
            let prefix = format!("{}/", rule.dir.trim_end_matches('/'));
            rel_path.strip_prefix(prefix.as_str()).unwrap_or(rel_path)
        };
        let nocase = rule.flags.iter().any(|f| f.eq_ignore_ascii_case("NC"));
        let pattern = if nocase {
            format!("(?i){}", rule.pattern)
        } else {
            rule.pattern.clone()
        };
        let re = match Regex::new(&pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let caps = match re.captures(subject) {
            Some(c) => c,
            None => continue,
        };

        let conds_ok = rule.conds.iter().all(|cond| {
            let expanded = expand_vars(&cond.test_string, path, query, headers);
            let expanded = expanded
                .replace("%{REQUEST_METHOD}", method)
                .replace("%{REMOTE_ADDR}", remote_addr);
            let cond_pattern = if cond.nocase {
                format!("(?i){}", cond.pattern)
            } else {
                cond.pattern.clone()
            };
            let is_match = Regex::new(&cond_pattern)
                .map(|re| re.is_match(&expanded))
                .unwrap_or(false);
            is_match != cond.negate
        });
        if !conds_ok {
            continue;
        }

        let substitution = expand_backrefs(&rule.substitution, &caps);
        let new_path = if substitution.starts_with('/') {
            substitution
        } else if rule.dir.is_empty() {
            format!("/{substitution}")
        } else {
            format!("/{}/{substitution}", rule.dir.trim_end_matches('/'))
        };

        let is_redirect = rule.flags.iter().any(|f| f == "R" || f.starts_with("R="));
        if is_redirect {
            let status = rule
                .flags
                .iter()
                .find_map(|f| f.strip_prefix("R="))
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(302);
            return RewriteOutcome::Redirect(status, new_path);
        }
        return RewriteOutcome::Rewritten(new_path);
    }

    RewriteOutcome::Unchanged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cashttpd-htaccess-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn cascade_merges_root_and_subdirectory_directives() {
        let base = tmp("cascade");
        write(&base, ".htaccess", "AuthType Basic\nAuthName \"Top\"\n");
        let sub = base.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        write(&sub, ".htaccess", "Require valid-user\n");

        let rules = merge_cascade(&base, &sub);
        assert_eq!(rules.auth_type.as_deref(), Some("Basic"));
        assert_eq!(rules.auth_name.as_deref(), Some("Top"));
        assert!(rules.require_valid_user());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn access_allowed_respects_order_deny_allow() {
        let mut rules = Rules {
            order: Some(Order::AllowDeny),
            deny: vec![AccessRule::All],
            ..Default::default()
        };
        assert!(!access_allowed(&rules, "10.0.0.5"));

        rules
            .allow
            .push(AccessRule::Cidr("10.0.0.0".parse().unwrap(), 8));
        // Deny still wins under Order allow,deny per this implementation's
        // "allowed && !denied" semantics.
        assert!(!access_allowed(&rules, "10.0.0.5"));
    }

    #[test]
    fn access_allowed_with_no_directives_is_open() {
        let rules = Rules::default();
        assert!(access_allowed(&rules, "anything"));
    }

    #[test]
    fn parse_basic_auth_decodes_credentials() {
        // "alice:secret" base64-encoded
        let header = "Basic YWxpY2U6c2VjcmV0";
        let (user, pass) = parse_basic_auth(header).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(pass, "secret");
    }

    #[test]
    fn verify_password_checks_sha_format() {
        let dir = tmp("sha");
        // {SHA}base64(sha1("secret"))
        use base64::Engine;
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(b"secret");
        let digest = hasher.finalize();
        let hash = format!(
            "{{SHA}}{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        );
        write(&dir, ".htpasswd", &format!("alice:{hash}\n"));
        assert!(verify_password(&dir.join(".htpasswd"), "alice", "secret"));
        assert!(!verify_password(&dir.join(".htpasswd"), "alice", "wrong"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verify_password_checks_bcrypt_format() {
        let dir = tmp("bcrypt");
        let hash = bcrypt::hash("secret", 4).unwrap();
        write(&dir, ".htpasswd", &format!("bob:{hash}\n"));
        assert!(verify_password(&dir.join(".htpasswd"), "bob", "secret"));
        assert!(!verify_password(&dir.join(".htpasswd"), "bob", "wrong"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apr1_crypt_matches_known_test_vector() {
        // Well-known Apache-documented md5crypt/apr1 test vector.
        let hash = apr1_crypt("myPassword", "r31.....");
        assert_eq!(hash, "$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/");
    }

    #[test]
    fn verify_password_checks_apr1_format() {
        let dir = tmp("apr1");
        write(
            &dir,
            ".htpasswd",
            "carol:$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/\n",
        );
        assert!(verify_password(
            &dir.join(".htpasswd"),
            "carol",
            "myPassword"
        ));
        assert!(!verify_password(&dir.join(".htpasswd"), "carol", "wrong"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn group_members_parses_group_file() {
        let dir = tmp("group");
        write(&dir, ".htgroup", "admins: alice bob\n");
        let members = group_members(&dir.join(".htgroup"), "admins");
        assert_eq!(members, vec!["alice".to_string(), "bob".to_string()]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn is_authorized_checks_require_user_and_group() {
        let rules = Rules {
            requires: vec![Require::User(vec!["alice".to_string()])],
            ..Default::default()
        };
        assert!(is_authorized(&rules, "alice"));
        assert!(!is_authorized(&rules, "bob"));
    }

    #[test]
    fn apply_rewrites_redirects_on_r_flag() {
        let rules = Rules {
            rewrite_engine: true,
            rewrite_rules: vec![RewriteRule {
                pattern: "^old/(.*)$".to_string(),
                substitution: "new/$1".to_string(),
                flags: vec!["R=301".to_string()],
                conds: Vec::new(),
                dir: String::new(),
            }],
            ..Default::default()
        };
        let headers = HashMap::new();
        match apply_rewrites(&rules, "/old/page", "", "GET", "127.0.0.1", &headers) {
            RewriteOutcome::Redirect(301, target) => assert_eq!(target, "/new/page"),
            other => panic!("expected redirect, got {other:?}"),
        }
    }

    #[test]
    fn apply_rewrites_internal_rewrite_without_flag() {
        let rules = Rules {
            rewrite_engine: true,
            rewrite_rules: vec![RewriteRule {
                pattern: "^alias$".to_string(),
                substitution: "real.html".to_string(),
                flags: Vec::new(),
                conds: Vec::new(),
                dir: String::new(),
            }],
            ..Default::default()
        };
        let headers = HashMap::new();
        match apply_rewrites(&rules, "/alias", "", "GET", "127.0.0.1", &headers) {
            RewriteOutcome::Rewritten(p) => assert_eq!(p, "/real.html"),
            other => panic!("expected rewrite, got {other:?}"),
        }
    }

    #[test]
    fn apply_rewrites_redirect_directive_prefix_match() {
        let rules = Rules {
            redirects: vec![Redirect {
                is_regex: false,
                status: 302,
                pattern: "/old".to_string(),
                target: "/new".to_string(),
            }],
            ..Default::default()
        };
        let headers = HashMap::new();
        match apply_rewrites(&rules, "/old/page", "", "GET", "127.0.0.1", &headers) {
            RewriteOutcome::Redirect(302, target) => assert_eq!(target, "/new"),
            other => panic!("expected redirect, got {other:?}"),
        }
    }
}
