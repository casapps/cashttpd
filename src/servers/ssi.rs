//! Server-Side Includes (IDEA.md "Server-Side Includes (SSI)") — builtin,
//! matching `mod_include`'s classic directive set.
//!
//! A file whose extension is in the resolved `ssi_extensions` list (`.shtml`
//! by default) is parsed for `<!--#directive attr="value" -->` markers and
//! served as `text/html`. Supported directives are exactly the ones IDEA.md
//! enumerates: `#include virtual=`/`#include file=`, `#echo var=`,
//! `#set var= value=`, and the `#if`/`#elif`/`#else`/`#endif` conditional
//! family over those variables.
//!
//! `#exec cmd=` / `#exec cgi=` are deliberately absent and are treated as an
//! unrecognized directive: Apache disables them by default
//! (`IncludesNOEXEC`) because unrestricted shell execution from template
//! content is a well-known injection vector, and this project offers no knob
//! to turn them on. That is a security decision, not an unfinished feature.
//!
//! Every failure — a missing include target, an include that escapes
//! `base_dir`, an unterminated or unrecognized directive, a malformed
//! conditional — renders `[an error occurred while processing this
//! directive]` inline at that point and leaves the rest of the document (and
//! the response status) alone, which is how Apache degrades and what keeps a
//! typo in one fragment from blanking a whole page.
//!
//! Rendering is a synchronous, recursive walk over small template files, so
//! it runs on `tokio::task::spawn_blocking` rather than on a reactor thread:
//! includes are resolved depth-first and each one is a filesystem read.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hyper::Response;

use super::{build_response, format_http_date, percent_decode, Body, Request, ServeOptions};

/// Apache's default error string for a directive that could not be
/// processed, reproduced verbatim so existing `.shtml` test suites and eyeball
/// checks recognize it.
const ERROR_MARKER: &str = "[an error occurred while processing this directive]";

/// Apache's default `SSIUndefinedEcho` value, emitted by `#echo` for a
/// variable that has no value.
const UNDEFINED_ECHO: &str = "(none)";

/// How deep `#include` nesting may go before the chain is cut off with an
/// error marker. This is what makes an include cycle (`a.shtml` including
/// `b.shtml` including `a.shtml`) terminate — cycle detection by path would
/// still allow an exponential fan-out of distinct files, whereas a depth cap
/// bounds both.
const MAX_INCLUDE_DEPTH: usize = 16;

/// Whether a resolved file gets SSI processing, i.e. whether its extension is
/// in the effective `ssi_extensions` list. An empty list disables SSI, so
/// this is also the "SSI is off" check.
pub fn applies(path: &Path, opts: &ServeOptions) -> bool {
    if opts.ssi_extensions.is_empty() {
        return false;
    }
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let ext = format!(".{}", ext.to_ascii_lowercase());
    opts.ssi_extensions.iter().any(|known| known == &ext)
}

/// Renders an SSI document and builds its response.
///
/// The response deliberately carries no `ETag`, `Last-Modified`, or
/// `Accept-Ranges`: the source file's size and mtime describe only the
/// outermost template, not the includes and variables that produced the
/// bytes actually sent, so advertising them would let a client cache a stale
/// composition of fresh fragments. Apache suppresses the same headers for
/// `INCLUDES`-filtered output for the same reason. Compression still applies
/// normally — it runs later, on the finished response.
///
/// A `HEAD` renders the document too rather than guessing: the whole point of
/// a `Content-Length` on a `HEAD` is that it matches what a `GET` would
/// return, and only rendering knows that number.
pub async fn serve(
    path: &Path,
    base_dir: &Path,
    request: &Request,
    opts: &ServeOptions,
    client: &str,
    head_only: bool,
    modified: SystemTime,
) -> std::io::Result<Response<Body>> {
    let vars = base_vars(path, base_dir, request, opts, client, modified);
    let mut renderer = Renderer {
        root: base_dir.to_path_buf(),
        vars,
    };
    let file = path.to_path_buf();
    let rendered = tokio::task::spawn_blocking(move || renderer.render_document(&file))
        .await
        .map_err(std::io::Error::other)?;

    let content_type = (
        "Content-Type".to_string(),
        "text/html; charset=utf-8".to_string(),
    );
    if head_only {
        return build_response(
            200,
            "OK",
            Bytes::new(),
            &[
                content_type,
                ("Content-Length".to_string(), rendered.len().to_string()),
            ],
        );
    }
    build_response(200, "OK", Bytes::from(rendered), &[content_type])
}

/// The variables `#echo` and the `#if` family can read: the CGI 1.1 set the
/// script handler exports (IDEA.md "CGI 1.1 protocol semantics"), the
/// `HTTP_*` request headers, and the SSI-standard document/date variables.
fn base_vars(
    path: &Path,
    base_dir: &Path,
    request: &Request,
    opts: &ServeOptions,
    client: &str,
    modified: SystemTime,
) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    let decoded = percent_decode(request.path.split('?').next().unwrap_or("/"));
    let query = request.path.split_once('?').map(|x| x.1).unwrap_or("");
    let (remote_addr, remote_port) = client.rsplit_once(':').unwrap_or((client, ""));

    vars.insert("REQUEST_METHOD".to_string(), request.method.clone());
    vars.insert("QUERY_STRING".to_string(), query.to_string());
    vars.insert("SERVER_PROTOCOL".to_string(), request.version.clone());
    vars.insert(
        "SERVER_NAME".to_string(),
        opts.fqdn.clone().unwrap_or_else(|| "localhost".to_string()),
    );
    vars.insert("SERVER_PORT".to_string(), opts.port.to_string());
    vars.insert(
        "SERVER_SOFTWARE".to_string(),
        format!("cashttpd/{}", crate::supports::version::VERSION),
    );
    vars.insert("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string());
    vars.insert("REMOTE_ADDR".to_string(), remote_addr.to_string());
    vars.insert("REMOTE_PORT".to_string(), remote_port.to_string());
    vars.insert(
        "DOCUMENT_ROOT".to_string(),
        base_dir.to_string_lossy().to_string(),
    );
    vars.insert(
        "SCRIPT_FILENAME".to_string(),
        path.to_string_lossy().to_string(),
    );
    if opts.tls_enabled {
        vars.insert("HTTPS".to_string(), "on".to_string());
    }
    for (name, value) in &request.headers {
        vars.insert(
            format!("HTTP_{}", name.to_ascii_uppercase().replace('-', "_")),
            value.clone(),
        );
    }

    vars.insert(
        "DOCUMENT_NAME".to_string(),
        path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
    );
    vars.insert("DOCUMENT_URI".to_string(), decoded);
    vars.insert("LAST_MODIFIED".to_string(), http_time(modified));
    let now = SystemTime::now();
    vars.insert("DATE_GMT".to_string(), http_time(now));
    // `DATE_LOCAL` is rendered in UTC as well. Converting to the host's local
    // zone needs either a linked libc `localtime` or a bundled tzdata
    // database, and both are ruled out by the single-static-binary/pure-Rust
    // constraints (AI.md PART 0, PART 5) for a variable whose only consumer
    // is a page footer. The variable exists and is well-formed; its offset is
    // the documented limitation (TODO.AI.md).
    vars.insert("DATE_LOCAL".to_string(), http_time(now));
    vars
}

fn http_time(t: SystemTime) -> String {
    format_http_date(
        t.duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

/// One conditional nesting level: whether any branch has already matched
/// (so `#elif`/`#else` must not fire again) and whether the branch currently
/// open is the one being emitted.
struct Branch {
    taken: bool,
    emitting: bool,
}

/// Document-rendering state: the containment root every `#include virtual`
/// resolves against, plus the variable table `#set` mutates as the document
/// is walked.
struct Renderer {
    root: PathBuf,
    vars: BTreeMap<String, String>,
}

impl Renderer {
    fn render_document(&mut self, path: &Path) -> String {
        let mut out = String::new();
        let mut stack: Vec<Branch> = Vec::new();
        self.render_file(path, 0, &mut stack, &mut out);
        // An unterminated `#if` at end of document is malformed input, and
        // Apache reports it rather than silently accepting the truncation.
        if !stack.is_empty() {
            out.push_str(ERROR_MARKER);
        }
        out
    }

    fn render_file(
        &mut self,
        path: &Path,
        depth: usize,
        stack: &mut Vec<Branch>,
        out: &mut String,
    ) {
        match std::fs::read(path) {
            // Invalid UTF-8 is transcoded lossily rather than failing: SSI
            // templates are HTML, and a stray byte in one paragraph must not
            // cost the whole page.
            Ok(bytes) => {
                let source = String::from_utf8_lossy(&bytes).into_owned();
                let dir = path.parent().unwrap_or(&self.root).to_path_buf();
                self.render_source(&source, &dir, depth, stack, out);
            }
            Err(_) => out.push_str(ERROR_MARKER),
        }
    }

    fn render_source(
        &mut self,
        source: &str,
        dir: &Path,
        depth: usize,
        stack: &mut Vec<Branch>,
        out: &mut String,
    ) {
        let mut rest = source;
        while let Some(start) = rest.find("<!--#") {
            if emitting(stack) {
                out.push_str(&rest[..start]);
            }
            let after = &rest[start + 5..];
            let Some(end) = after.find("-->") else {
                // An unterminated directive swallows the remainder of the
                // file in Apache too; the marker is what tells the author
                // where the document stopped being processed.
                out.push_str(ERROR_MARKER);
                return;
            };
            let directive = &after[..end];
            rest = &after[end + 3..];
            self.directive(directive, dir, depth, stack, out);
        }
        if emitting(stack) {
            out.push_str(rest);
        }
    }

    fn directive(
        &mut self,
        directive: &str,
        dir: &Path,
        depth: usize,
        stack: &mut Vec<Branch>,
        out: &mut String,
    ) {
        let trimmed = directive.trim();
        let (name, remainder) = match trimmed.find(char::is_whitespace) {
            Some(idx) => (&trimmed[..idx], &trimmed[idx..]),
            None => (trimmed, ""),
        };
        let name = name.to_ascii_lowercase();

        // The conditional family is processed even inside a suppressed
        // branch, because nesting has to stay balanced; everything else is
        // skipped there.
        match name.as_str() {
            "if" => {
                let parent_emitting = emitting(stack);
                let taken = parent_emitting && self.condition(remainder, out);
                stack.push(Branch {
                    taken,
                    emitting: taken,
                });
                return;
            }
            "elif" => {
                let Some(current) = stack.pop() else {
                    out.push_str(ERROR_MARKER);
                    return;
                };
                let parent_emitting = emitting(stack);
                let taken = !current.taken && parent_emitting && self.condition(remainder, out);
                stack.push(Branch {
                    taken: current.taken || taken,
                    emitting: taken,
                });
                return;
            }
            "else" => {
                let Some(current) = stack.pop() else {
                    out.push_str(ERROR_MARKER);
                    return;
                };
                let parent_emitting = emitting(stack);
                stack.push(Branch {
                    taken: true,
                    emitting: !current.taken && parent_emitting,
                });
                return;
            }
            "endif" => {
                if stack.pop().is_none() {
                    out.push_str(ERROR_MARKER);
                }
                return;
            }
            _ => {}
        }

        if !emitting(stack) {
            return;
        }

        let attrs = parse_attributes(remainder);
        match name.as_str() {
            "include" => self.include(&attrs, dir, depth, out),
            "echo" => self.echo(&attrs, out),
            "set" => self.set(&attrs, out),
            // Everything else, `#exec` included, is an unrecognized
            // directive here. `#exec` is not "not yet implemented": there is
            // no code path that could run it, by design.
            _ => out.push_str(ERROR_MARKER),
        }
    }

    fn include(&mut self, attrs: &[(String, String)], dir: &Path, depth: usize, out: &mut String) {
        if depth >= MAX_INCLUDE_DEPTH {
            out.push_str(ERROR_MARKER);
            return;
        }
        let virtual_target = attr(attrs, "virtual").map(|v| self.expand(v));
        let file_target = attr(attrs, "file").map(|v| self.expand(v));
        let resolved = match (virtual_target.as_deref(), file_target.as_deref()) {
            (Some(target), None) => self.resolve_virtual(target, dir),
            (None, Some(target)) => self.resolve_file(target, dir),
            // Neither attribute, or both at once, is malformed input.
            _ => None,
        };
        match resolved {
            Some(path) if path.is_file() => {
                // The included fragment shares the variable table (so a
                // `#set` in a header fragment is visible to the page that
                // included it, as in Apache) but gets its own conditional
                // stack: an unbalanced `#if` inside a fragment must not
                // silently swallow the parent document's markup.
                let mut nested = Vec::new();
                self.render_file(&path, depth + 1, &mut nested, out);
                if !nested.is_empty() {
                    out.push_str(ERROR_MARKER);
                }
            }
            _ => out.push_str(ERROR_MARKER),
        }
    }

    /// `#include virtual="..."` — a URL path resolved against `base_dir`
    /// when absolute, or against the including document's directory when
    /// relative, then held to exactly the same containment rule as any other
    /// request path.
    fn resolve_virtual(&self, target: &str, dir: &Path) -> Option<PathBuf> {
        let target = percent_decode(target.split('?').next().unwrap_or(""));
        let joined = match target.strip_prefix('/') {
            Some(rel) => self.root.join(rel),
            None => dir.join(&target),
        };
        self.contained(joined)
    }

    /// `#include file="..."` — a filesystem path relative to the including
    /// document's own directory. An absolute path or a `..` component is
    /// rejected outright (Apache does the same), and the canonicalized
    /// result still has to land inside `base_dir`.
    fn resolve_file(&self, target: &str, dir: &Path) -> Option<PathBuf> {
        let candidate = Path::new(target);
        if candidate.is_absolute()
            || candidate
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::RootDir))
        {
            return None;
        }
        self.contained(dir.join(candidate))
    }

    /// Canonicalizes a candidate include and rejects anything that resolves
    /// outside `base_dir` — the same containment check the static-file path
    /// applies, so a symlink or `..` chain inside a template cannot read
    /// `/etc/passwd`.
    fn contained(&self, candidate: PathBuf) -> Option<PathBuf> {
        let resolved = candidate.canonicalize().ok()?;
        let root = self
            .root
            .canonicalize()
            .unwrap_or_else(|_| self.root.clone());
        (resolved == root || resolved.starts_with(&root)).then_some(resolved)
    }

    fn echo(&self, attrs: &[(String, String)], out: &mut String) {
        let Some(var) = attr(attrs, "var") else {
            out.push_str(ERROR_MARKER);
            return;
        };
        let name = self.expand(var);
        let value = match self.vars.get(name.trim()) {
            Some(value) => value.clone(),
            None => UNDEFINED_ECHO.to_string(),
        };
        // Apache 2.x defaults `#echo` to `encoding="entity"`, and that
        // default is what keeps a reflected request header or query string
        // from becoming stored XSS in a template. `none` is honored when a
        // page asks for it explicitly.
        match attr(attrs, "encoding")
            .map(|e| e.to_ascii_lowercase())
            .as_deref()
        {
            Some("none") => out.push_str(&value),
            Some("url") => out.push_str(&url_encode(&value)),
            Some("entity") | None => out.push_str(&entity_encode(&value)),
            _ => out.push_str(ERROR_MARKER),
        }
    }

    fn set(&mut self, attrs: &[(String, String)], out: &mut String) {
        let (Some(var), Some(value)) = (attr(attrs, "var"), attr(attrs, "value")) else {
            out.push_str(ERROR_MARKER);
            return;
        };
        let name = self.expand(var).trim().to_string();
        if name.is_empty() {
            out.push_str(ERROR_MARKER);
            return;
        }
        let value = self.expand(value);
        self.vars.insert(name, value);
    }

    /// Evaluates an `#if`/`#elif` `expr="..."` attribute, writing an error
    /// marker for a malformed expression and treating it as false.
    fn condition(&self, remainder: &str, out: &mut String) -> bool {
        let attrs = parse_attributes(remainder);
        let Some(expr) = attr(&attrs, "expr") else {
            out.push_str(ERROR_MARKER);
            return false;
        };
        let expanded = self.expand(expr);
        match eval_expr(&expanded) {
            Some(result) => result,
            None => {
                out.push_str(ERROR_MARKER);
                false
            }
        }
    }

    /// Substitutes `$VAR` and `${VAR}` references, with `\$` as the literal
    /// escape. An unset variable expands to the empty string, matching
    /// Apache — `#echo`'s `(none)` placeholder is an echo-only affordance and
    /// would break comparisons if it leaked into expressions.
    fn expand(&self, input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(next) = chars.next() {
                    out.push(next);
                } else {
                    out.push('\\');
                }
                continue;
            }
            if c != '$' {
                out.push(c);
                continue;
            }
            let name = if chars.peek() == Some(&'{') {
                chars.next();
                let mut name = String::new();
                for c in chars.by_ref() {
                    if c == '}' {
                        break;
                    }
                    name.push(c);
                }
                name
            } else {
                let mut name = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_alphanumeric() || c == '_' {
                        name.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                name
            };
            if name.is_empty() {
                out.push('$');
                continue;
            }
            if let Some(value) = self.vars.get(&name) {
                out.push_str(value);
            }
        }
        out
    }
}

/// Whether output is currently being emitted, i.e. every open conditional
/// branch is the one that matched.
fn emitting(stack: &[Branch]) -> bool {
    stack.last().is_none_or(|branch| branch.emitting)
}

fn attr<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// Parses a directive's `name="value"` attribute list. Single quotes and
/// backquotes are accepted as delimiters (as in Apache), an unquoted value
/// runs to the next whitespace, and a backslash escapes the delimiter.
fn parse_attributes(input: &str) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    let mut chars = input.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let mut name = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c.is_whitespace() {
                break;
            }
            name.push(c);
            chars.next();
        }
        if name.is_empty() {
            return attrs;
        }
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        if chars.peek() != Some(&'=') {
            attrs.push((name.to_ascii_lowercase(), String::new()));
            continue;
        }
        chars.next();
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let mut value = String::new();
        match chars.peek().copied() {
            Some(quote @ ('"' | '\'' | '`')) => {
                chars.next();
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        if let Some(escaped) = chars.next() {
                            // Only the delimiter and the backslash itself are
                            // escapes; everything else keeps both characters,
                            // so a Windows path in a value survives intact.
                            if escaped == quote || escaped == '\\' {
                                value.push(escaped);
                            } else {
                                value.push('\\');
                                value.push(escaped);
                            }
                        }
                        continue;
                    }
                    if c == quote {
                        break;
                    }
                    value.push(c);
                }
            }
            Some(_) => {
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() {
                        break;
                    }
                    value.push(c);
                    chars.next();
                }
            }
            None => {}
        }
        attrs.push((name.to_ascii_lowercase(), value));
    }
}

fn entity_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Evaluates an already variable-substituted SSI expression, returning
/// `None` for a malformed one. This is a closed string-comparison grammar
/// parsed by the recursive-descent `Parser` below — it evaluates nothing but
/// the operators listed here, and there is no path from an expression to
/// process execution, filesystem access, or any interpreter.
///
/// The grammar is `mod_include`'s: `||` over `&&` over `!`, with parentheses,
/// string comparison (`=`, `==`, `!=`, `<`, `<=`, `>`, `>=`), a `/regex/`
/// right-hand side for `=`/`!=`, and a bare string that is true when
/// non-empty. Comparisons are lexicographic on strings, as in Apache.
fn eval_expr(expr: &str) -> Option<bool> {
    let mut parser = Parser {
        chars: expr.chars().collect(),
        pos: 0,
    };
    let value = parser.or()?;
    parser.skip_ws();
    if parser.pos != parser.chars.len() {
        return None;
    }
    Some(value)
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn skip_ws(&mut self) {
        while self.chars.get(self.pos).is_some_and(|c| c.is_whitespace()) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, token: &str) -> bool {
        self.skip_ws();
        let token: Vec<char> = token.chars().collect();
        if self.chars[self.pos..].starts_with(&token) {
            self.pos += token.len();
            return true;
        }
        false
    }

    fn or(&mut self) -> Option<bool> {
        let mut value = self.and()?;
        while self.eat("||") {
            // Both sides are always parsed: a malformed right operand is an
            // error even when the left one already decided the result, so a
            // typo cannot hide behind short-circuiting.
            value = self.and()? || value;
        }
        Some(value)
    }

    fn and(&mut self) -> Option<bool> {
        let mut value = self.unary()?;
        while self.eat("&&") {
            value = self.unary()? && value;
        }
        Some(value)
    }

    fn unary(&mut self) -> Option<bool> {
        self.skip_ws();
        if self.eat("!") {
            return Some(!self.unary()?);
        }
        if self.eat("(") {
            let value = self.or()?;
            if !self.eat(")") {
                return None;
            }
            return Some(value);
        }
        self.comparison()
    }

    fn comparison(&mut self) -> Option<bool> {
        let left = self.operand()?;
        self.skip_ws();
        let op = ["==", "!=", "<=", ">=", "=", "<", ">"]
            .into_iter()
            .find(|op| self.eat(op));
        let Some(op) = op else {
            return Some(!left.text.is_empty());
        };
        let right = self.operand()?;
        if right.regex {
            let matched = regex::Regex::new(&right.text).ok()?.is_match(&left.text);
            return match op {
                "=" | "==" => Some(matched),
                "!=" => Some(!matched),
                // Ordering a string against a pattern is meaningless.
                _ => None,
            };
        }
        Some(match op {
            "=" | "==" => left.text == right.text,
            "!=" => left.text != right.text,
            "<" => left.text < right.text,
            "<=" => left.text <= right.text,
            ">" => left.text > right.text,
            ">=" => left.text >= right.text,
            _ => return None,
        })
    }

    fn operand(&mut self) -> Option<Operand> {
        self.skip_ws();
        match self.chars.get(self.pos).copied() {
            Some(quote @ ('"' | '\'')) => {
                self.pos += 1;
                let mut text = String::new();
                loop {
                    let c = *self.chars.get(self.pos)?;
                    self.pos += 1;
                    if c == '\\' {
                        text.push(*self.chars.get(self.pos)?);
                        self.pos += 1;
                        continue;
                    }
                    if c == quote {
                        break;
                    }
                    text.push(c);
                }
                Some(Operand { text, regex: false })
            }
            Some('/') => {
                self.pos += 1;
                let mut text = String::new();
                loop {
                    let c = *self.chars.get(self.pos)?;
                    self.pos += 1;
                    if c == '\\' {
                        text.push('\\');
                        text.push(*self.chars.get(self.pos)?);
                        self.pos += 1;
                        continue;
                    }
                    if c == '/' {
                        break;
                    }
                    text.push(c);
                }
                Some(Operand { text, regex: true })
            }
            Some(_) => {
                let start = self.pos;
                while let Some(&c) = self.chars.get(self.pos) {
                    if c.is_whitespace() || matches!(c, '=' | '!' | '<' | '>' | '&' | '|' | ')') {
                        break;
                    }
                    self.pos += 1;
                }
                if self.pos == start {
                    return None;
                }
                Some(Operand {
                    text: self.chars[start..self.pos].iter().collect(),
                    regex: false,
                })
            }
            None => Some(Operand {
                // An empty tail (`"$UNSET"` expanded away entirely) is a
                // legitimately false operand, not a parse error.
                text: String::new(),
                regex: false,
            }),
        }
    }
}

/// One side of a comparison: literal text, or a `/pattern/` to match against
/// the other side.
struct Operand {
    text: String,
    regex: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn renderer(root: &Path) -> Renderer {
        let mut vars = BTreeMap::new();
        vars.insert("DOCUMENT_NAME".to_string(), "page.shtml".to_string());
        vars.insert("QUERY_STRING".to_string(), "a=1".to_string());
        vars.insert("SERVER_NAME".to_string(), "localhost".to_string());
        Renderer {
            root: root.to_path_buf(),
            vars,
        }
    }

    fn render(root: &Path, source: &str) -> String {
        let mut out = String::new();
        let mut stack = Vec::new();
        renderer(root).render_source(source, root, 0, &mut stack, &mut out);
        out
    }

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cashttpd-ssi-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn echo_renders_a_variable_and_html_escapes_it_by_default() {
        let root = tempdir("echo");
        let mut r = renderer(&root);
        r.vars.insert("EVIL".to_string(), "<script>&\"".to_string());
        let mut out = String::new();
        let mut stack = Vec::new();
        r.render_source(
            "name=<!--#echo var=\"DOCUMENT_NAME\" -->;evil=<!--#echo var=\"EVIL\" -->",
            &root,
            0,
            &mut stack,
            &mut out,
        );
        assert_eq!(out, "name=page.shtml;evil=&lt;script&gt;&amp;&quot;");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn echo_of_an_unset_variable_uses_apaches_placeholder() {
        let root = tempdir("unset");
        assert_eq!(render(&root, "<!--#echo var=\"NOPE\" -->"), "(none)");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn set_defines_a_variable_visible_to_later_directives() {
        let root = tempdir("set");
        assert_eq!(
            render(
                &root,
                "<!--#set var=\"greeting\" value=\"hi $SERVER_NAME\" --><!--#echo var=\"greeting\" -->"
            ),
            "hi localhost"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn conditionals_select_exactly_one_branch() {
        let root = tempdir("cond");
        let source = "<!--#if expr=\"$SERVER_NAME = 'localhost'\" -->A<!--#elif expr=\"1\" -->B\
                      <!--#else -->C<!--#endif -->";
        assert_eq!(render(&root, source), "A");

        // The variable is quoted on purpose: expansion happens before the
        // expression is parsed (Apache's own order), so a bare
        // `expr="$QUERY_STRING"` holding `a=1` would parse as the comparison
        // `a = 1` rather than as a truth test on the string.
        let source =
            "<!--#if expr=\"$SERVER_NAME = 'other'\" -->A<!--#elif expr=\"'$QUERY_STRING'\" -->B\
                      <!--#else -->C<!--#endif -->";
        assert_eq!(render(&root, source), "B");

        let source = "<!--#if expr=\"$NOPE\" -->A<!--#elif expr=\"$ALSO_NOPE\" -->B\
                      <!--#else -->C<!--#endif -->";
        assert_eq!(render(&root, source), "C");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_suppressed_branch_emits_neither_text_nor_directive_output() {
        let root = tempdir("suppressed");
        let source = "<!--#if expr=\"$NOPE\" -->text<!--#echo var=\"SERVER_NAME\" -->\
                      <!--#include virtual=\"/missing.html\" --><!--#endif -->done";
        assert_eq!(render(&root, source), "done");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn nested_conditionals_stay_balanced() {
        let root = tempdir("nested");
        let source = "<!--#if expr=\"1\" -->outer\
                      <!--#if expr=\"$NOPE\" -->inner<!--#else -->alt<!--#endif -->\
                      <!--#endif -->";
        assert_eq!(render(&root, source), "outeralt");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn include_virtual_and_file_both_resolve_and_are_processed_recursively() {
        let root = tempdir("include");
        std::fs::create_dir_all(root.join("parts")).unwrap();
        std::fs::write(
            root.join("parts/header.shtml"),
            "H:<!--#echo var=\"SERVER_NAME\" -->",
        )
        .unwrap();
        std::fs::write(root.join("parts/footer.html"), "F").unwrap();
        let out = render(
            &root,
            "<!--#include virtual=\"/parts/header.shtml\" -->|<!--#include file=\"parts/footer.html\" -->",
        );
        assert_eq!(out, "H:localhost|F");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_missing_include_renders_the_error_marker_without_stopping_the_page() {
        let root = tempdir("missing");
        let out = render(&root, "before<!--#include virtual=\"/nope.html\" -->after");
        assert_eq!(out, format!("before{ERROR_MARKER}after"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_include_escaping_the_document_root_is_refused() {
        let root = tempdir("traversal");
        std::fs::write(root.join("inside.html"), "ok").unwrap();
        for source in [
            "<!--#include file=\"../../etc/passwd\" -->",
            "<!--#include virtual=\"/../../etc/passwd\" -->",
            "<!--#include file=\"/etc/passwd\" -->",
        ] {
            assert_eq!(render(&root, source), ERROR_MARKER, "source: {source}");
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_include_cycle_terminates_with_an_error_marker() {
        let root = tempdir("cycle");
        std::fs::write(
            root.join("a.shtml"),
            "a<!--#include virtual=\"/b.shtml\" -->",
        )
        .unwrap();
        std::fs::write(
            root.join("b.shtml"),
            "b<!--#include virtual=\"/a.shtml\" -->",
        )
        .unwrap();
        let out = render(&root, "<!--#include virtual=\"/a.shtml\" -->");
        assert!(out.ends_with(ERROR_MARKER), "output: {out}");
        assert!(out.matches('a').count() <= MAX_INCLUDE_DEPTH);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn exec_is_never_executed_and_reports_as_an_unrecognized_directive() {
        let root = tempdir("exec");
        let marker = root.join("pwned");
        let source = format!(
            "<!--#exec cmd=\"touch {}\" --><!--#exec cgi=\"/cgi-bin/x\" -->",
            marker.display()
        );
        assert_eq!(
            render(&root, &source),
            format!("{ERROR_MARKER}{ERROR_MARKER}")
        );
        assert!(!marker.exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_malformed_directive_marks_the_spot_and_keeps_the_status_quo() {
        let root = tempdir("malformed");
        assert_eq!(render(&root, "<!--#echo -->"), ERROR_MARKER);
        assert_eq!(render(&root, "<!--#set var=\"x\" -->"), ERROR_MARKER);
        assert_eq!(render(&root, "<!--#endif -->"), ERROR_MARKER);
        assert_eq!(
            render(&root, "x<!--#echo var=\"A\""),
            format!("x{ERROR_MARKER}")
        );
        assert_eq!(
            render(&root, "<!--#if expr=\"'a' = = 'b'\" -->y<!--#endif -->"),
            ERROR_MARKER
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_unterminated_conditional_is_reported_at_end_of_document() {
        let root = tempdir("unbalanced");
        std::fs::write(root.join("open.shtml"), "<!--#if expr=\"1\" -->body").unwrap();
        let mut r = renderer(&root);
        assert_eq!(
            r.render_document(&root.join("open.shtml")),
            format!("body{ERROR_MARKER}")
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn expression_grammar_covers_apaches_operator_set() {
        assert_eq!(eval_expr("\"a\" = \"a\""), Some(true));
        assert_eq!(eval_expr("\"a\" == \"a\""), Some(true));
        assert_eq!(eval_expr("\"a\" != \"b\""), Some(true));
        assert_eq!(eval_expr("\"a\" < \"b\""), Some(true));
        assert_eq!(eval_expr("\"b\" <= \"b\""), Some(true));
        assert_eq!(eval_expr("\"b\" > \"a\""), Some(true));
        assert_eq!(eval_expr("\"a\" >= \"b\""), Some(false));
        assert_eq!(eval_expr("!\"\""), Some(true));
        assert_eq!(eval_expr("\"a\" && \"\""), Some(false));
        assert_eq!(eval_expr("\"a\" || \"\""), Some(true));
        assert_eq!(eval_expr("(\"\" || \"a\") && !\"\""), Some(true));
        assert_eq!(eval_expr("\"index.shtml\" = /\\.shtml$/"), Some(true));
        assert_eq!(eval_expr("\"index.html\" = /\\.shtml$/"), Some(false));
        assert_eq!(eval_expr("\"index.html\" != /\\.shtml$/"), Some(true));
        assert_eq!(eval_expr("bare"), Some(true));
        assert_eq!(eval_expr(""), Some(false));
        // A missing right operand is an empty string, not a parse error —
        // that is what `expr="$SET = $UNSET"` expands to, and Apache treats
        // it as an ordinary false comparison.
        assert_eq!(eval_expr("\"a\" = "), Some(false));
        assert_eq!(eval_expr("\"\" = "), Some(true));
        assert_eq!(eval_expr("(\"a\""), None);
        assert_eq!(eval_expr("\"a\" < /re/"), None);
    }

    #[test]
    fn attribute_parsing_handles_quotes_escapes_and_unquoted_values() {
        let attrs = parse_attributes(" VAR=\"one two\" other='three' bare=four ");
        assert_eq!(attr(&attrs, "var"), Some("one two"));
        assert_eq!(attr(&attrs, "other"), Some("three"));
        assert_eq!(attr(&attrs, "bare"), Some("four"));

        let attrs = parse_attributes(r#"value="a \"quoted\" b""#);
        assert_eq!(attr(&attrs, "value"), Some(r#"a "quoted" b"#));
    }

    #[test]
    fn variable_expansion_supports_braces_and_backslash_escapes() {
        let root = tempdir("expand");
        let r = renderer(&root);
        assert_eq!(r.expand("$SERVER_NAME/x"), "localhost/x");
        assert_eq!(r.expand("${SERVER_NAME}x"), "localhostx");
        assert_eq!(r.expand("\\$SERVER_NAME"), "$SERVER_NAME");
        assert_eq!(r.expand("$NOPE!"), "!");
        assert_eq!(r.expand("cost: $ 5"), "cost: $ 5");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn url_encoding_is_available_for_echo() {
        assert_eq!(url_encode("a b/c?d=é"), "a%20b%2Fc%3Fd%3D%C3%A9");
    }

    #[test]
    fn applies_matches_configured_extensions_case_insensitively() {
        let mut opts = super::super::fallback_defaults();
        assert!(applies(Path::new("/srv/index.shtml"), &opts));
        assert!(applies(Path::new("/srv/INDEX.SHTML"), &opts));
        assert!(!applies(Path::new("/srv/index.html"), &opts));
        opts.ssi_extensions = vec![".html".to_string()];
        assert!(applies(Path::new("/srv/index.html"), &opts));
        opts.ssi_extensions.clear();
        assert!(!applies(Path::new("/srv/index.shtml"), &opts));
    }
}
