//! `/server-info` diagnostics dashboard (IDEA.md "`/server-info` diagnostics
//! dashboard"): a built-in, always-on route (never `--debug`-gated) that
//! gives the developer running cashttpd a live Traefik/Caddy-admin/Apache-
//! `server-status`-style overview plus an active error/issue list, without
//! digging through log files. Everything here is in-memory aggregate state
//! for *this* process only — bounded structures, no per-request history, no
//! persistence, resets to zero on every restart (consistent with "no
//! persisted state across restarts" elsewhere in IDEA.md). This is a
//! distinct, additional surface: the on-disk access/error log written by
//! `Logger` remains the durable per-request record and is never replaced by
//! anything in this module.
//!
//! Trust boundary: only aggregate counts, paths, and request metadata are
//! ever recorded — never request bodies, header values, cookies,
//! credentials, `.htpasswd` hashes, or TLS private key material.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{html_escape, ServeOptions};

/// Which pipeline stage ultimately produced a response — IDEA.md's exact
/// handler-type breakdown list ("static file, directory listing,
/// script/CGI, `cgi-bin/`, framework proxy, `.htaccess`-denied").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandlerType {
    StaticFile,
    DirectoryListing,
    ScriptCgi,
    CgiBin,
    FrameworkProxy,
    HtaccessDenied,
}

impl HandlerType {
    const ALL: [HandlerType; 6] = [
        HandlerType::StaticFile,
        HandlerType::DirectoryListing,
        HandlerType::ScriptCgi,
        HandlerType::CgiBin,
        HandlerType::FrameworkProxy,
        HandlerType::HtaccessDenied,
    ];

    fn label(self) -> &'static str {
        match self {
            HandlerType::StaticFile => "static file",
            HandlerType::DirectoryListing => "directory listing",
            HandlerType::ScriptCgi => "script/CGI",
            HandlerType::CgiBin => "cgi-bin/",
            HandlerType::FrameworkProxy => "framework proxy",
            HandlerType::HtaccessDenied => ".htaccess-denied",
        }
    }
}

/// The exact tracked-issue taxonomy from IDEA.md's "Error/issue list — what
/// counts as a tracked issue" bullet list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssueKind {
    BrokenStaticRef,
    ScriptFailure,
    MissingInterpreter,
    // Documented gap (TODO.AI.md): cashttpd has no language-aware parsing of
    // arbitrary script stderr/stdout to distinguish "missing language
    // module" (e.g. a PHP script needing an uninstalled `mysqli` extension)
    // from an ordinary script failure, so this variant is never constructed
    // — such failures are recorded as `ScriptFailure` instead. Kept in the
    // taxonomy (not removed) so it can be wired up if that detection is
    // ever added.
    #[allow(dead_code)]
    MissingLanguageModule,
    FrameworkProxyError,
    AccessControlDenial,
    TlsIssue,
    /// A live config-file reload (IDEA.md "Configuration file" → "Live
    /// reload") that could not be fully applied — e.g. a `base_dir` change
    /// (never live-appliable) or a listener rebind that failed (a
    /// privileged-port rebind after privileges were already dropped).
    ConfigReloadIssue,
}

impl IssueKind {
    fn label(self) -> &'static str {
        match self {
            IssueKind::BrokenStaticRef => "broken static reference",
            IssueKind::ScriptFailure => "script/CGI failure",
            IssueKind::MissingInterpreter => "missing interpreter",
            IssueKind::MissingLanguageModule => "missing language module",
            IssueKind::FrameworkProxyError => "framework proxy error",
            IssueKind::AccessControlDenial => "access-control denial",
            IssueKind::TlsIssue => "TLS/certificate issue",
            IssueKind::ConfigReloadIssue => "config reload issue",
        }
    }
}

/// Full request context for one occurrence of a grouped issue (IDEA.md
/// "Tracing / correlation" — "every entry also carries its own request
/// context: timestamp, method, requested path, resolved filesystem path
/// (or upstream target for proxied requests), and response status").
#[derive(Debug, Clone)]
pub struct Occurrence {
    pub unix_secs: u64,
    pub method: String,
    pub path: String,
    pub target: String,
    pub status: u16,
    pub referer: Option<String>,
}

/// One grouped issue entry (IDEA.md "Grouping and lifecycle" — "repeated
/// occurrences of the same underlying issue (same path, same cause) are
/// grouped into a single entry with an occurrence count and a last-seen
/// timestamp"). Bounded occurrence list — only the most recent occurrences
/// are retained for click-through detail; `count` keeps the true total.
struct IssueGroup {
    kind: IssueKind,
    cause: String,
    count: u64,
    last_seen: u64,
    occurrences: Vec<Occurrence>,
}

impl IssueGroup {
    /// A short one-line summary for the collapsed `<summary>` — the full
    /// cause (which for script failures includes captured stderr) is shown
    /// in the expanded `<pre>` detail instead.
    fn cause_summary(&self) -> String {
        self.cause.lines().next().unwrap_or("").to_string()
    }
}

const MAX_ISSUE_GROUPS: usize = 200;
const MAX_OCCURRENCES_PER_GROUP: usize = 20;
const MAX_TRACKED_PATHS: usize = 1000;
const MAX_LATENCY_SAMPLES: usize = 256;
const RATE_WINDOW_SECS: u64 = 60;

struct IssueList {
    groups: HashMap<(IssueKind, String, String), IssueGroup>,
}

impl IssueList {
    fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    fn record(&mut self, kind: IssueKind, path: &str, cause: &str, occ: Occurrence) {
        let key = (kind, path.to_string(), cause.to_string());
        if let Some(group) = self.groups.get_mut(&key) {
            group.count += 1;
            group.last_seen = occ.unix_secs;
            if group.occurrences.len() >= MAX_OCCURRENCES_PER_GROUP {
                group.occurrences.remove(0);
            }
            group.occurrences.push(occ);
            return;
        }
        if self.groups.len() >= MAX_ISSUE_GROUPS {
            // Evict the group with the oldest `last_seen` — bounded total
            // size (IDEA.md "Bounded total issue-list size ... evict
            // oldest-grouped-entry on overflow").
            if let Some(oldest_key) = self
                .groups
                .iter()
                .min_by_key(|(_, g)| g.last_seen)
                .map(|(k, _)| k.clone())
            {
                self.groups.remove(&oldest_key);
            }
        }
        self.groups.insert(
            key,
            IssueGroup {
                kind,
                cause: cause.to_string(),
                count: 1,
                last_seen: occ.unix_secs,
                occurrences: vec![occ],
            },
        );
    }
}

/// Bounded min/avg/max + rough p50/p95 latency tracking for one handler
/// type (IDEA.md "Latency" — "a bounded reservoir or fixed-size sample
/// buffer is fine, no unbounded Vec").
struct HandlerStats {
    count: u64,
    total_ms: u64,
    min_ms: u64,
    max_ms: u64,
    samples: Vec<u64>,
}

impl HandlerStats {
    fn new() -> Self {
        Self {
            count: 0,
            total_ms: 0,
            min_ms: u64::MAX,
            max_ms: 0,
            samples: Vec::new(),
        }
    }

    fn record(&mut self, elapsed: Duration) {
        let ms = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
        self.count += 1;
        self.total_ms += ms;
        self.min_ms = self.min_ms.min(ms);
        self.max_ms = self.max_ms.max(ms);
        if self.samples.len() >= MAX_LATENCY_SAMPLES {
            self.samples.remove(0);
        }
        self.samples.push(ms);
    }

    fn avg_ms(&self) -> u64 {
        self.total_ms.checked_div(self.count).unwrap_or(0)
    }

    fn percentile(&self, pct: f64) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let idx = ((sorted.len() as f64 - 1.0) * pct).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }
}

/// Per-second request-count buckets used only to derive a live
/// requests/sec figure over a short rolling window — never a stored history
/// of every request's timestamp (IDEA.md "Throughput").
struct RateWindow {
    buckets: HashMap<u64, u64>,
}

impl RateWindow {
    fn new() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }

    fn record(&mut self, now_secs: u64) {
        *self.buckets.entry(now_secs).or_insert(0) += 1;
        self.prune(now_secs);
    }

    fn prune(&mut self, now_secs: u64) {
        self.buckets
            .retain(|secs, _| now_secs.saturating_sub(*secs) < RATE_WINDOW_SECS);
    }

    fn rate_per_sec(&self, now_secs: u64) -> f64 {
        let window_start = now_secs.saturating_sub(RATE_WINDOW_SECS);
        let total: u64 = self
            .buckets
            .iter()
            .filter(|(secs, _)| **secs > window_start && **secs <= now_secs)
            .map(|(_, c)| *c)
            .sum();
        total as f64 / RATE_WINDOW_SECS as f64
    }
}

/// Bounded top-N path counter (IDEA.md "Hot paths" — "bounded `HashMap`,
/// evict/cap it — no unbounded growth").
struct PathCounter {
    counts: HashMap<String, u64>,
}

impl PathCounter {
    fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    fn record(&mut self, path: &str) {
        if let Some(c) = self.counts.get_mut(path) {
            *c += 1;
            return;
        }
        if self.counts.len() >= MAX_TRACKED_PATHS {
            if let Some(min_key) = self
                .counts
                .iter()
                .min_by_key(|(_, c)| **c)
                .map(|(k, _)| k.clone())
            {
                self.counts.remove(&min_key);
            }
        }
        self.counts.insert(path.to_string(), 1);
    }

    fn top(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self.counts.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }
}

/// Request/response stats + issue list for one cashttpd process (IDEA.md
/// "Request/response stats tracking"). Constructed once in `run()` and
/// shared via `Arc` into every connection/request, same pattern as
/// `proxy_target`.
pub struct Stats {
    started_at: Instant,
    start_wall_secs: u64,
    sandboxing_posture: &'static str,
    proxy_child_pid: AtomicI32,
    in_flight: AtomicI64,
    active_upstream: AtomicI64,
    total_requests: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    by_method: Mutex<HashMap<String, u64>>,
    by_status: Mutex<HashMap<u16, u64>>,
    by_class: Mutex<HashMap<&'static str, u64>>,
    by_handler: Mutex<HashMap<HandlerType, HandlerStats>>,
    top_paths: Mutex<PathCounter>,
    top_error_paths: Mutex<PathCounter>,
    rate: Mutex<RateWindow>,
    issues: Mutex<IssueList>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn status_class(status: u16) -> &'static str {
    match status / 100 {
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

/// RAII guard decrementing the in-flight counter on drop, so every
/// `handle_request` exit path — including early returns — is covered
/// without threading extra bookkeeping through every call site.
pub struct InFlightGuard<'a> {
    stats: &'a Stats,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.stats.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// RAII guard decrementing the active-upstream-connections counter on drop
/// (IDEA.md "Concurrency" — "active upstream connections when framework
/// proxying is active").
pub struct UpstreamGuard<'a> {
    stats: &'a Stats,
}

impl Drop for UpstreamGuard<'_> {
    fn drop(&mut self) {
        self.stats.active_upstream.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Stats {
    pub fn new(sandboxing_posture: &'static str) -> Self {
        Self {
            started_at: Instant::now(),
            start_wall_secs: now_secs(),
            sandboxing_posture,
            proxy_child_pid: AtomicI32::new(0),
            in_flight: AtomicI64::new(0),
            active_upstream: AtomicI64::new(0),
            total_requests: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            by_method: Mutex::new(HashMap::new()),
            by_status: Mutex::new(HashMap::new()),
            by_class: Mutex::new(HashMap::new()),
            by_handler: Mutex::new(HashMap::new()),
            top_paths: Mutex::new(PathCounter::new()),
            top_error_paths: Mutex::new(PathCounter::new()),
            rate: Mutex::new(RateWindow::new()),
            issues: Mutex::new(IssueList::new()),
        }
    }

    pub fn set_proxy_child_pid(&self, pid: u32) {
        self.proxy_child_pid.store(pid as i32, Ordering::SeqCst);
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    pub fn in_flight_guard(&self) -> InFlightGuard<'_> {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlightGuard { stats: self }
    }

    pub fn upstream_guard(&self) -> UpstreamGuard<'_> {
        self.active_upstream.fetch_add(1, Ordering::Relaxed);
        UpstreamGuard { stats: self }
    }

    /// Records the per-request totals every request produces regardless of
    /// how it was handled: by method, by exact status and status class,
    /// throughput, the rolling requests/sec window, and hot/error paths.
    pub fn record_totals(
        &self,
        method: &str,
        path: &str,
        status: u16,
        bytes_sent: u64,
        bytes_received: u64,
    ) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes_sent, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(bytes_received, Ordering::Relaxed);
        if let Ok(mut m) = self.by_method.lock() {
            *m.entry(method.to_string()).or_insert(0) += 1;
        }
        if let Ok(mut m) = self.by_status.lock() {
            *m.entry(status).or_insert(0) += 1;
        }
        if let Ok(mut m) = self.by_class.lock() {
            *m.entry(status_class(status)).or_insert(0) += 1;
        }
        if let Ok(mut r) = self.rate.lock() {
            r.record(now_secs());
        }
        if let Ok(mut p) = self.top_paths.lock() {
            p.record(path);
        }
        if status >= 400 {
            if let Ok(mut p) = self.top_error_paths.lock() {
                p.record(path);
            }
        }
    }

    /// Records the handler-type-specific count and latency for a request
    /// (IDEA.md "Totals since start" / "Latency" — tracked per handler
    /// type since a static file, a CGI script, and a proxied framework
    /// request have meaningfully different expected latencies).
    pub fn record_handler(&self, handler: HandlerType, elapsed: Duration) {
        if let Ok(mut m) = self.by_handler.lock() {
            m.entry(handler)
                .or_insert_with(HandlerStats::new)
                .record(elapsed);
        }
    }

    /// Records one occurrence of a tracked issue, grouped by
    /// `(kind, path, cause)` (IDEA.md "Grouping and lifecycle").
    // Each parameter is one field of the `Occurrence`/grouping key this
    // records (IDEA.md "Grouping and lifecycle" needs kind+path+cause for
    // the group, plus method/target/status/referer for the occurrence
    // detail shown per-group) — collapsing them into a struct here would
    // just move the same fields one level out without reducing what call
    // sites (scattered across request handling) have to supply.
    #[allow(clippy::too_many_arguments)]
    pub fn record_issue(
        &self,
        kind: IssueKind,
        path: &str,
        cause: &str,
        method: &str,
        target: &str,
        status: u16,
        referer: Option<String>,
    ) {
        let occ = Occurrence {
            unix_secs: now_secs(),
            method: method.to_string(),
            path: path.to_string(),
            target: target.to_string(),
            status,
            referer,
        };
        if let Ok(mut issues) = self.issues.lock() {
            issues.record(kind, path, cause, occ);
        }
    }
}

/// Renders the `/server-info` dashboard page (IDEA.md "`/server-info`
/// diagnostics dashboard"), matching the dark-themed mobile-first style of
/// `error_page`/`error_page_with_trace` and `proxy::starting_page`.
pub fn render_dashboard(
    stats: &Stats,
    opts: &ServeOptions,
    proxy_target: Option<&super::proxy::ProxyTarget>,
) -> String {
    let uptime = crate::supports::format::duration(stats.started_at.elapsed().as_secs());
    let started_at = super::format_http_date(stats.start_wall_secs);

    let overview = render_overview(stats, opts, proxy_target, &uptime, &started_at);
    let totals = render_totals(stats);
    let handler_table = render_handler_table(stats);
    let hot_paths = render_hot_paths(stats);
    let issues = render_issues(stats);

    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>cashttpd /server-info</title>\
         <style>body{{font-family:system-ui,sans-serif;margin:0;padding:2rem 1.25rem;\
         background:#0f172a;color:#e2e8f0;min-height:100vh;box-sizing:border-box}}\
         h1{{font-size:1.75rem;margin:0 0 1rem}}h2{{font-size:1.15rem;margin:2rem 0 .5rem;\
         color:#94a3b8}}.card{{max-width:56rem;margin:0 auto}}\
         .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));gap:.75rem}}\
         .stat{{background:#1e293b;border-radius:.5rem;padding:.75rem 1rem}}\
         .stat .n{{font-size:1.4rem;font-weight:600}}.stat .l{{font-size:.8rem;color:#94a3b8}}\
         table{{width:100%;border-collapse:collapse;font-size:.9rem}}\
         th,td{{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #334155}}\
         code{{background:#334155;padding:.1rem .35rem;border-radius:.25rem;word-break:break-all}}\
         details{{background:#1e293b;border-radius:.5rem;padding:.5rem .75rem;margin:.5rem 0}}\
         summary{{cursor:pointer}}pre{{white-space:pre-wrap;word-break:break-word;\
         background:#0f172a;padding:.5rem;border-radius:.35rem;overflow-x:auto}}\
         .badge{{display:inline-block;padding:.05rem .4rem;border-radius:.25rem;\
         font-size:.75rem;background:#334155}}</style></head><body><div class=\"card\">\
         <h1>cashttpd /server-info</h1>{overview}{totals}{handler_table}{hot_paths}{issues}\
         </div></body></html>"
    )
}

fn render_overview(
    stats: &Stats,
    opts: &ServeOptions,
    proxy_target: Option<&super::proxy::ProxyTarget>,
    uptime: &str,
    started_at: &str,
) -> String {
    let proxy_line = match proxy_target {
        Some(t) => {
            let pid = stats.proxy_child_pid.load(Ordering::SeqCst);
            let pid_label = if pid > 0 {
                format!("running, pid {pid}")
            } else {
                "not running".to_string()
            };
            format!(
                "<tr><td>Proxy target</td><td><code>{}</code> &rarr; <code>{}</code> \
                 (prefix <code>{}</code>, {pid_label})</td></tr>",
                html_escape(&t.kind),
                html_escape(&t.upstream),
                html_escape(&t.path_prefix)
            )
        }
        None => "<tr><td>Proxy target</td><td>none configured</td></tr>".to_string(),
    };
    format!(
        "<h2>Overview</h2><table>\
         <tr><td>Listen</td><td><code>{}:{}</code></td></tr>\
         <tr><td>TLS</td><td>{}</td></tr>\
         <tr><td>Base dir</td><td><code>{}</code></td></tr>\
         {proxy_line}\
         <tr><td>Sandboxing / child-lifecycle posture</td><td>{}</td></tr>\
         <tr><td>Started</td><td>{started_at}</td></tr>\
         <tr><td>Uptime</td><td>{uptime}</td></tr>\
         </table>",
        html_escape(&opts.listen),
        opts.port,
        if opts.tls_enabled {
            "enabled"
        } else {
            "disabled"
        },
        html_escape(&opts.base_dir.display().to_string()),
        html_escape(stats.sandboxing_posture),
    )
}

fn render_totals(stats: &Stats) -> String {
    let total = stats.total_requests();
    let in_flight = stats.in_flight.load(Ordering::Relaxed).max(0);
    let active_upstream = stats.active_upstream.load(Ordering::Relaxed).max(0);
    let rate = stats
        .rate
        .lock()
        .map(|r| r.rate_per_sec(now_secs()))
        .unwrap_or(0.0);
    let bytes_sent = stats.bytes_sent.load(Ordering::Relaxed);
    let bytes_received = stats.bytes_received.load(Ordering::Relaxed);

    let mut by_method_rows = String::new();
    if let Ok(m) = stats.by_method.lock() {
        let mut entries: Vec<(&String, &u64)> = m.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for (method, count) in entries {
            by_method_rows.push_str(&format!(
                "<tr><td>{}</td><td>{count}</td></tr>",
                html_escape(method)
            ));
        }
    }

    let mut by_status_rows = String::new();
    if let Ok(m) = stats.by_status.lock() {
        let mut entries: Vec<(&u16, &u64)> = m.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for (status, count) in entries {
            by_status_rows.push_str(&format!("<tr><td>{status}</td><td>{count}</td></tr>"));
        }
    }
    if let Ok(m) = stats.by_class.lock() {
        let mut entries: Vec<(&&str, &u64)> = m.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for (class, count) in entries {
            by_status_rows.push_str(&format!(
                "<tr><td><span class=\"badge\">{class}</span></td><td>{count}</td></tr>"
            ));
        }
    }

    format!(
        "<h2>Request/response stats</h2><div class=\"grid\">\
         <div class=\"stat\"><div class=\"n\">{total}</div><div class=\"l\">total requests</div></div>\
         <div class=\"stat\"><div class=\"n\">{in_flight}</div><div class=\"l\">in-flight</div></div>\
         <div class=\"stat\"><div class=\"n\">{active_upstream}</div><div class=\"l\">active upstream conns</div></div>\
         <div class=\"stat\"><div class=\"n\">{rate:.2}/s</div><div class=\"l\">requests/sec (60s window)</div></div>\
         <div class=\"stat\"><div class=\"n\">{}</div><div class=\"l\">bytes sent</div></div>\
         <div class=\"stat\"><div class=\"n\">{}</div><div class=\"l\">bytes received</div></div>\
         </div>\
         <table><tr><th>By method</th><th></th></tr>{by_method_rows}</table>\
         <table><tr><th>By status</th><th></th></tr>{by_status_rows}</table>",
        crate::supports::format::size(bytes_sent),
        crate::supports::format::size(bytes_received),
    )
}

fn render_handler_table(stats: &Stats) -> String {
    let mut rows = String::new();
    if let Ok(m) = stats.by_handler.lock() {
        for handler in HandlerType::ALL {
            let Some(h) = m.get(&handler) else {
                continue;
            };
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}ms</td><td>{}ms</td><td>{}ms</td>\
                 <td>{}ms</td><td>{}ms</td></tr>",
                handler.label(),
                h.count,
                h.min_ms,
                h.avg_ms(),
                h.max_ms,
                h.percentile(0.50),
                h.percentile(0.95),
            ));
        }
    }
    if rows.is_empty() {
        return "<h2>By handler type</h2><p>No requests served yet.</p>".to_string();
    }
    format!(
        "<h2>By handler type</h2><table><tr><th>Handler</th><th>Count</th><th>Min</th>\
         <th>Avg</th><th>Max</th><th>p50</th><th>p95</th></tr>{rows}</table>"
    )
}

fn render_hot_paths(stats: &Stats) -> String {
    let top = stats
        .top_paths
        .lock()
        .map(|p| p.top(10))
        .unwrap_or_default();
    let top_errors = stats
        .top_error_paths
        .lock()
        .map(|p| p.top(10))
        .unwrap_or_default();

    let rows = |entries: &[(String, u64)]| -> String {
        entries
            .iter()
            .map(|(p, c)| {
                format!(
                    "<tr><td><code>{}</code></td><td>{c}</td></tr>",
                    html_escape(p)
                )
            })
            .collect()
    };

    format!(
        "<h2>Hot paths</h2><table><tr><th>Most requested</th><th>Hits</th></tr>{}</table>\
         <table><tr><th>Most error-prone</th><th>Errors</th></tr>{}</table>",
        rows(&top),
        rows(&top_errors),
    )
}

fn render_cause_detail(g: &IssueGroup) -> String {
    if matches!(
        g.kind,
        IssueKind::ScriptFailure | IssueKind::MissingLanguageModule
    ) {
        format!("<pre>{}</pre>", html_escape(&g.cause))
    } else {
        html_escape(&g.cause)
    }
}

fn render_issues(stats: &Stats) -> String {
    let Ok(issues) = stats.issues.lock() else {
        return String::new();
    };
    if issues.groups.is_empty() {
        return "<h2>Issues</h2><p>No issues recorded since start.</p>".to_string();
    }
    let mut groups: Vec<(&(IssueKind, String, String), &IssueGroup)> =
        issues.groups.iter().collect();
    groups.sort_by_key(|(_, g)| std::cmp::Reverse(g.last_seen));

    let body: String = groups
        .iter()
        .map(|(key, g)| {
            let path = &key.1;
            let occurrences: String = g
                .occurrences
                .iter()
                .rev()
                .map(|o| {
                    let referer = o
                        .referer
                        .as_deref()
                        .map(|r| format!(" (referred from <code>{}</code>)", html_escape(r)))
                        .unwrap_or_default();
                    format!(
                        "<tr><td>{}</td><td>{}</td><td><code>{}</code></td>\
                         <td><code>{}</code></td><td>{}</td><td>{referer}</td></tr>",
                        super::format_http_date(o.unix_secs),
                        html_escape(&o.method),
                        html_escape(&o.path),
                        html_escape(&o.target),
                        o.status,
                    )
                })
                .collect();
            format!(
                "<details><summary>[{}] <code>{}</code> &mdash; {} \
                 (&times;{}, last seen {})</summary>\
                 <p>{}</p>\
                 <table><tr><th>When</th><th>Method</th><th>Path</th><th>Target</th>\
                 <th>Status</th><th>Referer</th></tr>{occurrences}</table></details>",
                g.kind.label(),
                html_escape(path),
                html_escape(&g.cause_summary()),
                g.count,
                super::format_http_date(g.last_seen),
                render_cause_detail(g),
            )
        })
        .collect();

    format!("<h2>Issues</h2>{body}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_opts() -> ServeOptions {
        crate::configs::Resolved {
            base_dir: std::env::temp_dir(),
            listen: "127.0.0.1".to_string(),
            port: 8080,
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
            ssi_extensions: crate::configs::builtin_ssi_extensions(),
            security_headers: crate::configs::builtin_security_headers(
                false,
                crate::configs::ServerTokens::Full,
            ),
            cors: Some(crate::configs::builtin_cors_headers()),
            project_config_path: PathBuf::new(),
        }
    }

    #[test]
    fn records_totals_by_method_and_status_and_class() {
        let stats = Stats::new("test posture");
        stats.record_totals("GET", "/a", 200, 100, 0);
        stats.record_totals("GET", "/b", 404, 0, 0);
        stats.record_totals("POST", "/c", 500, 10, 20);
        assert_eq!(stats.total_requests(), 3);
        let by_method = stats.by_method.lock().unwrap();
        assert_eq!(by_method.get("GET"), Some(&2));
        assert_eq!(by_method.get("POST"), Some(&1));
        drop(by_method);
        let by_status = stats.by_status.lock().unwrap();
        assert_eq!(by_status.get(&200), Some(&1));
        assert_eq!(by_status.get(&404), Some(&1));
        drop(by_status);
        let by_class = stats.by_class.lock().unwrap();
        assert_eq!(by_class.get("2xx"), Some(&1));
        assert_eq!(by_class.get("4xx"), Some(&1));
        assert_eq!(by_class.get("5xx"), Some(&1));
    }

    #[test]
    fn records_handler_type_counts_and_latency() {
        let stats = Stats::new("test posture");
        stats.record_handler(HandlerType::StaticFile, Duration::from_millis(10));
        stats.record_handler(HandlerType::StaticFile, Duration::from_millis(20));
        stats.record_handler(HandlerType::ScriptCgi, Duration::from_millis(5));
        let by_handler = stats.by_handler.lock().unwrap();
        let sf = by_handler.get(&HandlerType::StaticFile).unwrap();
        assert_eq!(sf.count, 2);
        assert_eq!(sf.min_ms, 10);
        assert_eq!(sf.max_ms, 20);
        assert_eq!(sf.avg_ms(), 15);
        assert_eq!(by_handler.get(&HandlerType::ScriptCgi).unwrap().count, 1);
    }

    #[test]
    fn issue_grouping_increments_occurrence_count_not_new_entries() {
        let stats = Stats::new("test posture");
        for _ in 0..5 {
            stats.record_issue(
                IssueKind::BrokenStaticRef,
                "/css/main.css",
                "404 not found",
                "GET",
                "/base/css/main.css",
                404,
                Some("/index.html".to_string()),
            );
        }
        let issues = stats.issues.lock().unwrap();
        assert_eq!(issues.groups.len(), 1);
        let group = issues.groups.values().next().unwrap();
        assert_eq!(group.count, 5);
        assert!(group.occurrences.len() <= MAX_OCCURRENCES_PER_GROUP);
    }

    #[test]
    fn issue_grouping_keeps_distinct_cause_separate() {
        let stats = Stats::new("test posture");
        stats.record_issue(
            IssueKind::ScriptFailure,
            "/cgi-bin/a.pl",
            "exit code 1",
            "GET",
            "/base/cgi-bin/a.pl",
            500,
            None,
        );
        stats.record_issue(
            IssueKind::ScriptFailure,
            "/cgi-bin/a.pl",
            "exit code 2",
            "GET",
            "/base/cgi-bin/a.pl",
            500,
            None,
        );
        let issues = stats.issues.lock().unwrap();
        assert_eq!(issues.groups.len(), 2);
    }

    #[test]
    fn in_flight_guard_increments_and_decrements() {
        let stats = Stats::new("test posture");
        assert_eq!(stats.in_flight.load(Ordering::Relaxed), 0);
        {
            let _g = stats.in_flight_guard();
            assert_eq!(stats.in_flight.load(Ordering::Relaxed), 1);
        }
        assert_eq!(stats.in_flight.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn upstream_guard_increments_and_decrements() {
        let stats = Stats::new("test posture");
        {
            let _g = stats.upstream_guard();
            assert_eq!(stats.active_upstream.load(Ordering::Relaxed), 1);
        }
        assert_eq!(stats.active_upstream.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn render_dashboard_does_not_panic_on_empty_stats() {
        let stats = Stats::new("unavailable on this platform");
        let opts = test_opts();
        let html = render_dashboard(&stats, &opts, None);
        assert!(html.contains("/server-info"));
        assert!(html.contains("No issues recorded"));
    }

    #[test]
    fn render_dashboard_does_not_panic_on_populated_stats() {
        let stats = Stats::new("active (best-effort)");
        let opts = test_opts();
        stats.record_totals("GET", "/index.html", 200, 512, 0);
        stats.record_totals("GET", "/missing.css", 404, 0, 0);
        stats.record_handler(HandlerType::StaticFile, Duration::from_millis(3));
        stats.record_handler(HandlerType::ScriptCgi, Duration::from_millis(40));
        stats.record_issue(
            IssueKind::BrokenStaticRef,
            "/missing.css",
            "404 not found",
            "GET",
            "/base/missing.css",
            404,
            Some("/index.html".to_string()),
        );
        stats.record_issue(
            IssueKind::ScriptFailure,
            "/cgi-bin/broken.pl",
            "exited with status code 1\nsome stderr output",
            "GET",
            "/base/cgi-bin/broken.pl",
            500,
            None,
        );
        let target = super::super::proxy::ProxyTarget {
            kind: "vite".to_string(),
            command: "npm run dev".to_string(),
            upstream: "127.0.0.1:5173".to_string(),
            path_prefix: "/".to_string(),
        };
        stats.set_proxy_child_pid(1234);
        let html = render_dashboard(&stats, &opts, Some(&target));
        assert!(html.contains("missing.css"));
        assert!(html.contains("some stderr output"));
        assert!(html.contains("1234"));
        assert!(html.contains("vite"));
    }

    #[test]
    fn issue_list_evicts_oldest_group_on_overflow() {
        let stats = Stats::new("test posture");
        for i in 0..(MAX_ISSUE_GROUPS + 5) {
            stats.record_issue(
                IssueKind::BrokenStaticRef,
                &format!("/path-{i}"),
                "404 not found",
                "GET",
                &format!("/base/path-{i}"),
                404,
                None,
            );
        }
        let issues = stats.issues.lock().unwrap();
        assert!(issues.groups.len() <= MAX_ISSUE_GROUPS);
    }

    #[test]
    fn top_paths_bounded_and_sorted() {
        let stats = Stats::new("test posture");
        for i in 0..5 {
            for _ in 0..(i + 1) {
                stats.record_totals("GET", &format!("/p{i}"), 200, 0, 0);
            }
        }
        let top = stats.top_paths.lock().unwrap().top(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "/p4");
        assert_eq!(top[1].0, "/p3");
    }
}
