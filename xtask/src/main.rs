//! Rust-based build/release automation for cashttpd (AI.md PART 5
//! "Project Layout"). Always executed inside the project's Docker image.

fn main() {
    let task = std::env::args().nth(1).unwrap_or_default();
    println!("{}", dispatch(&task));
}

/// Dispatch logic split out from `main()` so it can be unit tested without
/// depending on real process argv.
fn dispatch(task: &str) -> String {
    match task {
        "" => "usage: xtask <task>".to_string(),
        other => format!("unknown task: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_with_no_task_reports_usage() {
        assert_eq!(dispatch(""), "usage: xtask <task>");
    }

    #[test]
    fn dispatch_with_unknown_task_reports_it() {
        assert_eq!(dispatch("build"), "unknown task: build");
    }
}
