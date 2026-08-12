//! Rust-based build/release automation for cashttpd (AI.md PART 5
//! "Project Layout"). Always executed inside the project's Docker image.

fn main() {
    let task = std::env::args().nth(1).unwrap_or_default();

    match task.as_str() {
        "" => println!("usage: xtask <task>"),
        other => println!("unknown task: {other}"),
    }
}
