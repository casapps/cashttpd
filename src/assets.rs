//! Compile-time asset embedding (AI.md PART 0 "Self-Contained Assets").
//!
//! Default config, MIME tables, error pages, and other runtime assets are
//! embedded from the build-time-only `assets/` source tree via
//! `include_bytes!`/`include_str!` as they are added. See TODO.AI.md.
