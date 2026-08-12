//! HTTP/HTTPS listener, routing, and request handling (IDEA.md
//! "Core behavior", "Security / access control model"). Serves `base_dir`
//! with strict canonicalize-then-check path safety — no traversal outside
//! `base_dir` under any circumstance. See TODO.AI.md for outstanding work.
