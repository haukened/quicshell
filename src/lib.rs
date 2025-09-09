//! Crate root for `quicshell`.
//!
//! This library layer exposes the public protocol / handshake type definitions
//! so they are rendered by `cargo doc`. Binaries (`qsh`, `qshd`) depend on the
//! same internal modules but don't by themselves produce rich documentation.
//!
//! High‑level tree:
//! * `core::protocol::handshake::types` – wire message structs & validation for the
//!   four‑message handshake.
//!
//! Additional modules will be surfaced here as they stabilize.
pub mod core;
