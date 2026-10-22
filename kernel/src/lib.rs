//! Portable CCP kernel.
//!
//! Implements the deterministic parts of the protocol — strict canonical
//! JSON, Ed25519, the schema subset, the §10.3 decision, and the §26.3
//! state machine — behind a plain Rust API, a C ABI, and a WASM build.

pub mod capi;
pub mod crypto;
pub mod decision;
pub mod json;
pub mod schema;
pub mod state_machine;
pub mod value;

pub use json::{parse_strict, serialize};
pub use value::Value;
