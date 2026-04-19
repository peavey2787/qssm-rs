#![forbid(unsafe_code)]
//! # QSSM Core — Proving Engine
//!
//! The canonical Rust + WASM package for the QSSM truth engine.
//! Re-exports the 5 façade functions from `qssm-api` and provides
//! `#[wasm_bindgen]` bindings so browsers and JS runtimes can call them.
//!
//! ## Rust usage
//!
//! ```no_run
//! use qssm_core::{compile, commit, prove, verify, open};
//!
//! let blueprint = compile("age-gate-21").unwrap();
//! let commitment = commit(b"my-secret", &[1u8; 32]);
//! let claim = br#"{"claim":{"age_years":25}}"#;
//! let proof = prove(claim, &[1u8; 32], &blueprint).unwrap();
//! assert!(verify(&proof, &blueprint));
//! assert_eq!(open(b"my-secret", &[1u8; 32]), commitment);
//! ```

// ── Re-export the native Rust API ────────────────────────────────────

pub use qssm_api::{commit, compile, open, prove, verify};

// ── WASM bindings ────────────────────────────────────────────────────

mod wasm;
