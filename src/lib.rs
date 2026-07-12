// Haven crypto-core - pure cryptography + MLS/MIMI protocol logic, FRB-free.
//
// A standalone answer to "what is the cryptography?" with nothing app-specific: no
// `flutter_rust_bridge` dependency, no FRB macros, no app-binding types. See Cargo.toml's
// header for the same invariant restated at the manifest level.
pub mod crypto;
pub mod identity;
pub mod mime;
pub mod mimi;
pub mod mls;
pub mod pgp;
pub mod profile;
pub mod secret_store;
pub mod suite_policy;
// (2026-07-03): test-only PQ crypto-agility seam-demo (IETF-126 hackathon PoC).
// Never compiled into a release build; see suite_policy_pq_demo.rs header for full scope.
#[cfg(test)]
mod suite_policy_pq_demo;
