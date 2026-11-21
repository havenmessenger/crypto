//! The `hpke-rs` provider this crate's direct HPKE calls run on.
//!
//! openmls covers HPKE Base mode through its own crypto trait. Two places here call `hpke-rs` directly: targeted
//! messages, which need PSK mode (RFC 9180 section 5.1.2), and the reader seal, which runs the KEM's `DeriveKeyPair`
//! on its own key material. Both build their context through [`new`], on the provider openmls itself uses, so one
//! HPKE stack is linked.
//!
//! In a test build the provider is a stand-in that forwards every primitive to the real one, and whose randomness a
//! test can fix for the next context built on its thread (`EPHEMERAL_SEED`), so a sealed message can be compared byte
//! for byte with a stored vector.

use hpke_rs::{Hpke, HpkeError, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};

#[cfg(not(test))]
pub type HpkeProvider = hpke_rs_rust_crypto::HpkeRustCrypto;

#[cfg(test)]
pub use seeded::{SeededRustCrypto as HpkeProvider, EPHEMERAL_SEED};

/// An HPKE context for the given mode and algorithms. Its randomness comes from the system; if that can't be had,
/// the context is refused rather than built.
pub fn new(
    mode: Mode,
    kem: KemAlgorithm,
    kdf: KdfAlgorithm,
    aead: AeadAlgorithm,
) -> Result<Hpke<HpkeProvider>, HpkeError> {
    Hpke::try_new(mode, kem, kdf, aead)
}

#[cfg(test)]
#[path = "hpke_provider_seeded.rs"]
mod seeded;
