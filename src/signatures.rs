//! Detached Ed25519 signatures over exact document bytes (RFC 8032).
//!
//! The caller supplies the trusted public key and owns document purpose and encoding. These functions
//! do not parse documents or decide which keys are authorized.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Check that a public key has canonical encoding and non-small, prime order.
///
/// Keys produced by `sign_detached` satisfy these conditions. Application authorization belongs to
/// the caller. ZIP-215 point decoding alone also accepts aliases and unusable small-order keys.
#[must_use]
pub fn is_valid_public_key(public: &[u8; 32]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    let point = key.to_edwards();
    // Canonical equality also guards decoder changes; the order checks already reject these aliases.
    !key.is_weak() && point.is_torsion_free() && point.compress().to_bytes() == *public
}

/// Sign exact document bytes, returning the public key and detached signature.
///
/// The seed is borrowed; the caller remains responsible for erasing its own seed storage.
#[must_use]
pub fn sign_detached(seed: &[u8; 32], document: &[u8]) -> ([u8; 32], [u8; 64]) {
    let key = SigningKey::from_bytes(seed);
    (
        key.verifying_key().to_bytes(),
        key.sign(document).to_bytes(),
    )
}

/// Verify exact document bytes with strict Ed25519 verification, including small-order rejection.
///
/// A malformed key or invalid signature returns false. Key authorization belongs to the caller.
#[must_use]
pub fn verify_detached(public: &[u8; 32], document: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    key.verify_strict(document, &Signature::from_bytes(signature))
        .is_ok()
}

#[cfg(test)]
#[path = "signatures_tests.rs"]
mod tests;
