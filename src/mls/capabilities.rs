//! What a leaf advertises, said outright.
//!
//! `openmls` no longer fills in a list the caller leaves out, so a leaf built with no capabilities advertises only its own
//! suite and credential type. These lists are what a leaf has always advertised here. Keeping them explicit keeps every
//! `KeyPackage`'s bytes the same, for members and hubs on any version of this library.

use openmls::prelude::*;

/// What a leaf advertises when nothing asks for more.
pub fn plain_leaf_capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        ]),
        None,
        None,
        Some(&[CredentialType::Basic]),
    )
}

#[cfg(test)]
#[path = "capabilities_tests.rs"]
mod tests;
