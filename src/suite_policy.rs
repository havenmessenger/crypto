//! Crypto-agility ciphersuite seam.
//!
//! The single surface every call site asks *"which ciphersuite / symmetric algorithm do we
//! GENERATE with, and which inbound MLS suites do we ACCEPT?"*, so a future suite migration
//! (e.g. a PQ hybrid) becomes a change *here* rather than a hunt across scattered inline tokens.
//!
//! - **Generation** (Phase 1): `mls_generation_suite()` / `pgp_symmetric()` - what Haven produces.
//! - **Acceptance** (Phase 2): `gate_inbound_mls_suite()` + the `gate_inbound_keypackage` /
//!   `gate_inbound_welcome` call-site helpers - the EXPLICIT accept-pin that rejects any inbound
//!   MLS object whose suite ∉ the accepted-set BEFORE openmls touches it. This upgrades
//!   INV-MLS-002's accept-clause from *emergent* (we relied on openmls rejecting cross-suite Adds
//!   + on never holding a foreign `KeyPackage`) to *explicit + first-class*. WHY: INV-MLS-002.
//!
//! Generation and the accepted set are both `{0x0001}`, so the gate's decisions match the prior
//! emergent behavior byte-for-byte. This makes the accept-pin explicit without changing behavior.
//! The seam exists so a *future* 2nd suite (PQ) is a config change here; the moment the
//! accepted-set has >1 member the emergent guarantee evaporates and this explicit gate becomes the
//! sole guarantor, which is why it is built now, additively, and KAT-pinned on the real receive
//! path.
//!
//! These accessors/gates are `pub(crate)` - internal seam helpers, never FRB-exposed to Dart.

use openmls::prelude::{Ciphersuite, KeyPackage, Welcome};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use tls_codec::Serialize as TlsSerialize;

/// The MLS ciphersuite Haven GENERATES every group/KeyPackage with - the IANA
/// mandatory-to-implement baseline 0x0001 (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`). This
/// is the SINGLE generation source; every call site asks `mls_generation_suite()`, never the
/// suite inline. Changing it is a deliberate, KAT-gated, documented wire-format event (it forks
/// the bytes existing groups were built with). INV-MLS-002's `verify:` clause-1 greps THIS file
/// by name for the pinned token. WHY: INV-MLS-002.
pub const MLS_GENERATION_SUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// The MLS ciphersuite Haven generates with (pinned 0x0001). Call sites ask this, not the const.
#[must_use]
pub const fn mls_generation_suite() -> Ciphersuite {
    MLS_GENERATION_SUITE
}

/// The MLS ciphersuite(s) Haven ACCEPTS on inbound, as u16 wire values. Today: `{0x0001}`.
/// The accept-gate compares against this set. When a future suite is added (PQ), it joins here AND
/// `mls_generation_suite()` - a KAT-gated, two-sided wire event (INV-MLS-002).
pub const MLS_ACCEPTED_SUITE_U16: u16 = 0x0001;

/// Lockstep value with `mimi_core::gate::HAVEN_MLS_CIPHERSUITE_U16` (0x0001). mimi-core has no
/// compile-time link to this crate (the WASM-target build excludes it), so the two suite-gates are
/// a deliberate duplication kept honest by this documented value-match + the lockstep test below -
/// the same discipline as the `participant_list` codec. If mimi-core's pin ever changes, this must
/// change in lockstep.
#[must_use]
pub const fn mls_accepted_suites() -> &'static [u16] {
    &[MLS_ACCEPTED_SUITE_U16]
}

/// **The explicit MLS inbound accept-gate, parameterized over an explicit accepted-set.** Reject
/// `found` unless it is a member of `accepted`. This is the seam's actual "config, not code" shape -
/// `gate_inbound_mls_suite` below is production's single caller, always passing the pinned
/// `mls_accepted_suites()`. The parameterized form demonstrates the crypto-agility thesis
/// (INV-CRYPTO-AGILITY-001: "a future suite is a config+KAT add, not a wire rewrite") without
/// touching the pinned production accepted-set. See `suite_policy_pq_demo` (test-only) for the
/// demo exercising a hypothetical 2nd entry.
pub fn gate_inbound_mls_suite_against(found: u16, accepted: &[u16]) -> anyhow::Result<()> {
    if !accepted.contains(&found) {
        return Err(anyhow::anyhow!(
            "INV-MLS-002 accept-gate: refusing inbound MLS object with ciphersuite 0x{found:04x} \
             (only 0x{MLS_ACCEPTED_SUITE_U16:04x} accepted)"
        ));
    }
    Ok(())
}

/// **The explicit MLS inbound accept-gate.** Reject any inbound MLS object whose ciphersuite (as a
/// u16 wire value) is not in the accepted-set, BEFORE the bytes reach openmls' AEAD/HPKE path. With
/// the accepted-set = `{0x0001}` this gate is a no-op today; it becomes load-bearing the instant
/// a 2nd suite is accepted. WHY: INV-MLS-002 (accept-clause).
pub fn gate_inbound_mls_suite(found: u16) -> anyhow::Result<()> {
    gate_inbound_mls_suite_against(found, mls_accepted_suites())
}

/// The u16 wire ciphersuite of a *validated* `KeyPackage`. `validate()` is signature-only and
/// instantiates no AEAD, so reading the suite here is safe on a foreign-suite object.
#[must_use]
pub fn keypackage_suite_u16(kp: &KeyPackage) -> u16 {
    u16::from(kp.ciphersuite())
}

/// The u16 wire ciphersuite of an extracted `Welcome`. `Welcome::ciphersuite()` is `pub(crate)` in
/// openmls 0.8.1 (not callable from our crate), so - as `mimi_core::gate::mimi_gate_welcome`
/// does - we re-serialize and read the leading big-endian u16: per RFC 9420 the `Welcome` struct is
/// `{ CipherSuite cipher_suite; EncryptedGroupSecrets secrets<V>; opaque encrypted_group_info<V>; }`,
/// so the first two bytes ARE the ciphersuite. (mimi-core's `welcome_suite_layout` test pins this so
/// an openmls wire change can't silently defeat the gate; our flow KATs cross-check it - a wrong
/// offset would reject every real 0x0001 Welcome and fail `test_two_party_mls_flow`.)
pub fn welcome_suite_u16(welcome: &Welcome) -> anyhow::Result<u16> {
    let wire = welcome
        .tls_serialize_detached()
        .map_err(|e| anyhow::anyhow!("welcome_suite_u16: re-serialize failed: {e:?}"))?;
    if wire.len() < 2 {
        return Err(anyhow::anyhow!(
            "welcome_suite_u16: Welcome too short to carry a ciphersuite"
        ));
    }
    Ok(u16::from_be_bytes([wire[0], wire[1]]))
}

/// Call-site helper: gate an inbound `KeyPackage` before `add_members`. Reject if suite ∉ accepted.
pub fn gate_inbound_keypackage(kp: &KeyPackage) -> anyhow::Result<()> {
    gate_inbound_mls_suite(keypackage_suite_u16(kp))
}

/// Call-site helper: gate an inbound Welcome before `StagedWelcome::new_from_welcome`. Reject if its
/// suite ∉ accepted. Without this gate, a foreign-suite `Welcome` would otherwise reach and drive
/// `openmls`'s libcrux ChaCha20-Poly1305 HPKE-open on an unvalidated suite.
pub fn gate_inbound_welcome(welcome: &Welcome) -> anyhow::Result<()> {
    gate_inbound_mls_suite(welcome_suite_u16(welcome)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Generation regression pins - determinism guards; no published RFC "answer key"
    //     exists for a policy function. A change here is a deliberate,
    //     KAT-gated, documented wire-format event, never an incidental edit.
    #[test]
    fn test_mls_generation_suite_is_0x0001() {
        assert_eq!(
            mls_generation_suite(),
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        );
    }

    #[test]
    fn test_pgp_symmetric_is_aes256() {
        assert_eq!(pgp_symmetric(), SymmetricKeyAlgorithm::AES256);
    }

    // --- Accept-gate behavior (Phase 2) ---
    #[test]
    fn test_gate_accepts_pinned_rejects_foreign() {
        assert!(gate_inbound_mls_suite(0x0001).is_ok());
        assert!(gate_inbound_mls_suite(0x0003).is_err()); // ChaCha20-Poly1305 - foreign
        assert!(gate_inbound_mls_suite(0x0002).is_err()); // AES-256-GCM - foreign (not accepted yet)
        assert!(gate_inbound_mls_suite(0x0000).is_err());
    }

    // --- Regression pin (2026-07-03): the gate_inbound_mls_suite_against extraction must not have
    //     drifted the production accepted-set. ---
    #[test]
    fn test_accepted_suites_unchanged_after_gate_extraction() {
        assert_eq!(mls_accepted_suites(), &[0x0001u16]);
        assert_eq!(mls_accepted_suites().len(), 1);
    }

    // --- Lockstep: accept-set ⊇ what we generate, AND matches mimi-core/gate.rs's pinned value ---
    #[test]
    fn test_accept_set_matches_generation_and_mimi_core() {
        // We must accept what we generate (today both are 0x0001).
        assert!(mls_accepted_suites().contains(&u16::from(MLS_GENERATION_SUITE)));
        // Documented value-match with mimi_core::gate::HAVEN_MLS_CIPHERSUITE_U16 (= 0x0001).
        // mimi-core has no compile-time link to this crate (the WASM-target build excludes it) →
        // this literal IS the lockstep; if gate.rs's pin changes, change this in the same commit.
        assert_eq!(MLS_ACCEPTED_SUITE_U16, 0x0001);
    }
}

/// The symmetric algorithm Haven uses for `OpenPGP` message encryption (AES-256). Decryption
/// needs no seam - `OpenPGP` packets are self-describing, so rPGP reads the algorithm from the
/// message.
pub const PGP_SYMMETRIC: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES256;

/// Accessor for the PGP symmetric algorithm - call sites ask the seam, not the inline token.
#[must_use]
pub const fn pgp_symmetric() -> SymmetricKeyAlgorithm {
    PGP_SYMMETRIC
}
