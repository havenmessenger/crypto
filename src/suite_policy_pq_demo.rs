//! **PQ crypto-agility seam-demo (2026-07-03). `#[cfg(test)]`-ONLY. Never compiled into a
//! release/production build; never FRB-reachable; not a dependency of anything.**
//!
//! IETF-126 hackathon `PoC` (Vienna, Jul 17–24 2026): demonstrates that `suite_policy`'s accept-gate
//! is config-driven rather than correct-by-hardcoding, by exercising it against a
//! hypothetical accepted-set that includes a placeholder for
//! `draft-ietf-mls-pq-ciphersuites-05`'s **TBD1** suite. This is the concrete evidence for
//! INV-CRYPTO-AGILITY-001's claim ("a future suite is a config+KAT add, not a wire rewrite").
//!
//! **What this proves:** `gate_inbound_mls_suite_against(found, accepted)` correctly accepts
//! `found` when it is a member of an arbitrary `accepted` slice, and the REAL production gate
//! (`gate_inbound_mls_suite`, which always uses the pinned `mls_accepted_suites()`) is completely
//! unaffected - it still rejects the same placeholder. **What this does NOT prove:** that PQ MLS
//! is live, that TBD1 is standardized, or that Haven accepts it - those remain gated behind (1)
//! IETF finalizing the draft, (2) openmls shipping a *released* crate carrying the feature (today
//! only available on openmls's unreleased `main` branch, behind its own
//! `draft-ietf-mls-pq-ciphersuites` cargo feature - verified by hand against a separate,
//! standalone lab experiment, never merged into this crate), and (3) a deliberate, two-sided,
//! KAT-gated, security-reviewed wire event adding the real codepoint to `MLS_ACCEPTED_SUITE_U16`
//! / `mls_generation_suite()` (INV-MLS-002).
//!
//! ## TBD1 ≡ X-Wing (resolved, not assumed)
//! `draft-ietf-mls-pq-ciphersuites-05` (fetched 2026-07-03, datatracker) names TBD1
//! `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`, HPKE KEM codepoint **`0x647a`**. Cross-checked
//! against `draft-connolly-cfrg-xwing-kem` §7 (IANA Considerations): `0x647a` (= 25519 + 203) is the
//! IANA-registered HPKE KEM ID for **X-Wing** (X25519 + ML-KEM-768 hybrid combiner; Nsecret=32,
//! Nenc=1120, Npk=1216, Nsk=32). Every MLS ciphersuite built on the X-Wing KEM - regardless of its
//! AEAD/hash pairing or provisional numbering across draft revisions - shares the same underlying
//! KEM construction and portability property: X-Wing needs no `libcrux`, and runs on the
//! `RustCrypto` provider, so the x86/AES-NI-only `libcrux` MLS provider's known platform-reach
//! limitation does not apply to it.

use crate::suite_policy::{
    gate_inbound_mls_suite, gate_inbound_mls_suite_against, mls_accepted_suites,
    MLS_ACCEPTED_SUITE_U16,
};

/// **NOT an IANA-assigned MLS ciphersuite codepoint.** `draft-ietf-mls-pq-ciphersuites-05` leaves
/// TBD1's real codepoint unassigned pending WG Chair Go-Ahead + IANA Expert Review (registry policy:
/// "Specification Required", per `iana.org/assignments/mls/mls.xhtml`, verified 2026-07-03). This
/// local value is drawn from that SAME registry's own **Private-Use range (`0xF000`–`0xFFFF`)** -
/// chosen precisely so it can never collide with a future real assignment. It exists solely to drive
/// the two tests below; it is never generated, never accepted, and never reachable from any
/// production or FRB call site.
pub const TBD1_LOCAL_DEMO_PLACEHOLDER_U16: u16 = 0xF001;

#[cfg(test)]
mod tests {
    use super::*;

    /// The seam-demo's headline assertion: a config list containing the TBD1 placeholder is
    /// accepted by the parameterized gate - proving the gate itself is config-driven, as
    /// INV-CRYPTO-AGILITY-001 claims a future suite addition would be.
    #[test]
    fn seam_accepts_tbd1_via_config_without_touching_production() {
        let demo_accepted = [MLS_ACCEPTED_SUITE_U16, TBD1_LOCAL_DEMO_PLACEHOLDER_U16];
        assert!(
            gate_inbound_mls_suite_against(TBD1_LOCAL_DEMO_PLACEHOLDER_U16, &demo_accepted).is_ok()
        );
        // The pinned suite is still accepted under the demo config too (a config add, not a swap).
        assert!(gate_inbound_mls_suite_against(MLS_ACCEPTED_SUITE_U16, &demo_accepted).is_ok());
    }

    /// The non-regression proof: the REAL production gate (pinned `mls_accepted_suites()`,
    /// unmodified by this demo module) still rejects the TBD1 placeholder. INV-MLS-002's
    /// two-sided pin is unaffected by the existence of the demo module.
    #[test]
    fn production_gate_still_rejects_tbd1_unconfigured() {
        assert!(gate_inbound_mls_suite(TBD1_LOCAL_DEMO_PLACEHOLDER_U16).is_err());
        assert_eq!(mls_accepted_suites(), &[0x0001u16]);
    }
}
