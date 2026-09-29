//! HPKE in PSK mode (RFC 9180 section 5.1.2), the one place the `hpke-rs` backend is used
//! directly: openmls's crypto trait exposes Base mode only, and a targeted message needs a PSK.
//! The KEM, KDF and AEAD come from the group's ciphersuite; nothing here names a suite.

use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use openmls_traits::types::{HpkeAeadType, HpkeKdfType, HpkeKemType};
use zeroize::Zeroizing;

use crate::suite_policy::TargetedSuite;

#[cfg(test)]
thread_local! {
    /// Number of times a content decryption was attempted on this thread. Tests read it to prove a
    /// refused message never reached the HPKE open.
    pub(super) static OPEN_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// When set, the HPKE ephemeral randomness of the next seal on this thread, so a test can
    /// compare the sealed bytes with a stored vector.
    pub(super) static EPHEMERAL_SEED: std::cell::RefCell<Option<Vec<u8>>> =
        const { std::cell::RefCell::new(None) };
}

/// The HPKE step failed. The reason is deliberately not carried: it never reveals key material
/// and the caller's typed refusal already names the step.
#[derive(Debug)]
pub(super) struct HpkeFailure;

const fn kem(kem: HpkeKemType) -> Option<KemAlgorithm> {
    Some(match kem {
        HpkeKemType::DhKemP256 => KemAlgorithm::DhKemP256,
        HpkeKemType::DhKemP384 => KemAlgorithm::DhKemP384,
        HpkeKemType::DhKemP521 => KemAlgorithm::DhKemP521,
        HpkeKemType::DhKem25519 => KemAlgorithm::DhKem25519,
        HpkeKemType::DhKem448 => KemAlgorithm::DhKem448,
        HpkeKemType::XWingKemDraft6 => return None,
    })
}

const fn kdf(kdf: HpkeKdfType) -> KdfAlgorithm {
    match kdf {
        HpkeKdfType::HkdfSha256 => KdfAlgorithm::HkdfSha256,
        HpkeKdfType::HkdfSha384 => KdfAlgorithm::HkdfSha384,
        HpkeKdfType::HkdfSha512 => KdfAlgorithm::HkdfSha512,
    }
}

const fn aead(aead: HpkeAeadType) -> Option<AeadAlgorithm> {
    Some(match aead {
        HpkeAeadType::AesGcm128 => AeadAlgorithm::Aes128Gcm,
        HpkeAeadType::AesGcm256 => AeadAlgorithm::Aes256Gcm,
        HpkeAeadType::ChaCha20Poly1305 => AeadAlgorithm::ChaCha20Poly1305,
        HpkeAeadType::Export => return None,
    })
}

fn hpke(suite: &TargetedSuite) -> Option<Hpke<HpkeRustCrypto>> {
    Some(Hpke::new(
        Mode::Psk,
        kem(suite.hpke_kem)?,
        kdf(suite.hpke_kdf),
        aead(suite.hpke_aead)?,
    ))
}

/// Two-step sender: encapsulate first (`SetupPSKS`), let `aad_for` build the AAD from the
/// `kem_output`, then seal. Returns `(kem_output, ciphertext)`.
pub(super) fn seal(
    suite: &TargetedSuite,
    recipient_public_key: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    aad_for: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), HpkeFailure> {
    let mut hpke = hpke(suite).ok_or(HpkeFailure)?;
    #[cfg(test)]
    if let Some(seed) = EPHEMERAL_SEED.with(|seed| seed.borrow_mut().take()) {
        hpke.seed(&seed).map_err(|_| HpkeFailure)?;
    }
    let (kem_output, mut context) = hpke
        .setup_sender(
            &HpkePublicKey::from(recipient_public_key),
            info,
            Some(psk),
            Some(psk_id),
            None,
        )
        .map_err(|_| HpkeFailure)?;
    let aad = aad_for(&kem_output).ok_or(HpkeFailure)?;
    let ciphertext = context.seal(&aad, plaintext).map_err(|_| HpkeFailure)?;
    Ok((kem_output, ciphertext))
}

/// Inputs of [`open`].
pub(super) struct OpenInput<'a> {
    pub kem_output: &'a [u8],
    pub recipient_private_key: &'a [u8],
    pub info: &'a [u8],
    pub aad: &'a [u8],
    pub ciphertext: &'a [u8],
    pub psk: &'a [u8],
    pub psk_id: &'a [u8],
}

/// `OpenPSK`: decrypt with the recipient's private key.
pub(super) fn open(
    suite: &TargetedSuite,
    input: &OpenInput<'_>,
) -> Result<Zeroizing<Vec<u8>>, HpkeFailure> {
    #[cfg(test)]
    OPEN_CALLS.with(|calls| calls.set(calls.get() + 1));
    let hpke = hpke(suite).ok_or(HpkeFailure)?;
    let plaintext = hpke
        .open(
            input.kem_output,
            &HpkePrivateKey::from(input.recipient_private_key),
            input.info,
            input.aad,
            input.ciphertext,
            Some(input.psk),
            Some(input.psk_id),
            None,
        )
        .map_err(|_| HpkeFailure)?;
    Ok(Zeroizing::new(plaintext))
}
