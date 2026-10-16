//! Sealing a small payload to a reader's long-term X25519 key (RFC 9180 Base mode, single shot).
//!
//! A reader derives its key pair from a 32-byte secret it already holds, with a purpose label, and publishes the
//! 32-byte public half. Anyone holding that public key can seal a payload to it; only the reader can open it.
//!
//! - **Derivation.** `ikm = HKDF-SHA256(salt = "detente reader key v1", ikm = seed, info = label, L = 32)`, then the
//!   KEM's `DeriveKeyPair` (RFC 9180 section 7.1.3) over that `ikm`. Two labels give unrelated keys.
//! - **Binding.** There is no `aad`: everything a seal is bound to goes through `info` (RFC 9180 section 8.1), so a
//!   payload opens only under the exact `info` it was sealed with.
//! - **Suite.** The KEM, KDF and AEAD come from [`reader_seal_suite`]. The key lengths and the derivation are
//!   X25519's, so a suite whose KEM is anything else is refused.
//! - **Refusals.** A public key or encapsulated key that is the wrong length, or a point of small order (the DH output
//!   is all zero, RFC 9180 section 7.1.4), is refused: a public key when it is received, an encapsulated key when it
//!   is opened. So is a payload that does not authenticate. A refusal carries no key material and does not say which
//!   check failed beyond its class.
//!
//! Each seal draws fresh randomness, so two seals of the same input differ.

use hkdf::Hkdf;
use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use openmls_traits::types::{HpkeAeadType, HpkeKdfType, HpkeKemType};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::suite_policy::{reader_seal_suite, ReaderSealSuite};

/// The salt of the derivation from a secret and a label to the key material the KEM derives from.
const DERIVATION_SALT: &[u8] = b"detente reader key v1";

/// Length of an X25519 private key, public key and encapsulated key.
pub const KEY_LEN: usize = 32;

#[cfg(test)]
thread_local! {
    /// When set, the HPKE ephemeral randomness (`ikmE`) of the next seal on this thread, so a test can compare a
    /// sealed payload with a published vector.
    pub(crate) static EPHEMERAL_SEED: std::cell::RefCell<Option<Vec<u8>>> =
        const { std::cell::RefCell::new(None) };
}

/// Why a seal, an open or a derivation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReaderSealError {
    /// The suite is not one this module can derive and seal with (its KEM is not X25519, or an algorithm is missing).
    #[error("the reader-seal suite is not supported")]
    Suite,
    /// A key is the wrong length, or is a point of small order.
    #[error("the key is malformed")]
    Key,
    /// The payload could not be sealed.
    #[error("the payload could not be sealed")]
    Seal,
    /// The payload did not open: wrong key, wrong `info`, or altered bytes.
    #[error("the payload did not open")]
    Open,
}

/// A reader's public key: 32 bytes of X25519.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderPublicKey([u8; KEY_LEN]);

impl ReaderPublicKey {
    /// The key from its 32 bytes. Any other length is refused, and so is a point of small order, the same way a seal
    /// to it would be: a key announced by someone else is refused when it is received, not at the first seal.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReaderSealError> {
        let key = <[u8; KEY_LEN]>::try_from(bytes).map_err(|_| ReaderSealError::Key)?;
        // A throwaway seal runs the KEM's own DH check (RFC 9180 section 7.1.4: an all-zero result is refused), so
        // no list of small-order encodings is kept here to get wrong. Its output is dropped.
        hpke(reader_seal_suite())
            .map_err(|_| ReaderSealError::Key)?
            .seal(
                &HpkePublicKey::from(key.as_slice()),
                &[],
                &[],
                &[],
                None,
                None,
                None,
            )
            .map_err(|_| ReaderSealError::Key)?;
        Ok(Self(key))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// A reader's private key; its bytes are wiped when it is dropped.
pub struct ReaderSecretKey(Zeroizing<[u8; KEY_LEN]>);

impl ReaderSecretKey {
    /// The key from its 32 bytes; any other length is refused.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReaderSealError> {
        <[u8; KEY_LEN]>::try_from(bytes)
            .map(|key| Self(Zeroizing::new(key)))
            .map_err(|_| ReaderSealError::Key)
    }
}

impl std::fmt::Debug for ReaderSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReaderSecretKey(..)")
    }
}

/// A reader's key pair.
#[derive(Debug)]
pub struct ReaderKeyPair {
    pub secret: ReaderSecretKey,
    pub public: ReaderPublicKey,
}

const fn x25519(suite: ReaderSealSuite) -> Result<(), ReaderSealError> {
    match suite.hpke_kem {
        HpkeKemType::DhKem25519 => Ok(()),
        _ => Err(ReaderSealError::Suite),
    }
}

fn hpke(suite: ReaderSealSuite) -> Result<Hpke<HpkeRustCrypto>, ReaderSealError> {
    x25519(suite)?;
    let kdf = match suite.hpke_kdf {
        HpkeKdfType::HkdfSha256 => KdfAlgorithm::HkdfSha256,
        HpkeKdfType::HkdfSha384 => KdfAlgorithm::HkdfSha384,
        HpkeKdfType::HkdfSha512 => KdfAlgorithm::HkdfSha512,
    };
    let aead = match suite.hpke_aead {
        HpkeAeadType::AesGcm128 => AeadAlgorithm::Aes128Gcm,
        HpkeAeadType::AesGcm256 => AeadAlgorithm::Aes256Gcm,
        HpkeAeadType::ChaCha20Poly1305 => AeadAlgorithm::ChaCha20Poly1305,
        HpkeAeadType::Export => return Err(ReaderSealError::Suite),
    };
    Ok(Hpke::new(Mode::Base, KemAlgorithm::DhKem25519, kdf, aead))
}

/// The key pair the KEM derives from `ikm` (RFC 9180 section 7.1.3).
pub(crate) fn derive_from_ikm(
    suite: ReaderSealSuite,
    ikm: &[u8],
) -> Result<ReaderKeyPair, ReaderSealError> {
    let pair = hpke(suite)?
        .derive_key_pair(ikm)
        .map_err(|_| ReaderSealError::Suite)?;
    let (secret, public) = pair.into_keys();
    Ok(ReaderKeyPair {
        secret: ReaderSecretKey::from_bytes(secret.as_slice())?,
        public: ReaderPublicKey::from_bytes(public.as_slice())?,
    })
}

/// The key pair for `label` derived from `seed`. The same seed and label always give the same pair; different labels
/// give unrelated pairs.
pub fn derive_reader_keypair(
    seed: &[u8; KEY_LEN],
    label: &[u8],
) -> Result<ReaderKeyPair, ReaderSealError> {
    let mut ikm = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(DERIVATION_SALT), seed)
        .expand(label, ikm.as_mut_slice())
        .map_err(|_| ReaderSealError::Key)?;
    derive_from_ikm(reader_seal_suite(), ikm.as_slice())
}

/// Seal `plaintext` to `public`, bound to `info`. Returns the encapsulated key and the ciphertext.
pub fn seal(
    public: &ReaderPublicKey,
    info: &[u8],
    plaintext: &[u8],
) -> Result<([u8; KEY_LEN], Vec<u8>), ReaderSealError> {
    let mut hpke = hpke(reader_seal_suite())?;
    #[cfg(test)]
    if let Some(seed) = EPHEMERAL_SEED.with(|seed| seed.borrow_mut().take()) {
        hpke.seed(&seed).map_err(|_| ReaderSealError::Seal)?;
    }
    let (enc, ciphertext) = hpke
        .seal(
            &HpkePublicKey::from(public.as_bytes().as_slice()),
            info,
            &[],
            plaintext,
            None,
            None,
            None,
        )
        .map_err(|_| ReaderSealError::Seal)?;
    let enc = <[u8; KEY_LEN]>::try_from(enc.as_slice()).map_err(|_| ReaderSealError::Seal)?;
    Ok((enc, ciphertext))
}

/// Open `ciphertext` sealed to the reader holding `secret`, under `info`.
pub fn open(
    secret: &ReaderSecretKey,
    enc: &[u8],
    info: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ReaderSealError> {
    if enc.len() != KEY_LEN {
        return Err(ReaderSealError::Key);
    }
    let plaintext = hpke(reader_seal_suite())?
        .open(
            enc,
            &HpkePrivateKey::from(secret.0.as_slice()),
            info,
            &[],
            ciphertext,
            None,
            None,
            None,
        )
        .map_err(|_| ReaderSealError::Open)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
#[path = "reader_seal_tests.rs"]
mod tests;
