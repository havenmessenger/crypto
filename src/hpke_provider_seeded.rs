//! Test builds only: a provider that forwards every primitive to `HpkeRustCrypto` and whose randomness a test can fix.
//!
//! RFC 9180's DH-KEM encapsulation derives the ephemeral key from `Nsk` random bytes (`ikmE`); a test sets
//! [`EPHEMERAL_SEED`] to a vector's `ikmE`, and the next HPKE context built on the same thread draws those bytes first.
//! Once they are used up, or when none were set, the bytes come from `HpkeRustCrypto`'s own generator.

use core::convert::Infallible;
use std::cell::RefCell;

use hpke_rs_crypto::error::Error;
use hpke_rs_crypto::types::{
    AeadAlgorithm, KdfAlgorithm, KemAlgorithm, SingleStageKdfAlgorithm, TwoStageKdfAlgorithm,
};
use hpke_rs_crypto::{HpkeCrypto, HpkeDefaultPrng, TryCryptoRng, TryRng};
use hpke_rs_rust_crypto::{HpkeRustCrypto, HpkeRustCryptoPrng};

thread_local! {
    /// When set, the first random bytes of the next HPKE context built on this thread, so a test can compare a sealed
    /// message with a stored vector.
    pub static EPHEMERAL_SEED: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

#[derive(Debug)]
pub struct SeededRustCrypto;

/// Serves the fixed bytes first, then the real generator's.
pub struct SeededPrng {
    fixed: Vec<u8>,
    rest: HpkeRustCryptoPrng,
}

impl TryRng for SeededPrng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let fixed = dst.len().min(self.fixed.len());
        dst[..fixed].copy_from_slice(&self.fixed[..fixed]);
        self.fixed.drain(..fixed);
        self.rest.try_fill_bytes(&mut dst[fixed..])
    }
}

impl TryCryptoRng for SeededPrng {}

impl HpkeDefaultPrng for SeededRustCrypto {
    fn try_prng() -> Result<Self::HpkePrng, Error> {
        Ok(SeededPrng {
            fixed: EPHEMERAL_SEED
                .with(|seed| seed.borrow_mut().take())
                .unwrap_or_default(),
            rest: HpkeRustCrypto::try_prng()?,
        })
    }
}

impl HpkeCrypto for SeededRustCrypto {
    type HpkePrng = SeededPrng;

    fn name() -> String {
        HpkeRustCrypto::name()
    }

    fn supports_kdf(alg: KdfAlgorithm) -> Result<(), Error> {
        HpkeRustCrypto::supports_kdf(alg)
    }

    fn supports_kem(alg: KemAlgorithm) -> Result<(), Error> {
        HpkeRustCrypto::supports_kem(alg)
    }

    fn supports_aead(alg: AeadAlgorithm) -> Result<(), Error> {
        HpkeRustCrypto::supports_aead(alg)
    }

    fn kdf_digest_length(alg: KdfAlgorithm) -> usize {
        HpkeRustCrypto::kdf_digest_length(alg)
    }

    fn kdf_extract(alg: TwoStageKdfAlgorithm, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::kdf_extract(alg, salt, ikm)
    }

    fn kdf_expand(
        alg: TwoStageKdfAlgorithm,
        prk: &[u8],
        info: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::kdf_expand(alg, prk, info, output_size)
    }

    fn kdf_derive(alg: SingleStageKdfAlgorithm, ikm: &[u8], l: usize) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::kdf_derive(alg, ikm, l)
    }

    fn dh(alg: KemAlgorithm, pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::dh(alg, pk, sk)
    }

    fn secret_to_public(alg: KemAlgorithm, sk: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::secret_to_public(alg, sk)
    }

    fn kem_key_gen(
        alg: KemAlgorithm,
        prng: &mut Self::HpkePrng,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        HpkeRustCrypto::kem_key_gen(alg, &mut prng.rest)
    }

    fn kem_key_gen_derand(alg: KemAlgorithm, seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        HpkeRustCrypto::kem_key_gen_derand(alg, seed)
    }

    fn kem_encaps(
        alg: KemAlgorithm,
        pk_r: &[u8],
        prng: &mut Self::HpkePrng,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        HpkeRustCrypto::kem_encaps(alg, pk_r, &mut prng.rest)
    }

    fn kem_encaps_derand(
        alg: KemAlgorithm,
        pk_r: &[u8],
        randomness: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        HpkeRustCrypto::kem_encaps_derand(alg, pk_r, randomness)
    }

    fn kem_decaps(alg: KemAlgorithm, ct: &[u8], sk_r: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::kem_decaps(alg, ct, sk_r)
    }

    fn dh_validate_sk(alg: KemAlgorithm, sk: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::dh_validate_sk(alg, sk)
    }

    fn aead_seal(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::aead_seal(alg, key, nonce, aad, msg)
    }

    fn aead_open(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::aead_open(alg, key, nonce, aad, msg)
    }

    fn aead_key_length(alg: AeadAlgorithm) -> usize {
        HpkeRustCrypto::aead_key_length(alg)
    }

    fn aead_nonce_length(alg: AeadAlgorithm) -> usize {
        HpkeRustCrypto::aead_nonce_length(alg)
    }

    fn aead_tag_length(alg: AeadAlgorithm) -> usize {
        HpkeRustCrypto::aead_tag_length(alg)
    }
}
