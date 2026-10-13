//! Sealing data in parts, each part opened and checked on its own.
//!
//! The construction is STREAM, from "Online Authenticated-Encryption and its Nonce-Reuse
//! Misuse-Resistance" (Hoang, Reyhanitabar, Rogaway, Vizar; <https://eprint.iacr.org/2015/189>), as the
//! `aead` crate implements it in `aead::stream::StreamBE32`. None of it is implemented here: this
//! module names the suite, checks lengths and calls that implementation.
//!
//! Each part is one AEAD message. Its nonce is the stream's 7-byte prefix, then the part's position
//! as four big-endian bytes, then one byte that is 1 for the last part and 0 for every other. A part
//! therefore opens only at the position it was sealed at, and only with the same last-part flag. Bytes
//! offered at a position they were not sealed at are refused there, and a stream cut short is refused
//! at its new end when the reader opens that part as the last, because it was not sealed as the last.
//!
//! Parts open independently and in any order, so a reader can fetch and check one part without the
//! others. Sealing and opening keep no record between calls: the same part opens again at its own
//! position, and nothing here reports that a reader stopped before the last part.
//!
//! What the caller owes:
//! - One key and prefix pair seals ONE stream. Two streams sealed under the same pair repeat nonces,
//!   which breaks AES-GCM. A fresh random key for every stream meets this whatever the prefix.
//! - Each position of a stream is sealed ONCE. Sealing other bytes, or other associated data, at a
//!   position already sealed repeats that part's nonce. A caller that seals a part again, as when an
//!   interrupted transfer resumes, seals the same bytes under the same associated data or starts a
//!   new stream under a new key.
//! - The reader learns how many parts a stream has from somewhere it trusts, opens every one of
//!   them, and opens the last with `last` set. Nothing here tells a reader how many parts there are.
//! - `associated_data` is authenticated with every part and stored in none; sealing and opening pass
//!   the same bytes.
//! - The suite a stream was sealed under travels with the stream as its id; a reader opens under the
//!   suite that id names, not under the current default.
//! - Part lengths are bounded by the caller before a part is sealed or opened; a part is copied
//!   whole before it is checked.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::stream::{NewStream, StreamBE32, StreamPrimitive};
use aes_gcm::aead::{KeyInit, Payload};
use aes_gcm::Aes256Gcm;

use crate::suite_policy::SealedPartsSuite;

/// Bytes in a stream's key.
pub const KEY_LEN: usize = 32;
/// Bytes in a stream's nonce prefix.
pub const NONCE_PREFIX_LEN: usize = 7;
/// Bytes a sealed part is longer than its plaintext: the AEAD tag.
pub const PART_OVERHEAD: usize = 16;

/// One stream's key and nonce prefix, ready to seal or open any of its parts.
pub struct SealedParts {
    stream: StreamBE32<Aes256Gcm>,
}

impl SealedParts {
    /// A stream sealed under `suite` with `key` and `nonce_prefix`, both of exactly the suite's lengths.
    pub fn new(suite: SealedPartsSuite, key: &[u8], nonce_prefix: &[u8]) -> anyhow::Result<Self> {
        match suite {
            SealedPartsSuite::Aes256GcmStreamBe32 => {
                if nonce_prefix.len() != NONCE_PREFIX_LEN {
                    anyhow::bail!(
                        "sealed_parts: the nonce prefix is {} bytes, not {NONCE_PREFIX_LEN}",
                        nonce_prefix.len()
                    );
                }
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| {
                    anyhow::anyhow!(
                        "sealed_parts: the key is {} bytes, not {KEY_LEN}",
                        key.len()
                    )
                })?;
                Ok(Self {
                    stream: StreamBE32::from_aead(cipher, GenericArray::from_slice(nonce_prefix)),
                })
            }
        }
    }

    /// Seal the part at `position`; `last` is set for the stream's final part and no other. Returns
    /// the ciphertext followed by its tag, [`PART_OVERHEAD`] bytes longer than `plaintext`.
    pub fn seal_part(
        &self,
        position: u32,
        last: bool,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        self.stream
            .encrypt(
                position,
                last,
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| anyhow::anyhow!("sealed_parts: part {position} could not be sealed"))
    }

    /// Open the part sealed at `position` with the same `last` and `associated_data`. Fail-closed:
    /// bytes sealed at another position, under another flag, key, prefix or associated data, or
    /// changed since, are refused and no plaintext is returned.
    pub fn open_part(
        &self,
        position: u32,
        last: bool,
        associated_data: &[u8],
        sealed: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        self.stream
            .decrypt(
                position,
                last,
                Payload {
                    msg: sealed,
                    aad: associated_data,
                },
            )
            .map_err(|_| anyhow::anyhow!("sealed_parts: part {position} did not open"))
    }
}

#[cfg(test)]
#[path = "sealed_parts_tests.rs"]
mod tests;
