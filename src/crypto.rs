// Pure crypto primitives - PBKDF2, AES-GCM (+16-byte-IV variant), AES-CTR, HKDF-SHA256, BIP-39,
// HMAC-SHA256, secure-random bytes. FRB-free by construction: this crate has no
// `flutter_rust_bridge` dependency at all (see this crate's Cargo.toml header), so nothing here
// can depend on, or be reached only through, an app's binding layer.
//
// Every function in this module is a plain, ownership-explicit operation over byte buffers - one
// canonical entry point per operation, no duplicate call-shape pairs for the same algorithm.
//
// `needless_pass_by_value` on the `Vec<u8>` secret-material params is DELIBERATELY not fixed
// by narrowing to `&[u8]`: every such param is immediately wrapped in `zeroize::Zeroizing::new(..)`,
// which needs OWNERSHIP to wipe the caller's actual buffer on drop - a `&[u8]` signature would force
// an extra `.to_vec()` clone before wrapping, leaving the original (unwiped) copy alive longer. Owned
// `Vec<u8>` is the CORRECT crypto-hygiene choice here, not an idiom gap.
#![allow(clippy::needless_pass_by_value)]

use aes::Aes256;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type Aes256GcmIv16 = aes_gcm::AesGcm<aes::Aes256, aes_gcm::aead::generic_array::typenum::U16>;

/// A 32-byte symmetric key (AES-256-GCM/CTR). Validated once, at construction, so a wrong-length
/// byte slice is a constructor error rather than a check repeated inline in every function that
/// takes a key. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key32([u8; 32]);

impl Key32 {
    /// Validates `bytes` is exactly 32 bytes and takes ownership.
    pub fn from_vec(bytes: Vec<u8>) -> anyhow::Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() != 32 {
            anyhow::bail!("Key32: key must be 32 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A 12-byte AES-GCM nonce. Validated once, at construction. Not secret (a nonce is public by
/// design), so it does not zeroize.
#[derive(Clone, Copy)]
pub struct Nonce12([u8; 12]);

impl Nonce12 {
    /// Validates `bytes` is exactly 12 bytes and takes ownership.
    pub fn from_vec(bytes: Vec<u8>) -> anyhow::Result<Self> {
        if bytes.len() != 12 {
            anyhow::bail!("Nonce12: nonce must be 12 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 12];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// PBKDF2-HMAC-SHA256 derivation. Used by Haven's v2 chain to produce `master_root_key` from
/// `(passphrase, "haven-root:" + email_lc)` at 210,000 iterations, 32-byte output. WHY: INV-KEY-001
/// (`SECURITY-INVARIANTS.md`) - this key is the root of the identity-key custody chain.
pub fn pbkdf2_sha256(
    passphrase: String,
    salt: String,
    iterations: u32,
    output_bytes: u32,
) -> anyhow::Result<Vec<u8>> {
    validate_pbkdf2_params(iterations, output_bytes)?;
    let passphrase = Zeroizing::new(passphrase);
    let mut okm = vec![0u8; output_bytes as usize];
    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), salt.as_bytes(), iterations, &mut okm)
        .map_err(|e| anyhow::anyhow!("PBKDF2 failed: {e}"))?;
    Ok(okm)
}

/// Upper bound on PBKDF2 iterations. Haven's own production derivation runs at 210,000
/// (`INV-KEY-001`); this cap leaves an order of magnitude of headroom for a legitimate caller
/// tuning for slower/faster hardware while still bounding the CPU time an unbounded value could
/// force (unlike `output_bytes`, iterations has no allocation to cap - the risk here is wall-clock
/// time, not memory).
const MAX_PBKDF2_ITERATIONS: u32 = 2_000_000;

/// A missing/zero `iterations` must fail closed, not silently compute a one-iteration key
/// (under the pinned PBKDF2 implementation, zero rounds still runs the initial U1 block rather
/// than erroring). `output_bytes` is capped at the same RFC 5869-derived ceiling the HKDF fns in
/// this file already enforce (255*32=8160) - PBKDF2 has no analogous RFC max, but an unbounded
/// caller-supplied `output_bytes as usize` allocation (a large value can request ~4 GiB) should
/// fail closed rather than abort the process.
fn validate_pbkdf2_params(iterations: u32, output_bytes: u32) -> anyhow::Result<()> {
    if iterations == 0 {
        anyhow::bail!("PBKDF2: iterations must be > 0");
    }
    if iterations > MAX_PBKDF2_ITERATIONS {
        anyhow::bail!(
            "PBKDF2: iterations {iterations} exceeds the sane cap ({MAX_PBKDF2_ITERATIONS})"
        );
    }
    if output_bytes == 0 {
        anyhow::bail!("PBKDF2: output_bytes must be > 0");
    }
    if output_bytes > 255 * 32 {
        anyhow::bail!("PBKDF2: output_bytes {output_bytes} exceeds the sane cap (255*32=8160)");
    }
    Ok(())
}

/// PBKDF2-HMAC-SHA256 over raw password + salt BYTES - for the binary-salt at-rest
/// key-storage paths (`mobile_key_storage`/`haven_secure_storage`), which would be UTF-8-mangled by
/// the string form above. Byte-identical output to pointycastle for the same (password, salt, iters, dkLen).
pub fn pbkdf2_sha256_bytes(
    password: Vec<u8>,
    salt: Vec<u8>,
    iterations: u32,
    output_bytes: u32,
) -> anyhow::Result<Vec<u8>> {
    validate_pbkdf2_params(iterations, output_bytes)?;
    let password = Zeroizing::new(password);
    let mut okm = vec![0u8; output_bytes as usize];
    pbkdf2::<Hmac<Sha256>>(&password, &salt, iterations, &mut okm)
        .map_err(|e| anyhow::anyhow!("PBKDF2(bytes) failed: {e}"))?;
    Ok(okm)
}

/// AES-GCM-256 **seal**: mint a fresh 96-bit nonce from `OsRng`, encrypt, return `nonce(12) ‖ ct ‖ tag`.
pub fn aes_gcm_256_seal(key: Vec<u8>, plaintext: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let key = Key32::from_vec(key).map_err(|e| anyhow::anyhow!("aes_gcm_256_seal: {e}"))?;
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow::anyhow!("aes_gcm_256_seal: key init failed: {e}"))?;
    let mut rng = rand::rngs::OsRng;
    let nonce = Aes256Gcm::generate_nonce(&mut rng);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: &[],
            },
        )
        .map_err(|e| anyhow::anyhow!("aes_gcm_256_seal: GCM encrypt failed: {e}"))?;
    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-GCM-256 **open**: parse `nonce(12) ‖ ct ‖ tag`, decrypt. Fail-closed on a short buffer or any
/// tag mismatch. Reads both legacy and current blobs; the nonce is always on the wire.
pub fn aes_gcm_256_open(key: Vec<u8>, wire: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let key = Key32::from_vec(key).map_err(|e| anyhow::anyhow!("aes_gcm_256_open: {e}"))?;
    if wire.len() < 12 + 16 {
        anyhow::bail!(
            "aes_gcm_256_open: wire shorter than nonce(12)+tag(16) ({})",
            wire.len()
        );
    }
    let (nonce_bytes, ct_and_tag) = wire.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow::anyhow!("aes_gcm_256_open: key init failed: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct_and_tag,
                aad: &[],
            },
        )
        .map_err(|e| anyhow::anyhow!("aes_gcm_256_open: GCM open failed: {e}"))
}

/// AES-GCM-256 **seal** with a 16-byte IV minted from `OsRng` (`haven_secure_storage`'s Linux-desktop
/// fallback shape). Returns `iv(16) ‖ ct ‖ tag`.
pub fn aes_gcm_256_seal_iv16(key: Vec<u8>, plaintext: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let key = Key32::from_vec(key).map_err(|e| anyhow::anyhow!("aes_gcm_256_seal_iv16: {e}"))?;
    let cipher = Aes256GcmIv16::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow::anyhow!("aes_gcm_256_seal_iv16: key init failed: {e}"))?;
    let mut rng = rand::rngs::OsRng;
    let nonce = Aes256GcmIv16::generate_nonce(&mut rng);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: &[],
            },
        )
        .map_err(|e| anyhow::anyhow!("aes_gcm_256_seal_iv16: GCM encrypt failed: {e}"))?;
    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-GCM-256 **open** of an `iv(16) ‖ ct ‖ tag` blob (GHASH-derived J0 for the non-96-bit nonce).
/// Reads the existing pointycastle 16-byte-IV `haven_secure_storage` blobs byte-identically.
pub fn aes_gcm_256_open_iv16(key: Vec<u8>, wire: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::aead::generic_array::GenericArray;
    let key = Key32::from_vec(key).map_err(|e| anyhow::anyhow!("aes_gcm_256_open_iv16: {e}"))?;
    if wire.len() < 16 + 16 {
        anyhow::bail!(
            "aes_gcm_256_open_iv16: wire shorter than iv(16)+tag(16) ({})",
            wire.len()
        );
    }
    let (iv_bytes, ct_and_tag) = wire.split_at(16);
    let cipher = Aes256GcmIv16::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow::anyhow!("aes_gcm_256_open_iv16: key init failed: {e}"))?;
    let nonce = GenericArray::from_slice(iv_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct_and_tag,
                aad: &[],
            },
        )
        .map_err(|e| anyhow::anyhow!("aes_gcm_256_open_iv16: GCM open failed: {e}"))
}

/// HKDF-SHA256 **Expand** (RFC 5869 §2.3): expand a pseudorandom key `prk` to `out_len` bytes.
pub fn hkdf_sha256_expand(prk: Vec<u8>, info: Vec<u8>, out_len: u32) -> anyhow::Result<Vec<u8>> {
    let prk = Zeroizing::new(prk);
    let out_len = out_len as usize;
    if out_len > 255 * 32 {
        anyhow::bail!(
            "hkdf_sha256_expand: out_len {out_len} exceeds RFC 5869 max (255*HashLen=8160)"
        );
    }
    let hk = Hkdf::<Sha256>::from_prk(&prk)
        .map_err(|e| anyhow::anyhow!("hkdf_sha256_expand: invalid PRK (need >= 32 bytes): {e}"))?;
    let mut okm = vec![0u8; out_len];
    hk.expand(&info, &mut okm)
        .map_err(|e| anyhow::anyhow!("hkdf_sha256_expand: expand failed: {e}"))?;
    Ok(okm)
}

/// HKDF-SHA256 full **Extract-then-Expand** (RFC 5869 §2.2+§2.3). An empty `salt` uses the RFC
/// default (`HashLen` zero bytes) - the variant the client's login/key-derivation path actually
/// calls (not the Expand-only path).
pub fn hkdf_sha256(
    ikm: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    out_len: u32,
) -> anyhow::Result<Vec<u8>> {
    let ikm = Zeroizing::new(ikm);
    let out_len = out_len as usize;
    if out_len > 255 * 32 {
        anyhow::bail!("hkdf_sha256: out_len {out_len} exceeds RFC 5869 max (255*HashLen=8160)");
    }
    let salt_opt = if salt.is_empty() {
        None
    } else {
        Some(&salt[..])
    };
    let hk = Hkdf::<Sha256>::new(salt_opt, &ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(&info, &mut okm)
        .map_err(|e| anyhow::anyhow!("hkdf_sha256: expand failed: {e}"))?;
    Ok(okm)
}

/// LEGACY, UNAUTHENTICATED read path for symmetric blobs encrypted before this crate's AES-GCM
/// migration: CTR keystream over PKCS7-padded plaintext (a third-party crypto library's
/// `AESMode.sic` default, the format the client used previously). CTR is a stream cipher with no
/// integrity check - a bit-flip in the ciphertext produces a bit-flip in the recovered plaintext
/// with no way to detect it from this function alone; PKCS7-padding validation is the only
/// malformation check available here. Kept only so already-encrypted CTR blobs (MLS-identity
/// backup + contact-history) stay decryptable on a fresh-device restore, over already-authenticated
/// caller-controlled storage, not network input. Fail-closed on malformed PKCS7 (never returns
/// truncated plaintext). See `docs/THREAT_MODEL.md` for the residual this function represents.
pub fn aes_ctr_256_pkcs7_open(
    key: Vec<u8>,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    let key = Zeroizing::new(key);
    if key.len() != 32 {
        anyhow::bail!(
            "aes_ctr_256_pkcs7_open: key must be 32 bytes, got {}",
            key.len()
        );
    }
    if iv.len() != 16 {
        anyhow::bail!(
            "aes_ctr_256_pkcs7_open: iv must be 16 bytes, got {}",
            iv.len()
        );
    }
    let mut cipher = Aes256Ctr::new_from_slices(&key, &iv)
        .map_err(|e| anyhow::anyhow!("aes_ctr_256_pkcs7_open: init failed: {e}"))?;
    let mut buf = ciphertext;
    cipher.apply_keystream(&mut buf);
    let n = *buf
        .last()
        .ok_or_else(|| anyhow::anyhow!("aes_ctr_256_pkcs7_open: empty plaintext"))?
        as usize;
    if n == 0 || n > 16 || n > buf.len() {
        anyhow::bail!("aes_ctr_256_pkcs7_open: invalid PKCS7 pad length");
    }
    if buf[buf.len() - n..].iter().any(|&b| b as usize != n) {
        anyhow::bail!("aes_ctr_256_pkcs7_open: invalid PKCS7 padding");
    }
    buf.truncate(buf.len() - n);
    Ok(buf)
}

/// Generate a fresh 24-word English mnemonic from 256 bits of `OsRng` entropy.
pub fn bip39_generate_phrase() -> anyhow::Result<String> {
    use rand::RngCore;
    let mut entropy = Zeroizing::new(vec![0u8; 32]);
    rand::rngs::OsRng.fill_bytes(entropy.as_mut_slice());
    let m = bip39::Mnemonic::from_entropy(entropy.as_slice())
        .map_err(|e| anyhow::anyhow!("bip39_generate_phrase: {e}"))?;
    Ok(m.to_string())
}

/// Encode raw entropy → English mnemonic (appends the BIP-39 SHA256 checksum).
pub fn bip39_entropy_to_phrase(entropy: Vec<u8>) -> anyhow::Result<String> {
    let entropy = Zeroizing::new(entropy);
    let m = bip39::Mnemonic::from_entropy(entropy.as_slice())
        .map_err(|e| anyhow::anyhow!("bip39_entropy_to_phrase: {e}"))?;
    Ok(m.to_string())
}

/// Decode an English mnemonic → raw entropy, verifying the wordlist + checksum. Input is expected
/// pre-normalized (lowercase, single-space) by the caller.
pub fn bip39_phrase_to_entropy(phrase: String) -> anyhow::Result<Vec<u8>> {
    let phrase = Zeroizing::new(phrase);
    let m = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &phrase)
        .map_err(|e| anyhow::anyhow!("bip39_phrase_to_entropy: {e}"))?;
    Ok(m.to_entropy())
}

/// Validate an English mnemonic (wordlist + checksum). Non-throwing. Input is expected
/// pre-normalized (lowercase, single-space) by the caller.
#[must_use]
pub fn bip39_validate(phrase: String) -> bool {
    bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &phrase).is_ok()
}

/// Upper bound on `random_bytes_secure`'s requested length. The largest real caller requests 32
/// bytes; this cap bounds the allocation an unbounded `len` (up to `u32::MAX`, ~4 GiB) could force
/// while leaving generous headroom for any legitimate key-material size.
const MAX_RANDOM_BYTES_LEN: u32 = 65536;

/// Generate `len` cryptographically-secure random bytes from `OsRng` - the single Rust-stack
/// key-material generator (secret KEY material only - nonce/salt generation stays in the
/// client's Dart layer by design).
pub fn random_bytes_secure(len: u32) -> anyhow::Result<Vec<u8>> {
    use rand::RngCore;
    if len > MAX_RANDOM_BYTES_LEN {
        anyhow::bail!(
            "random_bytes_secure: len {len} exceeds the sane cap ({MAX_RANDOM_BYTES_LEN})"
        );
    }
    let mut bytes = vec![0u8; len as usize];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// HMAC-SHA256(key, msg) → 32-byte digest. Used as the subkey-derivation primitive in the
/// client's vault key chain (see `secret_store` module docs for the chain shape).
pub fn hmac_sha256(key: Vec<u8>, msg: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    // The key must be wrapped so it wipes on drop - every other secret-key-taking fn in this
    // file already wraps its key in Zeroizing (PBKDF2/AES/HKDF). The documented caller is
    // subkey derivation (secret_store's vault chain), so this can be master/derived key
    // material, not disposable test bytes.
    let key = Zeroizing::new(key);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("HMAC key init failed: {e}"))?;
    mac.update(&msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Constrained primitives kept for byte-compatibility with an existing wire format, not for new
/// use. Both functions here require the caller to supply state that the equivalent main-surface
/// function derives safely on its own: a caller-chosen nonce (reusing one under GCM breaks both
/// confidentiality and authentication for every message that reused it), or no authentication at
/// all (CTR is a stream cipher with no integrity check - a bit-flip in the ciphertext produces a
/// bit-flip in the recovered plaintext with no way to detect it). Reaching into this module by
/// name is a visible, reviewable decision; no other function in this crate calls into it. This is
/// distinct from [`super::aes_ctr_256_pkcs7_open`], a main-surface function with its own
/// unauthenticated-CTR residual documented at its definition - that function does not route
/// through this module either, it implements its own legacy read path directly.
pub mod compat {
    use super::{Aes256Ctr, Aes256Gcm, Key32, Nonce12};
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Nonce,
    };
    use ctr::cipher::{KeyIvInit, StreamCipher};

    /// AES-GCM-256 encrypt with a CALLER-SUPPLIED nonce. Returns `ct || tag`. The caller is
    /// responsible for nonce uniqueness across every encryption under the same key; this
    /// function does not and cannot enforce it. Prefer [`super::aes_gcm_256_seal`] (mints a
    /// fresh nonce internally) unless a specific, reviewed reason requires controlling the
    /// nonce directly.
    pub fn aes_gcm_256_encrypt_caller_nonce_hazard(
        key: Vec<u8>,
        nonce: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let key = Key32::from_vec(key)
            .map_err(|e| anyhow::anyhow!("aes_gcm_256_encrypt_caller_nonce_hazard: {e}"))?;
        let nonce = Nonce12::from_vec(nonce)
            .map_err(|e| anyhow::anyhow!("aes_gcm_256_encrypt_caller_nonce_hazard: {e}"))?;
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|e| {
            anyhow::anyhow!("aes_gcm_256_encrypt_caller_nonce_hazard: key init failed: {e}")
        })?;
        let nonce = Nonce::from_slice(nonce.as_bytes());
        cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: &[],
                },
            )
            .map_err(|e| {
                anyhow::anyhow!("aes_gcm_256_encrypt_caller_nonce_hazard: GCM encrypt failed: {e}")
            })
    }

    /// AES-GCM-256 decrypt with a caller-supplied nonce. Input is `ct || tag`. The read-side
    /// sibling of [`aes_gcm_256_encrypt_caller_nonce_hazard`] - decrypting carries no misuse
    /// hazard of its own (any nonce/key/ciphertext combination either authenticates or fails
    /// closed); it lives here for pairing symmetry with its encrypt sibling.
    pub fn aes_gcm_256_decrypt_caller_nonce_hazard(
        key: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext_and_tag: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let key = Key32::from_vec(key)
            .map_err(|e| anyhow::anyhow!("aes_gcm_256_decrypt_caller_nonce_hazard: {e}"))?;
        let nonce = Nonce12::from_vec(nonce)
            .map_err(|e| anyhow::anyhow!("aes_gcm_256_decrypt_caller_nonce_hazard: {e}"))?;
        if ciphertext_and_tag.len() < 16 {
            anyhow::bail!(
                "aes_gcm_256_decrypt_caller_nonce_hazard: ciphertext shorter than 16-byte tag ({})",
                ciphertext_and_tag.len()
            );
        }
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|e| {
            anyhow::anyhow!("aes_gcm_256_decrypt_caller_nonce_hazard: key init failed: {e}")
        })?;
        let nonce = Nonce::from_slice(nonce.as_bytes());
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext_and_tag,
                    aad: &[],
                },
            )
            .map_err(|e| {
                anyhow::anyhow!("aes_gcm_256_decrypt_caller_nonce_hazard: GCM decrypt failed: {e}")
            })
    }

    /// AES-CTR-256 encrypt. IV is 16 bytes, counter is 128-bit BE. Stream cipher, no
    /// authentication - output length equals input length, and any bit-flip in the ciphertext
    /// silently flips the corresponding plaintext bit on decrypt.
    pub fn aes_ctr_256_encrypt(
        key: Vec<u8>,
        iv: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let key = Key32::from_vec(key).map_err(|e| anyhow::anyhow!("aes_ctr_256_encrypt: {e}"))?;
        if iv.len() != 16 {
            anyhow::bail!("aes_ctr_256_encrypt: iv must be 16 bytes, got {}", iv.len());
        }
        let mut cipher = Aes256Ctr::new_from_slices(key.as_bytes(), &iv)
            .map_err(|e| anyhow::anyhow!("aes_ctr_256_encrypt: init failed: {e}"))?;
        let mut buf = plaintext;
        cipher.apply_keystream(&mut buf);
        Ok(buf)
    }

    /// AES-CTR-256 decrypt. Symmetric to encrypt - CTR XORs the keystream.
    pub fn aes_ctr_256_decrypt(
        key: Vec<u8>,
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let key = Key32::from_vec(key).map_err(|e| anyhow::anyhow!("aes_ctr_256_decrypt: {e}"))?;
        if iv.len() != 16 {
            anyhow::bail!("aes_ctr_256_decrypt: iv must be 16 bytes, got {}", iv.len());
        }
        let mut cipher = Aes256Ctr::new_from_slices(key.as_bytes(), &iv)
            .map_err(|e| anyhow::anyhow!("aes_ctr_256_decrypt: init failed: {e}"))?;
        let mut buf = ciphertext;
        cipher.apply_keystream(&mut buf);
        Ok(buf)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// NIST SP 800-38D Test Case 13 - AES-256-GCM, empty plaintext.
        #[test]
        fn kat_aes_gcm_256_empty_plaintext() {
            let key = vec![0u8; 32];
            let nonce = vec![0u8; 12];
            let ct = aes_gcm_256_encrypt_caller_nonce_hazard(key.clone(), nonce.clone(), vec![])
                .unwrap();
            let expected_tag = hex::decode("530f8afbc74536b9a963b4f1c4cb738b").unwrap();
            assert_eq!(ct, expected_tag, "empty-plaintext GCM tag matches NIST KAT");
            let pt = aes_gcm_256_decrypt_caller_nonce_hazard(key, nonce, ct).unwrap();
            assert!(pt.is_empty(), "round-trip empty plaintext");
        }

        /// Round-trip with a realistic 1KB CipherStore-sized blob.
        #[test]
        fn aes_gcm_256_round_trip_1kb() {
            let key: Vec<u8> = (0u8..32).collect();
            let nonce: Vec<u8> = (0u8..12).collect();
            let pt: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
            let ct =
                aes_gcm_256_encrypt_caller_nonce_hazard(key.clone(), nonce.clone(), pt.clone())
                    .unwrap();
            assert_eq!(ct.len(), pt.len() + 16, "ciphertext = pt_len + 16-byte tag");
            let dec = aes_gcm_256_decrypt_caller_nonce_hazard(key, nonce, ct).unwrap();
            assert_eq!(dec, pt, "round-trip 1KB plaintext");
        }

        /// Tag-mismatch must fail decrypt (catches wire tamper / wrong key).
        #[test]
        fn aes_gcm_256_tag_mismatch_fails() {
            let key = vec![0u8; 32];
            let nonce = vec![0u8; 12];
            let pt = b"hello world".to_vec();
            let mut ct =
                aes_gcm_256_encrypt_caller_nonce_hazard(key.clone(), nonce.clone(), pt.clone())
                    .unwrap();
            let last = ct.len() - 1;
            ct[last] ^= 0x01;
            let err = aes_gcm_256_decrypt_caller_nonce_hazard(key, nonce, ct);
            assert!(err.is_err(), "tampered tag must fail decrypt");
        }

        /// AES-CTR-256 round-trip. Stream cipher - output length = input length.
        #[test]
        fn aes_ctr_256_round_trip() {
            let key: Vec<u8> = (0u8..32).collect();
            let iv: Vec<u8> = (0u8..16).collect();
            let pt = b"haven contact history payload, varied length, no PKCS7".to_vec();
            let ct = aes_ctr_256_encrypt(key.clone(), iv.clone(), pt.clone()).unwrap();
            assert_eq!(ct.len(), pt.len(), "CTR output length equals input");
            assert_ne!(ct, pt, "ciphertext differs from plaintext");
            let dec = aes_ctr_256_decrypt(key, iv, ct).unwrap();
            assert_eq!(dec, pt, "CTR round-trip");
        }

        /// RFC 3686 §6 test vector #9: AES-256-CTR. Locks the counter convention (128-bit BE
        /// increment).
        #[test]
        fn kat_aes_ctr_256_rfc3686_vector() {
            let key =
                hex::decode("FF7A617CE69148E4F1726E2F43581DE2AA62D9F805532EDFF1EED687FB54153D")
                    .unwrap();
            let iv = hex::decode("001CC5B751A51D70A1C1114800000001").unwrap();
            let pt = hex::decode(
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223",
            )
            .unwrap();
            let expected_ct = hex::decode(
                "EB6C52821D0BBBF7CE7594462ACA4FAAB407DF866569FD07F48CC0B583D6071F1EC0E6B8",
            )
            .unwrap();
            let ct = aes_ctr_256_encrypt(key, iv, pt).unwrap();
            assert_eq!(ct, expected_ct, "RFC 3686 §6 AES-256-CTR vector #9");
        }

        /// A wrong-length key or nonce is rejected at construction, before any cipher init runs.
        #[test]
        fn rejects_wrong_length_key_and_nonce() {
            let short_key = vec![0u8; 16];
            let full_key = vec![0u8; 32];
            let short_nonce = vec![0u8; 8];
            let full_nonce = vec![0u8; 12];
            assert!(aes_gcm_256_encrypt_caller_nonce_hazard(
                short_key.clone(),
                full_nonce.clone(),
                vec![]
            )
            .is_err());
            assert!(
                aes_gcm_256_encrypt_caller_nonce_hazard(full_key, short_nonce, vec![]).is_err()
            );
            assert!(aes_ctr_256_encrypt(short_key, vec![0u8; 16], vec![]).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Key32` rejects any length other than exactly 32 bytes, both directions.
    #[test]
    fn key32_rejects_wrong_length() {
        assert!(Key32::from_vec(vec![0u8; 31]).is_err(), "too short");
        assert!(Key32::from_vec(vec![0u8; 33]).is_err(), "too long");
        assert!(
            Key32::from_vec(vec![0u8; 32]).is_ok(),
            "exact length accepted"
        );
    }

    /// `Nonce12` rejects any length other than exactly 12 bytes, both directions.
    #[test]
    fn nonce12_rejects_wrong_length() {
        assert!(Nonce12::from_vec(vec![0u8; 11]).is_err(), "too short");
        assert!(Nonce12::from_vec(vec![0u8; 13]).is_err(), "too long");
        assert!(
            Nonce12::from_vec(vec![0u8; 12]).is_ok(),
            "exact length accepted"
        );
    }

    /// The main-surface GCM functions reject a wrong-length key at the same construction step,
    /// before any cipher init runs - proven through the public functions, not just the
    /// constructor in isolation.
    #[test]
    fn aes_gcm_256_seal_and_open_reject_wrong_length_key() {
        assert!(aes_gcm_256_seal(vec![0u8; 16], b"x".to_vec()).is_err());
        assert!(aes_gcm_256_open(vec![0u8; 16], vec![0u8; 40]).is_err());
        assert!(aes_gcm_256_seal_iv16(vec![0u8; 16], b"x".to_vec()).is_err());
        assert!(aes_gcm_256_open_iv16(vec![0u8; 16], vec![0u8; 40]).is_err());
    }

    /// Known-Answer Test #1: RFC 6070-style PBKDF2 test vector (SHA-256 variant).
    #[test]
    fn kat_basic_vector() {
        let out = pbkdf2_sha256("password".into(), "salt".into(), 1, 32).unwrap();
        let expected =
            hex::decode("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
                .unwrap();
        assert_eq!(out, expected, "PBKDF2-SHA256(password, salt, 1, 32) KAT");
    }

    /// KAT #2: 2-iteration variant from the same RFC 6070-style table.
    #[test]
    fn kat_two_iterations() {
        let out = pbkdf2_sha256("password".into(), "salt".into(), 2, 32).unwrap();
        let expected =
            hex::decode("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
                .unwrap();
        assert_eq!(out, expected, "PBKDF2-SHA256(password, salt, 2, 32) KAT");
    }

    /// RFC 4231 test case 2 (HMAC-SHA-256) - the standard published KAT.
    #[test]
    fn kat_hmac_sha256_rfc4231_case2() {
        let key = b"Jefe".to_vec();
        let msg = b"what do ya want for nothing?".to_vec();
        let out = hmac_sha256(key, msg).unwrap();
        let expected =
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap();
        assert_eq!(out, expected, "HMAC-SHA256 RFC 4231 case 2 KAT");
    }

    /// Reproduces Haven's exact `deriveSubKey` shape - `HMAC-SHA256(masterKey, "haven:"+purpose)`.
    #[test]
    fn kat_derive_sub_key_shape() {
        let master_key = vec![0x42u8; 32];
        let msg = b"haven:vault-encryption".to_vec();
        let out = hmac_sha256(master_key.clone(), msg.clone()).unwrap();
        assert_eq!(out.len(), 32);
        let out2 = hmac_sha256(master_key, msg).unwrap();
        assert_eq!(out, out2, "hmac_sha256 must be deterministic");
    }

    /// Haven's actual production parameters - locks the wire format for the login critical path.
    #[test]
    fn kat_haven_production_shape() {
        let out = pbkdf2_sha256(
            "test-passphrase-not-real".into(),
            "haven-root:test@havenmessenger.com".into(),
            210_000,
            32,
        )
        .unwrap();
        assert_eq!(out.len(), 32, "master_root_key must be 32 bytes");
        let second_call = pbkdf2_sha256(
            "test-passphrase-not-real".into(),
            "haven-root:test@havenmessenger.com".into(),
            210_000,
            32,
        )
        .unwrap();
        assert_eq!(
            out, second_call,
            "PBKDF2 must be deterministic for identical inputs"
        );
    }

    /// Sanity: 32-byte zero output is impossible from a real PBKDF2 call.
    #[test]
    fn output_is_not_trivially_zero() {
        let out = pbkdf2_sha256("abc".into(), "def".into(), 1000, 32).unwrap();
        assert_ne!(out, vec![0u8; 32], "PBKDF2 must not produce all-zero key");
    }

    /// The LEGACY-READ data-loss gate: a REAL third-party-library `AES(key)` (SIC+PKCS7)
    /// blob, captured from an actual previously-encrypted value. Proves the Rust legacy
    /// reader decrypts the on-server CTR blobs byte-identically - if this drifts, a
    /// fresh-device restore loses the MLS identity.
    #[test]
    fn aes_ctr_256_pkcs7_open_real_encrypt_pkg_blob() {
        let key: Vec<u8> = (0u8..32).collect();
        let iv = hex::decode("07121d28333e49545f6a75808b96a1ac").unwrap();
        let ct = hex::decode(
            "0792d3576ce743b5c834c7ff6d9046261c224196354f95e598c188754ef47a48b6cfef665f4a78ecfc3b2ec575162d40",
        )
        .unwrap();
        let pt = aes_ctr_256_pkcs7_open(key, iv, ct).unwrap();
        assert_eq!(
            String::from_utf8(pt).unwrap(),
            r#"{"client_id":"abc","kp":"ZZ==","ts":1234567890}"#,
            "Rust legacy-read must decrypt the real encrypt-pkg SIC+PKCS7 blob byte-identically"
        );
    }

    /// Fail-closed: a tampered trailing byte flips the pad → invalid PKCS7 length. Must error, never
    /// return truncated/garbage plaintext (no padding oracle leak).
    #[test]
    fn aes_ctr_256_pkcs7_open_rejects_bad_pad() {
        let key: Vec<u8> = (0u8..32).collect();
        let iv = hex::decode("07121d28333e49545f6a75808b96a1ac").unwrap();
        let mut ct = hex::decode(
            "0792d3576ce743b5c834c7ff6d9046261c224196354f95e598c188754ef47a48b6cfef665f4a78ecfc3b2ec575162d40",
        )
        .unwrap();
        *ct.last_mut().unwrap() ^= 0xFF;
        assert!(
            aes_ctr_256_pkcs7_open(key, iv, ct).is_err(),
            "tampered PKCS7 pad must fail-closed"
        );
    }

    /// seal→open round-trip: a sealed blob is `nonce(12)‖ct‖tag` and opens back to the plaintext.
    #[test]
    fn aes_gcm_256_seal_open_round_trip() {
        let key: Vec<u8> = (0u8..32).collect();
        let pt = b"haven seal/open round-trip payload".to_vec();
        let wire = aes_gcm_256_seal(key.clone(), pt.clone()).unwrap();
        assert_eq!(
            wire.len(),
            12 + pt.len() + 16,
            "wire = nonce(12)+ct+tag(16)"
        );
        let dec = aes_gcm_256_open(key, wire).unwrap();
        assert_eq!(dec, pt, "open recovers the sealed plaintext");
    }

    /// Two seals of the same (key, plaintext) differ - fresh OsRng nonce each time.
    #[test]
    fn aes_gcm_256_seal_uses_fresh_nonce() {
        let key: Vec<u8> = (0u8..32).collect();
        let a = aes_gcm_256_seal(key.clone(), b"x".to_vec()).unwrap();
        let b = aes_gcm_256_seal(key, b"x".to_vec()).unwrap();
        assert_ne!(a, b, "fresh OsRng nonce per seal → distinct wire blobs");
        assert_ne!(a[..12], b[..12], "the 12-byte nonce prefixes differ");
    }

    /// open() fail-closed: too-short buffer, and a tampered tag, both Err.
    #[test]
    fn aes_gcm_256_open_fail_closed() {
        let key: Vec<u8> = (0u8..32).collect();
        assert!(
            aes_gcm_256_open(key.clone(), vec![0u8; 27]).is_err(),
            "too short → Err"
        );
        let mut wire = aes_gcm_256_seal(key.clone(), b"tamper me".to_vec()).unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        assert!(aes_gcm_256_open(key, wire).is_err(), "tampered tag → Err");
    }

    /// NIST SP 800-38D published-vector byte-compat blob opens to empty plaintext.
    #[test]
    fn aes_gcm_256_open_nist_vector_blob() {
        let mut wire = vec![0u8; 12];
        wire.extend_from_slice(&hex::decode("530f8afbc74536b9a963b4f1c4cb738b").unwrap());
        let pt = aes_gcm_256_open(vec![0u8; 32], wire).unwrap();
        assert!(
            pt.is_empty(),
            "NIST empty-plaintext GCM blob opens to empty"
        );
    }

    /// 🔴 REAL-DART BYTE-COMPAT: open a blob captured from the pointycastle
    /// GCMBlockCipher path. `open` MUST recover the exact plaintext or the cutover bricks data.
    #[test]
    fn aes_gcm_256_open_real_pointycastle_blob() {
        let key: Vec<u8> = (0u8..32).collect();
        let wire = hex::decode(
            "000102030405060708090a0b2f63a07eabc5a172fd29f2f9ee9a0c02f1b3a7569c143d5c4e56650c7dc179405c9a019508bf687f0f4f",
        )
        .unwrap();
        let pt = aes_gcm_256_open(key, wire).unwrap();
        assert_eq!(
            pt, b"haven cipher_store blob v1",
            "Rust open == pointycastle plaintext"
        );
    }

    /// 🔴 the at-rest byte-compat gate for the 16-byte-IV `haven_secure_storage` path.
    #[test]
    fn aes_gcm_256_open_iv16_real_pointycastle_blob() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let iv = "000102030405060708090a0b0c0d0e0f";
        let ct_and_tag =
            "0f0dd61357c9394dfe8aa94c78d758dc26d20cc447e4a572721e3da7e19ba97ef5a0923b1b32a93adb13debbb7fdc1";
        let wire = hex::decode(format!("{iv}{ct_and_tag}")).unwrap();
        let pt = aes_gcm_256_open_iv16(key, wire).unwrap();
        assert_eq!(
            pt, b"haven-secure-storage iv16 probe",
            "open_iv16 byte-compat with pointycastle 16-byte-IV GCM"
        );
    }

    /// `aes_gcm_256_seal_iv16` round-trips through `_open_iv16`, mints a fresh 16-byte nonce each
    /// call, and produces a 16-byte IV prefix (not 12).
    #[test]
    fn aes_gcm_256_iv16_seal_open_round_trip() {
        let key: Vec<u8> = (0u8..32).collect();
        let pt = b"haven_secure_storage payload".to_vec();
        let a = aes_gcm_256_seal_iv16(key.clone(), pt.clone()).unwrap();
        let b = aes_gcm_256_seal_iv16(key.clone(), pt.clone()).unwrap();
        assert_eq!(a.len(), 16 + pt.len() + 16, "wire = iv(16)+ct+tag(16)");
        assert_ne!(a[..16], b[..16], "fresh OsRng 16-byte nonce per seal");
        let back = aes_gcm_256_open_iv16(key, a).unwrap();
        assert_eq!(back, pt);
    }

    /// `iterations == 0` must fail closed on both PBKDF2 entry points - not silently compute
    /// a one-iteration key (the pinned implementation still runs the initial U1 block at 0 rounds).
    #[test]
    fn pbkdf2_rejects_zero_iterations() {
        assert!(pbkdf2_sha256("pw".into(), "salt".into(), 0, 32).is_err());
        assert!(pbkdf2_sha256_bytes(b"pw".to_vec(), b"salt".to_vec(), 0, 32).is_err());
    }

    /// `output_bytes == 0` and an oversize `output_bytes` must both fail closed on both entry
    /// points, rather than allocate an unbounded buffer.
    #[test]
    fn pbkdf2_rejects_zero_and_oversize_output() {
        assert!(pbkdf2_sha256("pw".into(), "salt".into(), 1000, 0).is_err());
        assert!(pbkdf2_sha256_bytes(b"pw".to_vec(), b"salt".to_vec(), 1000, 0).is_err());
        assert!(pbkdf2_sha256("pw".into(), "salt".into(), 1000, 8161).is_err());
        assert!(pbkdf2_sha256_bytes(b"pw".to_vec(), b"salt".to_vec(), 1000, 8161).is_err());
        // A generous-but-sane output length still succeeds (not an overly narrow cap).
        assert!(pbkdf2_sha256("pw".into(), "salt".into(), 1000, 8160).is_ok());
    }

    /// `pbkdf2_sha256_bytes` is a strict byte-generalization of the string form AND handles a
    /// non-UTF-8 binary salt deterministically.
    #[test]
    fn pbkdf2_sha256_bytes_generalizes_string_and_binary_salt() {
        let pw = "correct horse battery";
        let salt = "haven-root:user@example.com";
        let s = pbkdf2_sha256(pw.to_string(), salt.to_string(), 1000, 32).unwrap();
        let b = pbkdf2_sha256_bytes(pw.as_bytes().to_vec(), salt.as_bytes().to_vec(), 1000, 32)
            .unwrap();
        assert_eq!(s, b, "bytes(utf8(pw),utf8(salt)) == string(pw,salt)");
        let bin: Vec<u8> = (0u8..32).map(|i| 255 - i).collect();
        let c = pbkdf2_sha256_bytes(b"pw".to_vec(), bin.clone(), 210_000, 32).unwrap();
        let d = pbkdf2_sha256_bytes(b"pw".to_vec(), bin, 210_000, 32).unwrap();
        assert_eq!(c, d);
        assert_eq!(c.len(), 32);
    }

    /// RFC 5869 Appendix A.1 published vector - both the full Extract+Expand and the Expand-only path.
    #[test]
    fn hkdf_sha256_rfc5869_a1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let prk = hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
            .unwrap();
        let okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();
        let full = hkdf_sha256(ikm, salt, info.clone(), 42).unwrap();
        assert_eq!(full, okm, "RFC 5869 A.1 full HKDF");
        let exp = hkdf_sha256_expand(prk, info, 42).unwrap();
        assert_eq!(exp, okm, "RFC 5869 A.1 HKDF-Expand from PRK");
    }

    /// 🔴 REAL-DART BYTE-COMPAT: for every real `info` label,
    /// `hkdf_sha256(ikm, empty_salt, info, 32)` MUST equal the captured pointycastle output, AND
    /// `hkdf_sha256_expand` MUST differ from it (proving pointycastle does Extract+Expand).
    #[test]
    fn hkdf_sha256_byte_compat_pointycastle() {
        let ikm: Vec<u8> = (0u8..32).collect();
        let fixtures: &[(&str, &str)] = &[
            (
                "haven-auth-password",
                "711ae89b41e07da13edccb2a2668bb4629412a6e5eb6bbb413b6bfbef96de6d5",
            ),
            (
                "haven-db-master-key",
                "a6e873d9e353a0ff7b0a1f2fb1ff55265b918169ba7ea3bffab7e9592871b86c",
            ),
            (
                "haven-vault-master-key",
                "5bada27017d94f63ba3aef0ff08fbe286f1a9586149fe2a55e7bab4217f71c58",
            ),
            (
                "haven-cipher-store-root",
                "6212ce5cad7ca88d0ca7e0041dd7733e1c2dc07e38383e9e501f73aa1d164e1f",
            ),
            (
                "haven-contact-history",
                "017f326c048dfdeb2da67de87afe93a9ba3c994b125f48b736c6dea09c735226",
            ),
            (
                "haven-mls-backup",
                "4c61a40862dd8c0e63ef3fa2975ff83319f961914f0d273c0b00808467b84404",
            ),
            (
                "haven-recovery-wrap",
                "bc652cb5a756e470e91a5826a83eb5d5ebc6839d155aeef3bd112d2a6c082771",
            ),
        ];
        for (info, want_hex) in fixtures {
            let want = hex::decode(want_hex).unwrap();
            let full = hkdf_sha256(ikm.clone(), Vec::new(), info.as_bytes().to_vec(), 32).unwrap();
            assert_eq!(
                full, want,
                "hkdf_sha256 byte-compat with pointycastle for info={info}"
            );
            let expand_only =
                hkdf_sha256_expand(ikm.clone(), info.as_bytes().to_vec(), 32).unwrap();
            assert_ne!(
                expand_only, want,
                "expand-only(ikm) must NOT match pointycastle (it does Extract) - the §8 finding for info={info}"
            );
        }
    }

    /// out_len past the RFC 5869 max (255*HashLen) is fail-closed for both HKDF fns.
    #[test]
    fn hkdf_sha256_rejects_oversize_out_len() {
        let ikm: Vec<u8> = (0u8..32).collect();
        assert!(hkdf_sha256(ikm.clone(), Vec::new(), b"x".to_vec(), 8161).is_err());
        assert!(hkdf_sha256_expand(ikm, b"x".to_vec(), 8161).is_err());
    }

    /// Byte-compat gate: official Trezor 24-word vectors. A drift = recovery LOCK-OUT.
    #[test]
    fn bip39_official_trezor_24word_vectors() {
        let vectors: &[(&str, &str)] = &[
            ("0000000000000000000000000000000000000000000000000000000000000000",
             "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"),
            ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
             "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"),
            ("8080808080808080808080808080808080808080808080808080808080808080",
             "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
             "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"),
        ];
        for (ent_hex, phrase) in vectors {
            let entropy = hex::decode(ent_hex).unwrap();
            let got = bip39_entropy_to_phrase(entropy.clone()).unwrap();
            assert_eq!(&got, phrase, "entropy_to_phrase mismatch for {ent_hex}");
            let back = bip39_phrase_to_entropy(phrase.to_string()).unwrap();
            assert_eq!(back, entropy, "phrase_to_entropy mismatch for {ent_hex}");
            assert!(
                bip39_validate(phrase.to_string()),
                "validate should accept {ent_hex}"
            );
        }
    }

    /// `bip39_validate` rejects bad checksum / unknown word / wrong count.
    #[test]
    fn bip39_validate_rejects_invalid() {
        let bad_cksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(!bip39_validate(bad_cksum.to_string()));
        let bad_word = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        assert!(!bip39_validate(bad_word.to_string()));
        assert!(!bip39_validate("abandon abandon abandon".to_string()));
    }

    /// `bip39_generate_phrase` → 24 words, OsRng-distinct, round-trips + validates.
    #[test]
    fn bip39_generate_roundtrips() {
        let p1 = bip39_generate_phrase().unwrap();
        let p2 = bip39_generate_phrase().unwrap();
        assert_eq!(p1.split(' ').count(), 24);
        assert_ne!(p1, p2, "OsRng generation must differ");
        let ent = bip39_phrase_to_entropy(p1.clone()).unwrap();
        assert_eq!(ent.len(), 32);
        assert_eq!(bip39_entropy_to_phrase(ent).unwrap(), p1);
        assert!(bip39_validate(p1));
    }

    /// `random_bytes_secure` returns exactly the requested length.
    #[test]
    fn random_bytes_secure_returns_requested_length() {
        assert_eq!(random_bytes_secure(32).unwrap().len(), 32);
        assert_eq!(random_bytes_secure(0).unwrap().len(), 0);
        assert_eq!(random_bytes_secure(16).unwrap().len(), 16);
    }

    /// Two calls must produce distinct output (OsRng, not a fixed/zeroed buffer).
    #[test]
    fn random_bytes_secure_calls_differ() {
        let a = random_bytes_secure(32).unwrap();
        let b = random_bytes_secure(32).unwrap();
        assert_ne!(a, b, "OsRng generation must differ");
        assert_ne!(a, vec![0u8; 32], "must not be the trivially-zero buffer");
    }

    /// A `len` past the sane cap is refused, not allocated.
    #[test]
    fn random_bytes_secure_rejects_over_cap_len() {
        assert!(random_bytes_secure(MAX_RANDOM_BYTES_LEN + 1).is_err());
        assert!(random_bytes_secure(MAX_RANDOM_BYTES_LEN).is_ok());
    }

    /// A PBKDF2 iteration count past the sane cap is refused.
    #[test]
    fn pbkdf2_sha256_rejects_over_cap_iterations() {
        assert!(pbkdf2_sha256("pw".into(), "salt".into(), MAX_PBKDF2_ITERATIONS + 1, 32).is_err());
        assert!(pbkdf2_sha256("pw".into(), "salt".into(), 210_000, 32).is_ok());
    }
}
