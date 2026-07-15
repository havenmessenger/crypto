//! OpenPGP (rPGP) implementation. The Dart-exposed entry points a consuming application defines
//! are thin delegators over the functions here.
//!
//! The OpenPGP wire/armor formats, the deterministic-keygen byte-path
//! (`pgp_derive_deterministic`, an identity-determinism contract this crate holds), and the
//! `suite_policy::pgp_symmetric()` seam call are proven by the rPGP KATs in this module's own
//! tests.
//!
//! `PgpSignatureInfo` (a Dart-exposed return type) stays defined in the consuming application,
//! not here - crypto-core must not depend on the crate that wraps it (that would invert the
//! dependency direction). `pgp_signature_info` here returns a plain
//! `(bool, Option<i64>, String)` tuple; a thin wrapper on the application side converts it.
//!
//! Lint posture: this module allows several pedantic/style lints with justification rather than
//! fixing them, because fixing some of them would be a logic edit on a KAT-pinned crypto path;
//! the `unnecessary_wraps` / `manual_let_else` / `redundant_closure_for_method_calls` ones are
//! genuine idiom-cleanup candidates, allowed rather than fixed here to keep this pass
//! behavior-preserving.
#![allow(
    clippy::doc_markdown, // doc comments cite OpenPGP/CipherStore/etc. type names verbatim
    clippy::manual_let_else, // idiom-cleanup candidate, deferred
    clippy::redundant_closure_for_method_calls, // idiom-cleanup candidate, deferred
    clippy::unnecessary_wraps, // signatures are fixed by the delegator contract
    // Crypto-pathway: this module IS the rPGP boundary - rPGP's keygen/encrypt API
    // takes an `Rng`, and `thread_rng()` here is an OS-seeded ChaCha CSPRNG (cryptographically
    // secure, an accepted, documented boundary). The `disallowed_methods` ban still fires on
    // a `thread_rng`/`random` reach in EVERY OTHER file (the actual guard target); this known boundary
    // is allowed module-wide rather than at 5 byte-identical call sites.
    clippy::disallowed_methods
)]

use crate::suite_policy::pgp_symmetric;
use pgp::composed::signed_key::{SignedPublicKey, SignedPublicSubKey, SignedSecretKey};
use pgp::composed::{ArmorOptions, KeyType, Message, SecretKeyParamsBuilder, SubkeyParamsBuilder};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::errors::Result as PgpResult;
use pgp::types::{
    EskType, Fingerprint, KeyId, KeyVersion, PkeskBytes, PublicKeyTrait, PublicParams,
    SecretKeyTrait, SignatureBytes, StringToKey,
};
use pgp::Deserializable;
use rand::{thread_rng, CryptoRng, Rng};
use zeroize::Zeroizing;

/// Dispatch wrapper for mixing RSA primary keys and ECDH subkeys in a single
/// `encrypt_to_keys_seipdv1` call.  rpgp requires a homogeneous `&[&impl PublicKeyTrait]`
/// slice, but real-world key sets mix RSA (primary-only) and EdDSA+ECDH (subkey-based)
/// recipients.  This enum bridges the two concrete types under one `PublicKeyTrait` impl.
enum EncKey<'a> {
    Primary(&'a SignedPublicKey),
    Subkey(&'a SignedPublicSubKey),
}

impl std::fmt::Debug for EncKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = match self {
            EncKey::Primary(k) => k.key_id(),
            EncKey::Subkey(k) => k.key_id(),
        };
        write!(f, "EncKey({id:X})")
    }
}

impl PublicKeyTrait for EncKey<'_> {
    fn version(&self) -> KeyVersion {
        match self {
            EncKey::Primary(k) => k.version(),
            EncKey::Subkey(k) => k.version(),
        }
    }
    fn fingerprint(&self) -> Fingerprint {
        match self {
            EncKey::Primary(k) => k.fingerprint(),
            EncKey::Subkey(k) => k.fingerprint(),
        }
    }
    fn key_id(&self) -> KeyId {
        match self {
            EncKey::Primary(k) => k.key_id(),
            EncKey::Subkey(k) => k.key_id(),
        }
    }
    fn algorithm(&self) -> PublicKeyAlgorithm {
        match self {
            EncKey::Primary(k) => k.algorithm(),
            EncKey::Subkey(k) => k.algorithm(),
        }
    }
    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        match self {
            EncKey::Primary(k) => k.created_at(),
            EncKey::Subkey(k) => k.created_at(),
        }
    }
    fn expiration(&self) -> Option<u16> {
        match self {
            EncKey::Primary(k) => k.expiration(),
            EncKey::Subkey(k) => k.expiration(),
        }
    }
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> PgpResult<()> {
        match self {
            EncKey::Primary(k) => k.verify_signature(hash, data, sig),
            EncKey::Subkey(k) => k.verify_signature(hash, data, sig),
        }
    }
    fn encrypt<R: CryptoRng + Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> PgpResult<PkeskBytes> {
        match self {
            EncKey::Primary(k) => k.encrypt(rng, plain, typ),
            EncKey::Subkey(k) => k.encrypt(rng, plain, typ),
        }
    }
    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> PgpResult<()> {
        match self {
            EncKey::Primary(k) => k.serialize_for_hashing(writer),
            EncKey::Subkey(k) => k.serialize_for_hashing(writer),
        }
    }
    fn public_params(&self) -> &PublicParams {
        match self {
            EncKey::Primary(k) => k.public_params(),
            EncKey::Subkey(k) => k.public_params(),
        }
    }
}

/// Impl of `pgp_generate_key` (rich doc on the delegator).
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_generate_key(
    name: String,
    email: String,
    passphrase: String,
    algorithm: String,
) -> anyhow::Result<(String, String)> {
    // Tier-0: wipe our retained passphrase copy on drop. The clones below are consumed
    // by rPGP into its own buffers (out of our control); this wipes only the copy we own.
    let passphrase = Zeroizing::new(passphrase);
    let mut rng = thread_rng();

    let key_type = match algorithm.as_str() {
        "rsa2048" => KeyType::Rsa(2048),
        "rsa4096" => KeyType::Rsa(4096),
        "ecc" => KeyType::EdDSALegacy,
        _ => return Err(anyhow::anyhow!("Unsupported algorithm: {algorithm}")),
    };

    let subkey_type = match algorithm.as_str() {
        "ecc" => KeyType::ECDH(ECCCurve::Curve25519),
        _ => key_type.clone(),
    };

    let secret_key_params = SecretKeyParamsBuilder::default()
        .key_type(key_type)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(format!("{name} <{email}>"))
        .passphrase(Some((*passphrase).clone()))
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(subkey_type)
                .can_encrypt(true)
                .passphrase(Some((*passphrase).clone()))
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build subkey params: {e}"))?,
        )
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build key params: {e}"))?;

    let secret_key = secret_key_params
        .generate(&mut rng)
        .map_err(|e| anyhow::anyhow!("Key generation failed: {e}"))?;

    let signed_secret_key = secret_key
        .sign(&mut rng, || (*passphrase).clone())
        .map_err(|e| anyhow::anyhow!("Key signing failed: {e}"))?;

    let public_key = signed_secret_key.public_key();
    let signed_public_key = public_key
        .sign(&mut rng, &signed_secret_key, || (*passphrase).clone())
        .map_err(|e| anyhow::anyhow!("Public key signing failed: {e}"))?;

    let pub_armored = signed_public_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Public key armor failed: {e}"))?;
    let priv_armored = signed_secret_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Private key armor failed: {e}"))?;

    Ok((pub_armored, priv_armored))
}

/// Impl of `pgp_derive_deterministic` (rich doc on the delegator). The keygen byte-path
/// (ChaCha20Rng draw order, pinned `created_at`) is this crate's identity-determinism
/// contract, unchanged.
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_derive_deterministic(
    name: String,
    email: String,
    passphrase: String,
    algorithm: String,
    seed_hex: String,
    created_at_unix: i64,
) -> anyhow::Result<(String, String)> {
    use rand_chacha::rand_core::SeedableRng;

    // Tier-0: the seed (and its hex) regenerate the identity key - the crown-jewel
    // secret. Wrap every retained copy in Zeroizing so each wipes on drop. The passphrase wrap follows
    // the same rule; rPGP-internal copies of either are out of our control.
    let passphrase = Zeroizing::new(passphrase);
    let seed_hex = Zeroizing::new(seed_hex);
    let seed_bytes = Zeroizing::new(
        hex::decode(seed_hex.trim())
            .map_err(|e| anyhow::anyhow!("seed_hex is not valid hex: {e}"))?,
    );
    if seed_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "seed must be exactly 32 bytes, got {}",
            seed_bytes.len()
        ));
    }
    let mut seed_arr = Zeroizing::new([0u8; 32]);
    seed_arr.copy_from_slice(&seed_bytes);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed_arr);

    let created_at = chrono::DateTime::from_timestamp(created_at_unix, 0)
        .ok_or_else(|| anyhow::anyhow!("created_at_unix out of range: {created_at_unix}"))?;

    let key_type = match algorithm.as_str() {
        "rsa2048" => KeyType::Rsa(2048),
        "rsa4096" => KeyType::Rsa(4096),
        "ecc" => KeyType::EdDSALegacy,
        _ => return Err(anyhow::anyhow!("Unsupported algorithm: {algorithm}")),
    };
    let subkey_type = match algorithm.as_str() {
        "ecc" => KeyType::ECDH(ECCCurve::Curve25519),
        _ => key_type.clone(),
    };

    let secret_key_params = SecretKeyParamsBuilder::default()
        .key_type(key_type)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(format!("{name} <{email}>"))
        .passphrase(Some((*passphrase).clone()))
        .created_at(created_at)
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(subkey_type)
                .can_encrypt(true)
                .passphrase(Some((*passphrase).clone()))
                .created_at(created_at)
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build subkey params: {e}"))?,
        )
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build key params: {e}"))?;

    let secret_key = secret_key_params
        .generate(&mut rng)
        .map_err(|e| anyhow::anyhow!("Key generation failed: {e}"))?;

    let signed_secret_key = secret_key
        .sign(&mut rng, || (*passphrase).clone())
        .map_err(|e| anyhow::anyhow!("Key signing failed: {e}"))?;

    let public_key = signed_secret_key.public_key();
    let signed_public_key = public_key
        .sign(&mut rng, &signed_secret_key, || (*passphrase).clone())
        .map_err(|e| anyhow::anyhow!("Public key signing failed: {e}"))?;

    let pub_armored = signed_public_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Public key armor failed: {e}"))?;
    let priv_armored = signed_secret_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Private key armor failed: {e}"))?;

    Ok((pub_armored, priv_armored))
}

/// Impl of `pgp_encrypt` (rich doc on the delegator). Builds per-key `EncKey` targets so a
/// heterogeneous RSA-primary + ECDH-subkey set passes as one homogeneous slice.
///
/// `pub` (not `pub(crate)`): a `build-encrypted-mime` CLI, built downstream in Haven's
/// private codebase (this crate ships no binary - see this crate's Cargo.toml,
/// `[lib]` only), calls into this crate as a library dependency and needs this function visible
/// from outside the crate. Safe to widen - this crate has no `flutter_rust_bridge` dependency at
/// all, so nothing here is FRB-scanned regardless of visibility.
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_encrypt(plaintext: String, public_keys_armored: String) -> anyhow::Result<String> {
    let mut rng = thread_rng();

    let (keys, blocks_found) = parse_public_keys_report(&public_keys_armored);
    if blocks_found == 0 {
        return Err(anyhow::anyhow!("No public key blocks found"));
    }
    if keys.len() != blocks_found {
        return Err(anyhow::anyhow!(
            "{} of {blocks_found} recipient key block(s) failed to parse - refusing to encrypt \
             to a partial recipient set",
            blocks_found - keys.len()
        ));
    }

    let msg = Message::new_literal("", plaintext.as_str());

    let (enc_keys, dropped) = build_encryption_targets(&keys);
    if dropped > 0 {
        return Err(anyhow::anyhow!(
            "{dropped} of {} recipient key(s) have no encryption-capable subkey - refusing to \
             encrypt to a partial recipient set",
            keys.len()
        ));
    }
    if enc_keys.is_empty() {
        return Err(anyhow::anyhow!("No encryption-capable keys found"));
    }

    let enc_key_refs: Vec<&EncKey<'_>> = enc_keys.iter().collect();
    let encrypted = msg
        .encrypt_to_keys_seipdv1(&mut rng, pgp_symmetric(), &enc_key_refs)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    encrypted
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Armor encoding failed: {e}"))
}

/// Impl of `pgp_encrypt_symmetric` (rich doc on the delegator).
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_encrypt_symmetric(plaintext: String, passphrase: String) -> anyhow::Result<String> {
    // Tier-0: wipe our retained passphrase copy on drop.
    let passphrase = Zeroizing::new(passphrase);
    let mut rng = thread_rng();

    let msg = Message::new_literal("", plaintext.as_str());

    // Build S2K with iterated+salted (standard OpenPGP)
    let mut salt = [0u8; 8];
    rand::Rng::fill(&mut rng, &mut salt);
    let s2k = StringToKey::IteratedAndSalted {
        hash_alg: HashAlgorithm::SHA2_256,
        salt,
        count: 224, // ~65536 iterations
    };

    let encrypted = msg
        .encrypt_with_password_seipdv1(&mut rng, s2k, pgp_symmetric(), || (*passphrase).clone())
        .map_err(|e| anyhow::anyhow!("Symmetric encryption failed: {e}"))?;

    encrypted
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Armor encoding failed: {e}"))
}

/// Decrypt an armored PGP message. Does not check any embedded signature - the returned plaintext
/// is authenticated only against the SEIPDv1 integrity tag (tamper-evident), not against the
/// claimed sender. A message an attacker encrypted to the recipient's own public key, unsigned,
/// decrypts here exactly the same as a legitimately signed one. Use
/// [`pgp_decrypt_and_verify_strict_impl`] when the caller needs to know who sent the message, not
/// just that it decrypted.
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_decrypt_unauthenticated_impl(
    encrypted_armored: String,
    private_key_armored: String,
    passphrase: String,
) -> anyhow::Result<String> {
    let (msg, _) = Message::from_armor_single(encrypted_armored.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse encrypted message: {e}"))?;

    let (secret_key, _) = SignedSecretKey::from_armor_single(private_key_armored.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse private key: {e}"))?;

    // Tier-0: wipe our retained passphrase copy on drop.
    let passphrase = Zeroizing::new(passphrase);
    let (decrypted, _ids) = msg
        .decrypt(|| (*passphrase).clone(), &[&secret_key])
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;

    let content = decrypted
        .get_content()
        .map_err(|e| anyhow::anyhow!("Failed to get decrypted content: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("Decrypted message has no content"))?;

    String::from_utf8(content)
        .map_err(|e| anyhow::anyhow!("Decrypted content is not valid UTF-8: {e}"))
}

/// Impl of `pgp_decrypt_and_verify_impl` (rich doc on the delegator). The authenticate-on-decrypt
/// counterpart to `pgp_sign_and_encrypt`: `pgp_decrypt_unauthenticated_impl` alone returns whatever
/// content was encrypted regardless of whether it carries a valid signature, so an unsigned
/// chosen-plaintext message an attacker encrypted to the recipient's own public key comes back
/// through the exact same shape as a legitimately signed-and-encrypted one - a caller that only
/// calls `pgp_decrypt_unauthenticated_impl` cannot tell the difference. This fn decrypts THEN verifies the embedded
/// signature against `signer_public_key_armored` before returning, so the boolean tells the caller
/// whether what they got back is authenticated. A `false` result is a normal negative (unsigned, or
/// signed by someone else) - only a structural failure (bad armor, bad key, decrypt failure) is
/// `Err`.
///
/// The returned tuple is a misuse-capable shape: a caller can destructure it and use the
/// plaintext without checking the second element, silently treating unauthenticated content as
/// authenticated. Use this function only when the caller has a real need for the permissive
/// "decrypted, and here is whether it was also signed by X" answer (for example, an inbox
/// display that shows unverified messages with a distinct badge rather than hiding them). A
/// caller that wants a plaintext only when it is authenticated should call
/// [`pgp_decrypt_and_verify_strict_impl`] instead, which fails closed.
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_decrypt_and_verify_impl(
    encrypted_armored: String,
    private_key_armored: String,
    passphrase: String,
    signer_public_key_armored: String,
) -> anyhow::Result<(String, bool)> {
    let (msg, _) = Message::from_armor_single(encrypted_armored.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse encrypted message: {e}"))?;

    let (secret_key, _) = SignedSecretKey::from_armor_single(private_key_armored.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse private key: {e}"))?;

    let (signer_public_key, _) =
        SignedPublicKey::from_armor_single(signer_public_key_armored.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to parse signer public key: {e}"))?;

    // Tier-0: wipe our retained passphrase copy on drop.
    let passphrase = Zeroizing::new(passphrase);
    let (decrypted, _ids) = msg
        .decrypt(|| (*passphrase).clone(), &[&secret_key])
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;

    // Verify BEFORE extracting content - an unsigned or wrong-signer message still decrypts fine
    // (SEIPDv1's MDC covers ciphertext integrity, not authorship); a failed verify is a normal
    // "not authenticated" outcome, not an error.
    let signature_valid = decrypted.verify(&signer_public_key).is_ok();

    let content = decrypted
        .get_content()
        .map_err(|e| anyhow::anyhow!("Failed to get decrypted content: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("Decrypted message has no content"))?;

    let plaintext = String::from_utf8(content)
        .map_err(|e| anyhow::anyhow!("Decrypted content is not valid UTF-8: {e}"))?;

    Ok((plaintext, signature_valid))
}

/// Impl of `pgp_decrypt_and_verify_strict_impl` (rich doc on the delegator). The fail-closed
/// sibling of [`pgp_decrypt_and_verify_impl`]: returns the plaintext only when the embedded
/// signature verifies against `signer_public_key_armored`, and `Err` otherwise - unsigned,
/// wrong-signer, and malformed messages are indistinguishable to the caller, all three reach the
/// same `Err` path, and there is no tuple to destructure incorrectly. Use this
/// when the caller has no legitimate use for unauthenticated content (message send/receive on an
/// authenticated channel, key-rotation vouches, anything the caller would otherwise need to
/// remember to gate on the boolean itself).
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_decrypt_and_verify_strict_impl(
    encrypted_armored: String,
    private_key_armored: String,
    passphrase: String,
    signer_public_key_armored: String,
) -> anyhow::Result<String> {
    let (plaintext, signature_valid) = pgp_decrypt_and_verify_impl(
        encrypted_armored,
        private_key_armored,
        passphrase,
        signer_public_key_armored,
    )?;
    if !signature_valid {
        anyhow::bail!(
            "signature verification failed: refusing to return unauthenticated plaintext"
        );
    }
    Ok(plaintext)
}

/// Impl of `pgp_decrypt_symmetric` (rich doc on the delegator).
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_decrypt_symmetric(
    encrypted_armored: String,
    passphrase: String,
) -> anyhow::Result<String> {
    let (msg, _) = Message::from_armor_single(encrypted_armored.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse encrypted message: {e}"))?;

    // Tier-0: wipe our retained passphrase copy on drop.
    let passphrase = Zeroizing::new(passphrase);
    let decrypted = msg
        .decrypt_with_password(|| (*passphrase).clone())
        .map_err(|e| anyhow::anyhow!("Symmetric decryption failed: {e}"))?;

    let content = decrypted
        .get_content()
        .map_err(|e| anyhow::anyhow!("Failed to get decrypted content: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("Decrypted message has no content"))?;

    String::from_utf8(content)
        .map_err(|e| anyhow::anyhow!("Decrypted content is not valid UTF-8: {e}"))
}

/// Impl of `pgp_sign` (rich doc on the delegator).
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_sign(
    plaintext: String,
    private_key_armored: String,
    passphrase: String,
) -> anyhow::Result<String> {
    let (secret_key, _) = SignedSecretKey::from_armor_single(private_key_armored.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse private key: {e}"))?;

    // Tier-0: wipe our retained passphrase copy on drop.
    let passphrase = Zeroizing::new(passphrase);
    let msg = Message::new_literal("", plaintext.as_str());
    let rng = thread_rng();

    let signed = msg
        .sign(
            rng,
            &secret_key,
            || (*passphrase).clone(),
            HashAlgorithm::SHA2_256,
        )
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?;

    signed
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Armor encoding failed: {e}"))
}

/// Impl of `pgp_sign_and_encrypt` (rich doc on the delegator). Sign-then-encrypt in one op.
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_sign_and_encrypt(
    plaintext: String,
    public_keys_armored: String,
    signing_private_key_armored: String,
    signing_passphrase: String,
) -> anyhow::Result<String> {
    let (secret_key, _) =
        SignedSecretKey::from_armor_single(signing_private_key_armored.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to parse signing private key: {e}"))?;

    let (recipient_keys, blocks_found) = parse_public_keys_report(&public_keys_armored);
    if blocks_found == 0 {
        return Err(anyhow::anyhow!("No recipient public key blocks found"));
    }
    if recipient_keys.len() != blocks_found {
        return Err(anyhow::anyhow!(
            "{} of {blocks_found} recipient key block(s) failed to parse - refusing to encrypt \
             to a partial recipient set",
            blocks_found - recipient_keys.len()
        ));
    }

    // Tier-0: wipe our retained signing-passphrase copy on drop.
    let signing_passphrase = Zeroizing::new(signing_passphrase);
    let mut rng = thread_rng();
    let msg = Message::new_literal("", plaintext.as_str());

    // Step 1 - sign the literal message.
    let signed = msg
        .sign(
            &mut rng,
            &secret_key,
            || (*signing_passphrase).clone(),
            HashAlgorithm::SHA2_256,
        )
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?;

    // Step 2 - encrypt the signed message to recipients (one packet stream).
    let (enc_keys, dropped) = build_encryption_targets(&recipient_keys);
    if dropped > 0 {
        return Err(anyhow::anyhow!(
            "{dropped} of {} recipient key(s) have no encryption-capable subkey - refusing to \
             encrypt to a partial recipient set",
            recipient_keys.len()
        ));
    }
    if enc_keys.is_empty() {
        return Err(anyhow::anyhow!(
            "No encryption-capable recipient keys found"
        ));
    }

    let enc_key_refs: Vec<&EncKey<'_>> = enc_keys.iter().collect();
    let encrypted = signed
        .encrypt_to_keys_seipdv1(&mut rng, pgp_symmetric(), &enc_key_refs)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    encrypted
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Armor encoding failed: {e}"))
}

/// Impl of `pgp_verify` (rich doc on the delegator). Pure signature-validity check over whatever
/// content `signed_armored` itself carries - it takes no expected-message parameter,
/// because a signature-validity check that silently ignored such a parameter would let a
/// signature over `"A"` verify `true` even when the caller expected `"B"`. A caller that needs
/// "valid AND matches this exact content" must use [`pgp_verify_extract`] and compare its `Some(_)`
/// result themselves - that is what this crate's own `pgp_verify_cross_sig` does.
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_verify(signed_armored: String, public_key_armored: String) -> anyhow::Result<bool> {
    let (public_key, _) = SignedPublicKey::from_armor_single(public_key_armored.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse public key: {e}"))?;

    let (msg, _) = Message::from_armor_single(signed_armored.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse signed message: {e}"))?;

    match msg.verify(&public_key) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Impl of `pgp_verify_extract` (rich doc on the delegator). Returns cleartext only after the
/// signature verifies (binds "valid" to "over THIS content").
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_verify_extract(
    signed_armored: String,
    public_key_armored: String,
) -> anyhow::Result<Option<String>> {
    let (public_key, _) = SignedPublicKey::from_armor_single(public_key_armored.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse public key: {e}"))?;

    let (msg, _) = Message::from_armor_single(signed_armored.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse signed message: {e}"))?;

    // A failed signature is a normal "untrusted" answer, not an error.
    if msg.verify(&public_key).is_err() {
        return Ok(None);
    }

    let content = msg
        .get_content()
        .map_err(|e| anyhow::anyhow!("Failed to get verified content: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("Verified message has no content"))?;

    let text = String::from_utf8(content)
        .map_err(|e| anyhow::anyhow!("Verified content is not valid UTF-8: {e}"))?;
    Ok(Some(text))
}

/// Impl of `pgp_signature_info` (rich doc on the delegator). Returns the plain-data tuple
/// `(valid, signed_at, signer_key_id)` - the Dart-exposed `PgpSignatureInfo` struct stays
/// defined in the consuming application, not here, because crypto-core must not depend on the
/// crate that wraps it (that would invert the dependency direction). A thin wrapper on the
/// application side converts this tuple into `PgpSignatureInfo`.
#[allow(clippy::needless_pass_by_value, clippy::type_complexity)]
pub fn pgp_signature_info(
    signed_armored: String,
    public_key_armored: String,
) -> anyhow::Result<(bool, Option<i64>, String)> {
    let none = || (false, None, String::new());

    let public_key = match SignedPublicKey::from_armor_single(public_key_armored.as_bytes()) {
        Ok((k, _)) => k,
        Err(_) => return Ok(none()),
    };
    let msg = match Message::from_armor_single(signed_armored.as_bytes()) {
        Ok((m, _)) => m,
        Err(_) => return Ok(none()),
    };

    // Pull provenance metadata from the signature packet when directly signed.
    // Compressed/nested layouts degrade to (None, "") but still verify below.
    let (signed_at, signer_key_id) = match &msg {
        Message::Signed { signature, .. } => {
            let ts = signature.created().map(chrono::DateTime::timestamp);
            let kid = signature
                .issuer()
                .first()
                .map(|k| format!("{k:X}"))
                .unwrap_or_default();
            (ts, kid)
        }
        _ => (None, String::new()),
    };

    let valid = matches!(msg.verify(&public_key), Ok(()));
    Ok((valid, signed_at, signer_key_id))
}

/// Impl of `pgp_key_algo_summary` (rich doc on the delegator).
#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn pgp_key_algo_summary(public_key_armored: String) -> String {
    match SignedPublicKey::from_armor_single(public_key_armored.as_bytes()) {
        Ok((key, _)) => match key.public_params() {
            PublicParams::RSA { n, .. } => format!("RSA {}", n.as_bytes().len() * 8),
            PublicParams::Ed25519 { .. } | PublicParams::EdDSALegacy { .. } => {
                "Curve25519 (ECC)".to_string()
            }
            PublicParams::ECDH(_) | PublicParams::X25519 { .. } => "Curve25519 (ECC)".to_string(),
            PublicParams::ECDSA(_) => "ECDSA".to_string(),
            _ => "Unknown".to_string(),
        },
        Err(_) => "Unknown".to_string(),
    }
}

/// Impl of `pgp_primary_fingerprint` (rich doc on the delegator).
#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn pgp_primary_fingerprint(public_key_armored: String) -> String {
    match SignedPublicKey::from_armor_single(public_key_armored.as_bytes()) {
        Ok((key, _)) => hex::encode_upper(key.fingerprint().as_bytes()),
        Err(_) => "Unknown".to_string(),
    }
}

/// Impl of `pgp_cross_sign` (rich doc on the delegator). Reuses the KAT-pinned `pgp_sign` path.
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_cross_sign(
    new_public_armored: String,
    old_private_armored: String,
    old_passphrase: String,
) -> anyhow::Result<String> {
    let new_fp = pgp_primary_fingerprint(new_public_armored);
    if new_fp == "Unknown" {
        return Err(anyhow::anyhow!("Could not read the new key's fingerprint"));
    }
    pgp_sign(new_fp, old_private_armored, old_passphrase)
}

/// Impl of `pgp_verify_cross_sig` (rich doc on the delegator).
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_verify_cross_sig(
    cross_sig_armored: String,
    old_public_armored: String,
    new_public_armored: String,
) -> anyhow::Result<bool> {
    let expected_fp = pgp_primary_fingerprint(new_public_armored);
    if expected_fp == "Unknown" {
        return Ok(false);
    }

    // 1. The signature must verify against the OLD (pinned) public key.
    let sig_valid = match pgp_verify(cross_sig_armored.clone(), old_public_armored) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    if !sig_valid {
        return Ok(false);
    }

    // 2. The signed content must be EXACTLY the new key's primary fingerprint.
    let signed_content = match pgp_extract_signed(cross_sig_armored) {
        Ok(c) => c,
        Err(_) => return Ok(false),
    };
    Ok(signed_content.trim() == expected_fp)
}

/// Impl of `pgp_extract_signed` (rich doc on the delegator).
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_extract_signed(signed_armored: String) -> anyhow::Result<String> {
    let (msg, _) = Message::from_armor_single(signed_armored.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse signed message: {e}"))?;

    let content = msg
        .get_content()
        .map_err(|e| anyhow::anyhow!("Failed to extract content: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("Signed message has no content"))?;

    String::from_utf8(content).map_err(|e| anyhow::anyhow!("Content is not valid UTF-8: {e}"))
}

/// Impl of `pgp_get_public_key_id` (rich doc on the delegator).
#[allow(clippy::needless_pass_by_value)]
pub fn pgp_get_public_key_id(public_key_armored: String) -> anyhow::Result<String> {
    let (public_key, _) = SignedPublicKey::from_armor_single(public_key_armored.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse public key: {e}"))?;

    let key_id = public_key.key_id();
    Ok(format!("{key_id:X}"))
}

/// Parse one or more armored public keys from a concatenated string. Infallible by contract:
/// unparseable key blocks are skipped silently (dropped the unnecessary Result wrapper).
/// Kept for any caller that wants the lenient best-effort contract; a caller that needs to know
/// about a dropped recipient (any encryption path) should use [`parse_public_keys_report`]
/// instead.
#[must_use]
pub fn parse_public_keys(armored: &str) -> Vec<SignedPublicKey> {
    parse_public_keys_report(armored).0
}

/// Same parse as [`parse_public_keys`], plus the count of key blocks the input actually
/// delimited, so a caller can detect a silent drop: `keys.len() < blocks_found` means at
/// least one delimited block failed to parse. "Encrypt to A, B, C" must not
/// silently become "encrypt to A" when B's block is malformed or truncated - the caller
/// needs the count to refuse instead of proceeding.
///
/// `blocks_found` counts every BEGIN marker as a delimited block, whether or not a matching
/// END marker follows it. Counting only blocks with a found END marker would make an
/// unterminated block (a real recipient A followed by a `BEGIN` for recipient B with no
/// matching `END`, e.g. from network truncation) invisible: `keys.len() ==
/// blocks_found == 1` would pass the caller's completeness check even though the input named
/// two recipients. Counting on BEGIN alone closes that: an unterminated block still
/// contributes no key to `keys`, so `keys.len() != blocks_found` and the caller refuses.
///
/// A BEGIN marker only counts when it is a LINE by itself, not any occurrence of that text
/// in the input. rpgp accepts arbitrary `Key: value` armor headers, so a header value that
/// happens to contain the marker string (e.g. `Comment: -----BEGIN PGP PUBLIC KEY
/// BLOCK-----`) is not a second block start. Matching the marker as a raw substring anywhere
/// in the input would count that kind of header value as an extra block and make a valid
/// single-recipient key spuriously fail the completeness check.
/// Matching whole lines (trailing `\r`/`\n` stripped, so both `\n` and `\r\n` input work)
/// excludes the header-value case while still matching every real marker line.
///
/// Bounded on block count and aggregate input size (see the constants at the top of the function
/// body) - input over either is a hard refusal (empty keys, a `blocks_found` that can never equal
/// `keys.len()`), not a silent truncation, so the completeness contract above never gives a false
/// pass because both sides were quietly capped to the same number.
#[must_use]
pub fn parse_public_keys_report(armored: &str) -> (Vec<SignedPublicKey>, usize) {
    // Upper bounds on this function's input - generous enough for any real multi-recipient
    // encryption, small enough to bound the work a hostile or corrupted input can force before
    // any real parsing happens.
    const MAX_KEY_BLOCKS: usize = 1024;
    const MAX_AGGREGATE_ARMOR_BYTES: usize = 16 * 1024 * 1024;
    // The forced-mismatch `blocks_found` this function returns (alongside empty `keys`) when an
    // input exceeds either bound above.
    const OVER_LIMIT_REFUSAL: usize = MAX_KEY_BLOCKS + 1;

    if armored.len() > MAX_AGGREGATE_ARMOR_BYTES {
        return (Vec::new(), OVER_LIMIT_REFUSAL);
    }

    let mut keys = Vec::new();
    let mut blocks_found = 0usize;
    let begin_marker = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    let end_marker = "-----END PGP PUBLIC KEY BLOCK-----";

    // One pass: a block is open (`block_start = Some(offset)`) from the line where a bare BEGIN
    // marker line starts it to the line where a bare END marker line closes it. Each block is
    // sliced and parsed exactly once, closed, no re-scanning of already-consumed text - unlike
    // the prior `rest.find(end_marker)` version, which re-searched from every BEGIN offset
    // forward, worst-case quadratic in the number of BEGIN markers. Both markers require a whole
    // matching line (trailing `\r`/`\n` stripped): rpgp accepts arbitrary `Key: value` armor
    // headers, so a header value that happens to contain either marker string (e.g. a `Comment:`
    // line) must not be mistaken for a real delimiter.
    let mut block_start: Option<usize> = None;
    let mut offset = 0usize;
    for line in armored.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if block_start.is_none() && trimmed == begin_marker {
            blocks_found += 1;
            if blocks_found > MAX_KEY_BLOCKS {
                return (Vec::new(), OVER_LIMIT_REFUSAL);
            }
            block_start = Some(offset);
        } else if let Some(start) = block_start {
            if trimmed == end_marker {
                let end = offset + line.len();
                let key_block = &armored[start..end];
                if let Ok((key, _)) = SignedPublicKey::from_armor_single(key_block.as_bytes()) {
                    keys.push(key);
                }
                block_start = None;
            }
        }
        offset += line.len();
    }

    (keys, blocks_found)
}

/// Build the per-key `EncKey` encryption targets shared by [`pgp_encrypt`] and
/// [`pgp_sign_and_encrypt`] (previously duplicated inline in both). Returns the targets plus
/// the count of input keys that contributed none (no encryption-capable ECDH subkey and the
/// primary itself isn't an encryption key - a signing-only key). A caller must
/// refuse rather than silently encrypt to fewer recipients than it was asked for.
fn build_encryption_targets(keys: &[SignedPublicKey]) -> (Vec<EncKey<'_>>, usize) {
    let mut dropped = 0;
    let mut targets = Vec::new();
    for k in keys {
        let subs: Vec<EncKey<'_>> = k
            .public_subkeys
            .iter()
            .filter(|sk| sk.is_encryption_key())
            .map(EncKey::Subkey)
            .collect();
        if subs.is_empty() {
            if k.is_encryption_key() {
                targets.push(EncKey::Primary(k));
            } else {
                dropped += 1; // signing-only, no encryption subkey
            }
        } else {
            targets.extend(subs);
        }
    }
    (targets, dropped)
}

#[cfg(test)]
mod tests;
