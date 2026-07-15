//! PGP KATs: keygen/encrypt/decrypt round trips across key shapes, sign/verify, the
//! fail-closed tamper proof, and cross-signed identity rotation.

use super::*;

/// The decisive fail-closed proof: corrupting bytes inside an armored ciphertext's body must
/// make decryption return `Err`, never silently return corrupted/wrong plaintext and never
/// panic. Corrupts several bytes in the middle of the base64 body (leaving the armor
/// header/footer lines intact, so the corruption lands inside the encoded packet data itself,
/// not the envelope) - this exercises the integrity check on the encrypted data packet.
#[test]
fn tampered_ciphertext_fails_closed() {
    let (pub_key, priv_key) = pgp_generate_key(
        "Tamper".into(),
        "tamper@test.com".into(),
        "passT".into(),
        "ecc".into(),
    )
    .unwrap();

    let plaintext = "this must never be recovered from tampered ciphertext";
    let ciphertext = pgp_encrypt(plaintext.into(), pub_key).unwrap();

    // Sanity: the untampered ciphertext decrypts correctly first.
    let clean =
        pgp_decrypt_unauthenticated_impl(ciphertext.clone(), priv_key.clone(), "passT".into());
    assert_eq!(
        clean.unwrap(),
        plaintext,
        "untampered baseline must decrypt"
    );

    // Corrupt a run of bytes in the armor BODY (skip the first two lines: "-----BEGIN..." and
    // the blank/header line) - flip bits rather than replace, so the corruption is deterministic
    // and doesn't accidentally reproduce valid base64 for a different (still-parseable) packet.
    let lines: Vec<&str> = ciphertext.lines().collect();
    let mut tampered_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    let mut tampered_any = false;
    for line in tampered_lines.iter_mut() {
        if line.starts_with('-') || line.is_empty() {
            continue; // armor delimiter / blank separator lines - leave the envelope intact
        }
        // Flip bytes in this body line so the underlying encoded packet is corrupted.
        let mut bytes: Vec<u8> = line.bytes().collect();
        for b in bytes.iter_mut().take(8) {
            *b ^= 0xFF;
        }
        *line = String::from_utf8_lossy(&bytes).to_string();
        tampered_any = true;
        break; // one corrupted line is enough to prove fail-closed
    }
    assert!(tampered_any, "test must actually corrupt a body line");
    let tampered = tampered_lines.join("\n");

    let result = pgp_decrypt_unauthenticated_impl(tampered, priv_key, "passT".into());
    assert!(
        result.is_err(),
        "tampered ciphertext must fail to decrypt (fail-closed), got Ok"
    );
}

/// The tamper test above corrupts the FIRST body line, which can land in the session-key
/// packet header rather than the SEIPD-protected data packet itself - a parse failure there
/// proves fail-closed, but not specifically that the MDC (modification-detection code) check
/// catches a corruption INSIDE the encrypted data. This test uses a long plaintext (so the SEIPD
/// packet has real bulk) and corrupts bytes near the END of the armor body instead - past where
/// the session-key packet has long since ended, inside the encrypted data packet's own ciphertext
/// tail - and still must fail closed.
#[test]
fn tampered_ciphertext_near_end_fails_closed_mdc_check() {
    let (pub_key, priv_key) = pgp_generate_key(
        "TamperEnd".into(),
        "tamperend@test.com".into(),
        "passTE".into(),
        "ecc".into(),
    )
    .unwrap();

    // Long enough that the encoded body has multiple lines well past any session-key packet.
    let plaintext = "MDC corruption target - ".repeat(200);
    let ciphertext = pgp_encrypt(plaintext.clone(), pub_key).unwrap();

    let clean =
        pgp_decrypt_unauthenticated_impl(ciphertext.clone(), priv_key.clone(), "passTE".into());
    assert_eq!(
        clean.unwrap(),
        plaintext,
        "untampered baseline must decrypt"
    );

    let lines: Vec<&str> = ciphertext.lines().collect();
    let mut tampered_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();

    // Find the LAST non-delimiter, non-empty body line (the checksum line, if present, is
    // "=xxxx" - 5 chars - skip anything that short so the flip lands in real packet data, not the
    // CRC24 checksum line, which this test does not target).
    let target_idx = tampered_lines
        .iter()
        .enumerate()
        .rev()
        .find(|(_, l)| !l.starts_with('-') && !l.is_empty() && l.len() > 8)
        .map(|(i, _)| i)
        .expect("armor body must have a real trailing data line for this plaintext length");

    let mut bytes: Vec<u8> = tampered_lines[target_idx].bytes().collect();
    for b in bytes.iter_mut().take(8) {
        *b ^= 0xFF;
    }
    tampered_lines[target_idx] = String::from_utf8_lossy(&bytes).to_string();
    let tampered = tampered_lines.join("\n");

    let result = pgp_decrypt_unauthenticated_impl(tampered, priv_key, "passTE".into());
    assert!(
        result.is_err(),
        "corruption near the end of a long SEIPD ciphertext must still fail closed (MDC check)"
    );
}

/// Mirrors the real-world case: an RSA-4096 sender + an EdDSA+ECDH recipient both decrypt the
/// same multi-key ciphertext. A regression class where one primary-key type gets silently
/// dropped when any recipient key has an ECDH subkey.
#[test]
fn mixed_rsa_ecc_encrypt_decrypt() {
    let (pub_rsa, priv_rsa) = pgp_generate_key(
        "Alice".into(),
        "alice@test.com".into(),
        "passA".into(),
        "rsa4096".into(),
    )
    .unwrap();
    let (pub_ecc, priv_ecc) = pgp_generate_key(
        "Bob".into(),
        "bob@test.com".into(),
        "passB".into(),
        "ecc".into(),
    )
    .unwrap();

    let combined = format!("{pub_rsa}\n{pub_ecc}");
    let ciphertext = pgp_encrypt("Mixed test".into(), combined).unwrap();

    let dec_rsa = pgp_decrypt_unauthenticated_impl(ciphertext.clone(), priv_rsa, "passA".into());
    assert!(dec_rsa.is_ok(), "RSA decrypt failed: {:?}", dec_rsa.err());
    assert_eq!(dec_rsa.unwrap(), "Mixed test");

    let dec_ecc = pgp_decrypt_unauthenticated_impl(ciphertext, priv_ecc, "passB".into());
    assert!(dec_ecc.is_ok(), "ECC decrypt failed: {:?}", dec_ecc.err());
    assert_eq!(dec_ecc.unwrap(), "Mixed test");
}

/// ECC (EdDSA) sign + verify round trip.
#[test]
fn ecc_sign_verify_round_trip() {
    let (pub_key, priv_key) = pgp_generate_key(
        "Eve".into(),
        "eve@test.com".into(),
        "passE".into(),
        "ecc".into(),
    )
    .unwrap();

    let plaintext = "ECC sign/verify";
    let signed = pgp_sign(plaintext.into(), priv_key, "passE".into());
    assert!(signed.is_ok(), "ECC sign failed: {:?}", signed.err());

    let valid = pgp_verify(signed.unwrap(), pub_key);
    assert!(valid.is_ok(), "ECC verify errored: {:?}", valid.err());
    assert!(valid.unwrap(), "ECC signature did not verify as valid");
}

/// Regression: `pgp_verify` is a pure signature-validity check - it has no message parameter
/// to ignore anymore. A caller that needs "valid AND matches this exact content" must use
/// `pgp_verify_extract` and compare the extracted content itself; prove that pattern actually
/// catches a message swap (the defect the old ignored `_message` param let through silently).
#[test]
fn pgp_verify_extract_catches_wrong_message() {
    let (pub_key, priv_key) = pgp_generate_key(
        "Frank".into(),
        "frank@test.com".into(),
        "passF".into(),
        "ecc".into(),
    )
    .unwrap();

    let signed = pgp_sign("A".into(), priv_key, "passF".into()).unwrap();

    // pgp_verify: pure signature validity - true (the signature itself is genuine).
    assert!(pgp_verify(signed.clone(), pub_key.clone()).unwrap());

    // The caller-side "does this match what I expected" check: extract-then-compare.
    let extracted = pgp_verify_extract(signed, pub_key).unwrap();
    assert_eq!(extracted, Some("A".to_string()));
    assert_ne!(
        extracted.as_deref(),
        Some("B"),
        "extract-then-compare must catch a message swap the old ignored-_message pgp_verify let through"
    );
}

/// `pgp_verify` also fails closed on a signature from an unrelated key (not just a tampered one).
#[test]
fn pgp_verify_rejects_foreign_signature() {
    let (pub_a, priv_a) = pgp_generate_key(
        "KeyA".into(),
        "keya@test.com".into(),
        "passA".into(),
        "ecc".into(),
    )
    .unwrap();
    let (pub_b, _priv_b) = pgp_generate_key(
        "KeyB".into(),
        "keyb@test.com".into(),
        "passB".into(),
        "ecc".into(),
    )
    .unwrap();
    let _ = pub_a;

    let signed = pgp_sign("hello".into(), priv_a, "passA".into()).unwrap();
    let valid = pgp_verify(signed, pub_b).unwrap();
    assert!(
        !valid,
        "signature by key A must not verify against key B's public key"
    );
}

/// Encrypt for two recipients; both independently decrypt.
#[test]
fn multikey_encrypt_decrypt() {
    let (pub1, priv1) = pgp_generate_key(
        "Alice".into(),
        "alice@test.com".into(),
        "pass1".into(),
        "ecc".into(),
    )
    .unwrap();
    let (pub2, priv2) = pgp_generate_key(
        "Bob".into(),
        "bob@test.com".into(),
        "pass2".into(),
        "ecc".into(),
    )
    .unwrap();

    let combined_pub = format!("{pub1}\n{pub2}");
    let ciphertext = pgp_encrypt("Hello, both of you!".into(), combined_pub).unwrap();

    let dec1 = pgp_decrypt_unauthenticated_impl(ciphertext.clone(), priv1, "pass1".into());
    assert!(dec1.is_ok(), "Alice decrypt failed: {:?}", dec1.err());
    assert_eq!(dec1.unwrap(), "Hello, both of you!");

    let dec2 = pgp_decrypt_unauthenticated_impl(ciphertext, priv2, "pass2".into());
    assert!(dec2.is_ok(), "Bob decrypt failed: {:?}", dec2.err());
    assert_eq!(dec2.unwrap(), "Hello, both of you!");
}

/// Test-only: generate a primary-only RSA-4096 key (no subkey), `can_encrypt(true)` set on the
/// primary itself. `pgp_generate_key` always attaches a subkey, so it can't produce this shape -
/// this reproduces the real-world key shape where the ONLY encryption capability lives on the
/// primary, which `pgp_encrypt` must not silently drop.
fn generate_primary_only_rsa4096(
    name: &str,
    email: &str,
    passphrase: &str,
) -> anyhow::Result<(String, String)> {
    use pgp::composed::{ArmorOptions, KeyType, SecretKeyParamsBuilder};
    use pgp::types::SecretKeyTrait;
    use rand::thread_rng;

    let mut rng = thread_rng();
    let secret_key_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Rsa(4096))
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(true)
        .primary_user_id(format!("{name} <{email}>"))
        .passphrase(Some(passphrase.to_string()))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build key params: {e}"))?;

    let secret_key = secret_key_params
        .generate(&mut rng)
        .map_err(|e| anyhow::anyhow!("Key generation failed: {e}"))?;
    let signed_secret_key = secret_key
        .sign(&mut rng, || passphrase.to_string())
        .map_err(|e| anyhow::anyhow!("Key signing failed: {e}"))?;
    let public_key = signed_secret_key.public_key();
    let signed_public_key = public_key
        .sign(&mut rng, &signed_secret_key, || passphrase.to_string())
        .map_err(|e| anyhow::anyhow!("Public key signing failed: {e}"))?;

    let pub_armored = signed_public_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Public key armor failed: {e}"))?;
    let priv_armored = signed_secret_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Private key armor failed: {e}"))?;

    Ok((pub_armored, priv_armored))
}

#[test]
fn rsa4096_primary_only_encrypt() {
    let (synthetic_pub, synthetic_priv) =
        generate_primary_only_rsa4096("Test User", "test-rsa4096@example.com", "passSynth")
            .expect("failed to generate synthetic primary-only RSA-4096 key");

    let ciphertext = pgp_encrypt("primary-only encrypt".into(), synthetic_pub)
        .expect("encrypt to a primary-only RSA-4096 key must not silently drop it");
    let dec = pgp_decrypt_unauthenticated_impl(ciphertext, synthetic_priv, "passSynth".into());
    assert_eq!(dec.unwrap(), "primary-only encrypt");
}

// -- Cross-signed identity rotation -----------------------------------------------------

/// Old identity vouches for a new identity. A recipient holding the OLD public key can verify
/// the cross-sig over the NEW key's fingerprint.
#[test]
fn cross_sign_valid_rotation_verifies() {
    let (old_pub, old_priv) = pgp_generate_key(
        "Alice".into(),
        "alice@test.com".into(),
        "old".into(),
        "ecc".into(),
    )
    .unwrap();
    let (new_pub, _new_priv) = pgp_generate_key(
        "Alice".into(),
        "alice@test.com".into(),
        "new".into(),
        "ecc".into(),
    )
    .unwrap();

    let cross =
        pgp_cross_sign(new_pub.clone(), old_priv, "old".into()).expect("cross-sign should succeed");

    let ok = pgp_verify_cross_sig(cross, old_pub, new_pub).unwrap();
    assert!(ok, "a valid cross-sig from the old key must verify");
}

/// A cross-sig from an UNRELATED key must NOT verify against the pinned old key - the attack
/// case (a server attempting to forge a rotation).
#[test]
fn cross_sign_wrong_old_key_fails() {
    let (_old_pub, old_priv) = pgp_generate_key(
        "Alice".into(),
        "alice@test.com".into(),
        "old".into(),
        "ecc".into(),
    )
    .unwrap();
    let (new_pub, _) = pgp_generate_key(
        "Alice".into(),
        "alice@test.com".into(),
        "new".into(),
        "ecc".into(),
    )
    .unwrap();
    let (attacker_pub, _) = pgp_generate_key(
        "Eve".into(),
        "eve@test.com".into(),
        "x".into(),
        "ecc".into(),
    )
    .unwrap();

    let cross = pgp_cross_sign(new_pub.clone(), old_priv, "old".into()).unwrap();
    let ok = pgp_verify_cross_sig(cross, attacker_pub, new_pub).unwrap();
    assert!(!ok, "cross-sig must NOT verify against a non-signing key");
}

/// A cross-sig is bound to a SPECIFIC new key's fingerprint. Presenting it alongside a DIFFERENT
/// new key must fail - a signature cannot be transplanted onto another key.
#[test]
fn cross_sign_tampered_new_key_fails() {
    let (old_pub, old_priv) = pgp_generate_key(
        "Alice".into(),
        "alice@test.com".into(),
        "old".into(),
        "ecc".into(),
    )
    .unwrap();
    let (new_pub, _) = pgp_generate_key(
        "Alice".into(),
        "alice@test.com".into(),
        "new".into(),
        "ecc".into(),
    )
    .unwrap();
    let (different_new_pub, _) = pgp_generate_key(
        "Alice".into(),
        "alice@test.com".into(),
        "different".into(),
        "ecc".into(),
    )
    .unwrap();

    let cross = pgp_cross_sign(new_pub, old_priv, "old".into()).unwrap();
    let ok = pgp_verify_cross_sig(cross, old_pub, different_new_pub).unwrap();
    assert!(
        !ok,
        "a cross-sig over one new key must not verify for a different new key"
    );
}

/// Garbage input to the cross-sig verifier must never panic - always degrade to `false`/`Err`.
#[test]
fn cross_sign_garbage_never_panics() {
    let ok = pgp_verify_cross_sig(
        "not armor".into(),
        "also not armor".into(),
        "still not".into(),
    );
    assert!(ok.is_ok());
    assert!(!ok.unwrap());
}

// ── sign-and-encrypt / decrypt-and-verify ────────────────────────────────

/// The happy path: sign-then-encrypt, decrypt-and-verify recovers the plaintext AND reports
/// `signature_valid == true` when checked against the actual signer's public key.
#[test]
fn sign_and_encrypt_then_decrypt_and_verify_round_trip() {
    let (recipient_pub, recipient_priv) = pgp_generate_key(
        "Recipient".into(),
        "recipient@test.com".into(),
        "passR".into(),
        "ecc".into(),
    )
    .unwrap();
    let (signer_pub, signer_priv) = pgp_generate_key(
        "Signer".into(),
        "signer@test.com".into(),
        "passS".into(),
        "ecc".into(),
    )
    .unwrap();

    let ciphertext = pgp_sign_and_encrypt(
        "sign-and-encrypt payload".into(),
        recipient_pub,
        signer_priv,
        "passS".into(),
    )
    .expect("sign_and_encrypt should succeed");

    let (plaintext, signature_valid) =
        pgp_decrypt_and_verify_impl(ciphertext, recipient_priv, "passR".into(), signer_pub)
            .expect("decrypt_and_verify should succeed");

    assert_eq!(plaintext, "sign-and-encrypt payload");
    assert!(
        signature_valid,
        "signature by the real signer must verify true"
    );
}

/// The exact defect this closes: an attacker who knows the recipient's public key can encrypt an
/// UNSIGNED chosen plaintext (plain `pgp_encrypt`, no signing step at all). Decrypt-and-verify
/// MUST still return the plaintext (decrypt succeeds - SEIPDv1 only proves ciphertext integrity,
/// not authorship) but `signature_valid` MUST be `false` - never silently claim authentication
/// that never happened, and never error/panic on the missing signature layer.
#[test]
fn decrypt_and_verify_reports_false_for_unsigned_ciphertext() {
    let (recipient_pub, recipient_priv) = pgp_generate_key(
        "Recipient".into(),
        "recipient@test.com".into(),
        "passR".into(),
        "ecc".into(),
    )
    .unwrap();
    // An unrelated "signer" key the attacker does NOT hold the private half of - stands in for
    // "whatever identity the UI would have displayed as the expected sender."
    let (bystander_pub, _bystander_priv) = pgp_generate_key(
        "Bystander".into(),
        "bystander@test.com".into(),
        "passB".into(),
        "ecc".into(),
    )
    .unwrap();

    // No signing step at all - plain encrypt, exactly the attacker-crafted case.
    let ciphertext = pgp_encrypt(
        "attacker chosen plaintext, unsigned".into(),
        recipient_pub.clone(),
    )
    .unwrap();

    let (plaintext, signature_valid) =
        pgp_decrypt_and_verify_impl(ciphertext, recipient_priv, "passR".into(), bystander_pub)
            .expect("decrypt must still succeed - the ciphertext itself is well-formed");

    assert_eq!(plaintext, "attacker chosen plaintext, unsigned");
    assert!(
        !signature_valid,
        "an unsigned message must never report signature_valid=true"
    );
}

/// A message signed by SOME key but checked against a DIFFERENT expected signer must report
/// `signature_valid == false` - proves the check is bound to the specific public key passed in,
/// not "any valid signature by anyone."
#[test]
fn decrypt_and_verify_rejects_wrong_signer() {
    let (recipient_pub, recipient_priv) = pgp_generate_key(
        "Recipient".into(),
        "recipient@test.com".into(),
        "passR".into(),
        "ecc".into(),
    )
    .unwrap();
    let (real_signer_pub, real_signer_priv) = pgp_generate_key(
        "RealSigner".into(),
        "real@test.com".into(),
        "passReal".into(),
        "ecc".into(),
    )
    .unwrap();
    let (wrong_pub, _wrong_priv) = pgp_generate_key(
        "WrongSigner".into(),
        "wrong@test.com".into(),
        "passWrong".into(),
        "ecc".into(),
    )
    .unwrap();
    let _ = real_signer_pub;

    let ciphertext = pgp_sign_and_encrypt(
        "signed by the real signer".into(),
        recipient_pub,
        real_signer_priv,
        "passReal".into(),
    )
    .unwrap();

    let (_plaintext, signature_valid) =
        pgp_decrypt_and_verify_impl(ciphertext, recipient_priv, "passR".into(), wrong_pub)
            .expect("decrypt must succeed regardless of who we check the signature against");

    assert!(
        !signature_valid,
        "a signature by the real signer must not verify against an unrelated expected-signer key"
    );
}

/// The fail-closed sibling must return `Err`, not `(plaintext, false)`, on an unsigned
/// ciphertext - the exact case the permissive fn's tuple return lets a careless caller destructure
/// and misuse.
#[test]
fn decrypt_and_verify_strict_fails_closed_on_unsigned_ciphertext() {
    let (recipient_pub, recipient_priv) = pgp_generate_key(
        "Recipient".into(),
        "recipient@test.com".into(),
        "passR".into(),
        "ecc".into(),
    )
    .unwrap();
    let (bystander_pub, _bystander_priv) = pgp_generate_key(
        "Bystander".into(),
        "bystander@test.com".into(),
        "passB".into(),
        "ecc".into(),
    )
    .unwrap();

    let ciphertext = pgp_encrypt(
        "attacker chosen plaintext, unsigned".into(),
        recipient_pub.clone(),
    )
    .unwrap();

    let result = pgp_decrypt_and_verify_strict_impl(
        ciphertext,
        recipient_priv,
        "passR".into(),
        bystander_pub,
    );
    assert!(
        result.is_err(),
        "an unsigned ciphertext must never produce a plaintext from the strict variant"
    );
}

/// The fail-closed sibling must return `Err` when the ciphertext is signed by someone other
/// than the expected signer, mirroring `decrypt_and_verify_rejects_wrong_signer` but asserting
/// the strict contract.
#[test]
fn decrypt_and_verify_strict_fails_closed_on_wrong_signer() {
    let (recipient_pub, recipient_priv) = pgp_generate_key(
        "Recipient".into(),
        "recipient@test.com".into(),
        "passR".into(),
        "ecc".into(),
    )
    .unwrap();
    let (real_signer_pub, real_signer_priv) = pgp_generate_key(
        "RealSigner".into(),
        "real@test.com".into(),
        "passReal".into(),
        "ecc".into(),
    )
    .unwrap();
    let (wrong_pub, _wrong_priv) = pgp_generate_key(
        "WrongSigner".into(),
        "wrong@test.com".into(),
        "passWrong".into(),
        "ecc".into(),
    )
    .unwrap();
    let _ = real_signer_pub;

    let ciphertext = pgp_sign_and_encrypt(
        "signed by the real signer".into(),
        recipient_pub,
        real_signer_priv,
        "passReal".into(),
    )
    .unwrap();

    let result =
        pgp_decrypt_and_verify_strict_impl(ciphertext, recipient_priv, "passR".into(), wrong_pub);
    assert!(
        result.is_err(),
        "a signature by the real signer checked against an unrelated key must fail closed"
    );
}

/// The strict sibling must still return the plaintext when the signature actually verifies -
/// proves the fail-closed change doesn't also reject the legitimate case.
#[test]
fn decrypt_and_verify_strict_succeeds_on_valid_signature() {
    let (recipient_pub, recipient_priv) = pgp_generate_key(
        "Recipient".into(),
        "recipient@test.com".into(),
        "passR".into(),
        "ecc".into(),
    )
    .unwrap();
    let (signer_pub, signer_priv) = pgp_generate_key(
        "Signer".into(),
        "signer@test.com".into(),
        "passS".into(),
        "ecc".into(),
    )
    .unwrap();

    let ciphertext = pgp_sign_and_encrypt(
        "strict variant happy path".into(),
        recipient_pub,
        signer_priv,
        "passS".into(),
    )
    .unwrap();

    let plaintext =
        pgp_decrypt_and_verify_strict_impl(ciphertext, recipient_priv, "passR".into(), signer_pub)
            .expect("a valid signature must produce the plaintext");
    assert_eq!(plaintext, "strict variant happy path");
}

/// Test-only: a signing-only key (no encryption capability anywhere - no subkey, and
/// `can_encrypt(false)` on the primary). Reproduces the real-world key shape `pgp_encrypt` must
/// refuse to silently drop from a recipient set.
fn generate_signing_only_key(name: &str, email: &str, passphrase: &str) -> (String, String) {
    use pgp::composed::{ArmorOptions, KeyType, SecretKeyParamsBuilder};
    use pgp::types::SecretKeyTrait;
    use rand::thread_rng;

    let mut rng = thread_rng();
    let secret_key_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::EdDSALegacy)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(false)
        .primary_user_id(format!("{name} <{email}>"))
        .passphrase(Some(passphrase.to_string()))
        .build()
        .expect("build signing-only key params");

    let secret_key = secret_key_params
        .generate(&mut rng)
        .expect("generate signing-only key");
    let signed_secret_key = secret_key
        .sign(&mut rng, || passphrase.to_string())
        .expect("sign signing-only secret key");
    let public_key = signed_secret_key.public_key();
    let signed_public_key = public_key
        .sign(&mut rng, &signed_secret_key, || passphrase.to_string())
        .expect("sign signing-only public key");

    (
        signed_public_key
            .to_armored_string(ArmorOptions::default())
            .expect("armor signing-only public key"),
        signed_secret_key
            .to_armored_string(ArmorOptions::default())
            .expect("armor signing-only private key"),
    )
}

/// `pgp_encrypt` given a good key alongside a malformed key block (a truncated armor
/// body, still bounded by real BEGIN/END markers so it counts as a delimited block) must refuse
/// - not silently encrypt to only the good recipient.
#[test]
fn pgp_encrypt_refuses_on_malformed_recipient_block() {
    let (good_pub, _) = pgp_generate_key(
        "Good".into(),
        "good@test.com".into(),
        "passG".into(),
        "ecc".into(),
    )
    .unwrap();

    // A real key block with its body corrupted (BEGIN/END markers intact, so it still counts
    // as a delimited block for parse_public_keys_report's blocks_found).
    let mut lines: Vec<&str> = good_pub.lines().collect();
    for line in lines.iter_mut() {
        if !line.starts_with('-') && !line.is_empty() {
            *line = "this-is-not-valid-base64-armor-content";
            break;
        }
    }
    let malformed = lines.join("\n");

    let combined = format!("{good_pub}\n{malformed}");
    let result = pgp_encrypt("must not silently drop a recipient".into(), combined);
    assert!(
        result.is_err(),
        "a malformed key block among good recipients must refuse, not silently encrypt to fewer"
    );
}

/// A regression guard on the malformed-block-detection fix above: rpgp
/// accepts arbitrary `Key: value` armor headers, so a legitimate header whose VALUE contains
/// the BEGIN marker text (e.g. a `Comment:` line) must not be counted as a second block
/// start. `pgp_encrypt` given a single good key carrying such a header must still succeed.
#[test]
fn pgp_encrypt_succeeds_with_begin_marker_embedded_in_header_value() {
    let (good_pub, _) = pgp_generate_key(
        "Good".into(),
        "good@test.com".into(),
        "passG".into(),
        "ecc".into(),
    )
    .unwrap();

    // Insert an armor header, right after the BEGIN line, whose value happens to contain the
    // BEGIN marker text - the exact shape parse_public_keys_report's raw-substring version
    // miscounted as a second block.
    let mut lines: Vec<&str> = good_pub.lines().collect();
    let begin_idx = lines
        .iter()
        .position(|line| *line == "-----BEGIN PGP PUBLIC KEY BLOCK-----")
        .expect("armored key has a BEGIN line");
    lines.insert(
        begin_idx + 1,
        "Comment: -----BEGIN PGP PUBLIC KEY BLOCK-----",
    );
    let with_header = lines.join("\n");

    let result = pgp_encrypt(
        "a header value containing the marker text must not be miscounted as a block".into(),
        with_header,
    );
    assert!(
        result.is_ok(),
        "a BEGIN marker embedded in an armor header value must not be counted as a second \
         block: {:?}",
        result.err()
    );
}

/// The malformed-block test above keeps both the BEGIN and
/// END markers on the bad block, so it never exercises the case an attacker or a network
/// truncation actually produces - a BEGIN with no matching END. `pgp_encrypt` given a good
/// key followed by an unterminated block (no `-----END PGP PUBLIC KEY BLOCK-----` anywhere
/// after it) must refuse, not silently encrypt to only the good recipient.
#[test]
fn pgp_encrypt_refuses_on_unterminated_recipient_block() {
    let (good_pub, _) = pgp_generate_key(
        "Good".into(),
        "good@test.com".into(),
        "passG".into(),
        "ecc".into(),
    )
    .unwrap();

    // A second BEGIN marker with real-looking body content but no END marker anywhere after
    // it - the exact shape a truncated transfer produces.
    let truncated = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nthis-body-never-terminates";
    let combined = format!("{good_pub}\n{truncated}");

    let result = pgp_encrypt("must not silently drop a recipient".into(), combined);
    assert!(
        result.is_err(),
        "an unterminated key block among good recipients must refuse, not silently encrypt to fewer"
    );
}

/// A batch over `parse_public_keys_report`'s internal block-count cap (1024) is a hard refusal
/// (empty keys, a forced completeness mismatch), not a partial parse - proven with fake blocks
/// (garbage bodies), so the only way this can behave this way is the cap running before any real
/// parsing is attempted.
#[test]
fn parse_public_keys_report_rejects_over_cap_block_count() {
    let mut input = String::new();
    for _ in 0..1025 {
        input.push_str(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----\n",
        );
    }
    let (keys, blocks_found) = parse_public_keys_report(&input);
    assert!(
        keys.is_empty(),
        "over the block-count cap must refuse, not partially parse"
    );
    assert!(
        blocks_found > 1024,
        "blocks_found must force a completeness mismatch, not report the real (over-cap) count"
    );
}

/// Input over `parse_public_keys_report`'s internal aggregate-byte cap (16 MiB) is refused before
/// any line scanning, same forced-mismatch shape as the block-count cap above.
#[test]
fn parse_public_keys_report_rejects_over_cap_aggregate_bytes() {
    let oversized = "x".repeat(16 * 1024 * 1024 + 1);
    let (keys, blocks_found) = parse_public_keys_report(&oversized);
    assert!(keys.is_empty());
    assert!(blocks_found > 1024);
}

/// `pgp_encrypt` given a good key alongside a signing-only key (parses fine, but has no
/// encryption capability at all) must refuse - not silently encrypt to only the encryption-
/// capable recipient.
#[test]
fn pgp_encrypt_refuses_on_signing_only_recipient() {
    let (good_pub, _) = pgp_generate_key(
        "Good".into(),
        "good@test.com".into(),
        "passG".into(),
        "ecc".into(),
    )
    .unwrap();
    let (signing_only_pub, _) = generate_signing_only_key("SignOnly", "signonly@test.com", "passS");

    let combined = format!("{good_pub}\n{signing_only_pub}");
    let result = pgp_encrypt("must not silently drop a recipient".into(), combined);
    assert!(
        result.is_err(),
        "a signing-only recipient among good ones must refuse, not silently encrypt to fewer"
    );
}

/// The happy-path control for the two refusal tests above: an all-good, all-encryption-capable
/// recipient set must still succeed as before (no regression on the passing path).
#[test]
fn pgp_encrypt_still_succeeds_with_all_good_recipients() {
    let (pub1, priv1) = pgp_generate_key(
        "Alice".into(),
        "alice2@test.com".into(),
        "pass1".into(),
        "ecc".into(),
    )
    .unwrap();
    let (pub2, priv2) = pgp_generate_key(
        "Bob".into(),
        "bob2@test.com".into(),
        "pass2".into(),
        "ecc".into(),
    )
    .unwrap();

    let combined = format!("{pub1}\n{pub2}");
    let ciphertext = pgp_encrypt("all good".into(), combined).expect("all-good set must succeed");

    assert_eq!(
        pgp_decrypt_unauthenticated_impl(ciphertext.clone(), priv1, "pass1".into()).unwrap(),
        "all good"
    );
    assert_eq!(
        pgp_decrypt_unauthenticated_impl(ciphertext, priv2, "pass2".into()).unwrap(),
        "all good"
    );
}
