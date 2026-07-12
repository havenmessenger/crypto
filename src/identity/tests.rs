//! Identity-generation KATs: the HD-seed recovery property, signing-key determinism, and an
//! RFC 8032 answer-key anchor independent of this crate's own Ed25519 implementation.

use super::*;
use crate::mls::groups::mls_extract_signature_key;
use openmls_traits::signatures::Signer;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64
}

/// The whole point of the HD-derived identity path: a new account's MLS identity is
/// deterministically derived from a seed, so it is recoverable. Two derivations from the SAME
/// seed must produce the SAME signing key (extractable from the resulting KeyPackage), and that
/// key must equal the seed's own derived public key. A different seed must yield a different
/// identity; a malformed seed must error, never panic.
#[test]
fn generate_identity_from_seed_recovery_property() {
    let now = now_secs();
    let seed = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".to_string();

    let (_id1, kp1, bundle1) =
        generate_identity_from_seed("alice".to_string(), now, seed.clone()).unwrap();
    let (_id2, kp2, _bundle2) =
        generate_identity_from_seed("alice".to_string(), now, seed.clone()).unwrap();

    let sig1 = mls_extract_signature_key(kp1);
    let sig2 = mls_extract_signature_key(kp2);
    assert!(!sig1.is_empty(), "HD identity KeyPackage must validate");
    assert_eq!(
        sig1, sig2,
        "same seed must reproduce the same MLS signing key (recovery property)"
    );

    let (_priv, expected_pub) = mls_derive_signing_key(seed.clone());
    assert_eq!(
        sig1, expected_pub,
        "extracted key must equal the seed's pubkey"
    );
    let bundle = IdentityBundle::from_slice(&bundle1).unwrap();
    assert_eq!(
        hex::encode_upper(&bundle.public_key_bytes),
        expected_pub,
        "bundle signing key must be the HD-derived one"
    );

    let other = "FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100".to_string();
    let (_id3, kp3, _b3) = generate_identity_from_seed("alice".to_string(), now, other).unwrap();
    assert_ne!(
        mls_extract_signature_key(kp3),
        sig1,
        "distinct seeds must yield distinct MLS identities"
    );

    assert!(generate_identity_from_seed("alice".to_string(), now, "nope".to_string()).is_err());
}

/// Seed -> signing keypair must be (a) deterministic, (b) priv == seed, (c) the public key
/// matches an independent ed25519-dalek derivation from the same seed, (d) distinct seeds ->
/// distinct keys, (e) the derived private key actually signs+verifies through the same crypto
/// `MlsSigner` uses, (f) garbage -> ("", "") never a panic.
#[test]
fn mls_derive_signing_key_deterministic() {
    let seed_hex = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF".to_string();

    let (priv1, pub1) = mls_derive_signing_key(seed_hex.clone());
    let (priv2, pub2) = mls_derive_signing_key(seed_hex.clone());
    assert_eq!(priv1, priv2, "derivation must be deterministic (priv)");
    assert_eq!(pub1, pub2, "derivation must be deterministic (pub)");
    assert!(!priv1.is_empty(), "valid seed must derive a key");

    assert_eq!(
        priv1,
        seed_hex.to_uppercase(),
        "MLS private key bytes must equal the 32-byte seed verbatim"
    );

    let seed_bytes = hex::decode(&seed_hex).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed_bytes);
    let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
    assert_eq!(
        pub1,
        hex::encode_upper(sk.verifying_key().to_bytes()),
        "public key must match the seed's Ed25519 verifying key"
    );

    let other = "FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100".to_string();
    let (priv3, pub3) = mls_derive_signing_key(other);
    assert_ne!(priv1, priv3, "distinct seeds -> distinct private keys");
    assert_ne!(pub1, pub3, "distinct seeds -> distinct public keys");

    // The derived key is pipeline-compatible: it signs and the public key verifies, proving it
    // round-trips through the same crypto the MlsSigner path uses.
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let priv_bytes = hex::decode(&priv1).unwrap();
    let pub_bytes = hex::decode(&pub1).unwrap();
    let signer = MlsSigner {
        key: zeroize::Zeroizing::new(priv_bytes),
        scheme: openmls::prelude::SignatureScheme::ED25519,
    };
    let payload = b"identity determinism KAT";
    let sig = signer.sign(payload).expect("derived key must sign");
    use openmls_traits::crypto::OpenMlsCrypto;
    use openmls_traits::OpenMlsProvider;
    provider
        .crypto()
        .verify_signature(
            openmls::prelude::SignatureScheme::ED25519,
            payload,
            &pub_bytes,
            &sig,
        )
        .expect("public key must verify the derived key's signature");

    assert_eq!(
        mls_derive_signing_key("not-hex".to_string()),
        (String::new(), String::new())
    );
    assert_eq!(
        mls_derive_signing_key("AABB".to_string()),
        (String::new(), String::new()),
        "wrong-length seed must be rejected"
    );
}

/// KAT: published Ed25519 vectors (secret seed -> public key) from RFC 8032 section 7.1.
/// Unlike the determinism test above (which re-derives with the same ed25519-dalek library -
/// circular), this anchors the output to an INDEPENDENT answer key, so a future dependency swap
/// or implementation bug that still passes the determinism test would still be caught here.
#[test]
fn mls_derive_signing_key_rfc8032_kat() {
    let vectors = [
        // RFC 8032 section 7.1 TEST 2
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3D4017C3E843895A92B70AA74D1B7EBC9C982CCF2EC4968CC0CD55F12AF4660C",
        ),
        // RFC 8032 section 7.1 TEST 3
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "FC51CD8E6218A1A38DA47ED00230F0580816ED13BA3303AC5DEB911548908025",
        ),
    ];
    for (seed_hex, want_pub) in vectors {
        let (priv_hex, pub_hex) = mls_derive_signing_key(seed_hex.to_string());
        assert_eq!(
            priv_hex,
            seed_hex.to_uppercase(),
            "private key must equal the 32-byte seed verbatim"
        );
        assert_eq!(
            pub_hex, want_pub,
            "RFC 8032 Ed25519 public-key vector mismatch for seed {seed_hex}"
        );
    }
}
