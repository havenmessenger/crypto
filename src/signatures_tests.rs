use super::{is_valid_public_key, sign_detached, verify_detached};
use ed25519_dalek::VerifyingKey;

fn bytes<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("hex fixture")
        .try_into()
        .expect("fixed-size fixture")
}

// RFC 8032 section 7.1 provides independently published Ed25519 signatures.
#[test]
fn signing_and_verification_match_rfc8032() {
    let vectors = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ),
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            concat!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ),
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            concat!(
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
            ),
        ),
    ];
    for (seed, public, message, signature) in vectors {
        let message = hex::decode(message).expect("message");
        let expected_public = bytes(public);
        let expected_signature = bytes(signature);
        let (public, signature) = sign_detached(&bytes(seed), &message);
        assert_eq!(public, expected_public);
        assert_eq!(signature, expected_signature);
        assert!(verify_detached(
            &expected_public,
            &message,
            &expected_signature
        ));
    }
}

#[test]
fn binary_documents_preserve_every_byte() {
    let document = b"\0release\r\n\xff";
    let (public, signature) = sign_detached(&[17; 32], document);
    assert!(verify_detached(&public, document, &signature));
    assert!(!verify_detached(&public, b"\0release\n\xff", &signature));
    assert!(!verify_detached(
        &public,
        b"\0release\r\n\xff\0",
        &signature
    ));
}

#[test]
fn a_changed_document_is_rejected() {
    let (public, signature) = sign_detached(&[17; 32], b"document");
    assert!(!verify_detached(&public, b"documenu", &signature));
}

#[test]
fn another_key_is_rejected() {
    let (_, signature) = sign_detached(&[17; 32], b"document");
    let (other, _) = sign_detached(&[18; 32], b"document");
    assert!(!verify_detached(&other, b"document", &signature));
}

#[test]
fn a_changed_signature_is_rejected() {
    let (public, mut signature) = sign_detached(&[17; 32], b"document");
    signature[0] ^= 1;
    assert!(!verify_detached(&public, b"document", &signature));
}

#[test]
fn a_noncanonical_scalar_is_rejected() {
    let (public, mut signature) = sign_detached(&[17; 32], b"document");
    signature[32..].fill(255);
    assert!(!verify_detached(&public, b"document", &signature));
}

#[test]
fn a_small_order_key_and_signature_are_rejected() {
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut signature = [0; 64];
    signature[0] = 1;
    assert!(!verify_detached(&identity, b"document", &signature));
}

#[test]
fn generated_and_rfc_public_keys_are_valid() {
    let rfc = bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    assert!(is_valid_public_key(&rfc));
    for seed in [[0; 32], [17; 32], [255; 32]] {
        let (public, signature) = sign_detached(&seed, b"key validation");
        assert!(is_valid_public_key(&public));
        assert!(verify_detached(&public, b"key validation", &signature));
    }
}

#[test]
fn invalid_compressed_public_key_is_rejected() {
    let mut invalid = [0; 32];
    invalid[0] = 2;
    assert!(
        VerifyingKey::from_bytes(&invalid).is_err(),
        "off-curve fixture"
    );
    assert!(!is_valid_public_key(&invalid));
}

#[test]
fn small_order_public_keys_are_rejected() {
    let mut identity = [0; 32];
    identity[0] = 1;
    for public in [identity, [0; 32]] {
        let decoded = VerifyingKey::from_bytes(&public).expect("small-order fixture");
        assert!(decoded.is_weak());
        assert!(!is_valid_public_key(&public));
    }
}

#[test]
fn mixed_order_public_key_is_rejected() {
    let (valid, _) = sign_detached(&[17; 32], b"");
    let valid = VerifyingKey::from_bytes(&valid)
        .expect("generated key")
        .to_edwards();
    let torsion = VerifyingKey::from_bytes(&[0; 32])
        .expect("order-four fixture")
        .to_edwards();
    let mixed = valid + torsion;
    let public = mixed.compress().to_bytes();
    let decoded = VerifyingKey::from_bytes(&public).expect("mixed-order fixture");
    assert!(!decoded.is_weak());
    assert!(!mixed.is_torsion_free());
    assert!(!is_valid_public_key(&public));
}

#[test]
fn noncanonical_public_key_encodings_are_rejected() {
    // ZIP-215 decoding accepts y >= p. Enumerate its nineteen reduced aliases and both signs.
    let mut decoded_aliases = 0;
    for low in 0xed..=0xff {
        for high in [0x7f, 0xff] {
            let mut public = [0xff; 32];
            public[0] = low;
            public[31] = high;
            if let Ok(decoded) = VerifyingKey::from_bytes(&public) {
                assert_ne!(decoded.to_edwards().compress().to_bytes(), public);
                assert!(!is_valid_public_key(&public), "{}", hex::encode(public));
                decoded_aliases += 1;
            }
        }
    }
    assert!(
        decoded_aliases > 0,
        "exercise the decoder's alias acceptance"
    );
}
