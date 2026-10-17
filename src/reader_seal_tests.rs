use openmls::prelude::Ciphersuite;

use super::*;
use crate::suite_policy::{ReaderSealSuite, READER_SEAL_SUITE_OVERRIDE};

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).expect("hex")
}

fn seed() -> [u8; KEY_LEN] {
    [7; KEY_LEN]
}

fn pair() -> ReaderKeyPair {
    derive_reader_keypair(&seed(), b"drive").expect("derives")
}

fn with_ephemeral<T>(ikm_e: &[u8], work: impl FnOnce() -> T) -> T {
    EPHEMERAL_SEED.with(|seed| *seed.borrow_mut() = Some(ikm_e.to_vec()));
    work()
}

/// RFC 9180 Appendix A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, Base mode.
mod appendix_a_1_1 {
    pub const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    pub const IKM_E: &str = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234";
    pub const PK_E: &str = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
    pub const IKM_R: &str = "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037";
    pub const PK_R: &str = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d";
    pub const SK_R: &str = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
    pub const AAD_0: &str = "436f756e742d30";
    pub const PT_0: &str = "4265617574792069732074727574682c20747275746820626561757479";
    /// The same first encryption with no `aad`, which is what this module seals with. Computed from the RFC's inputs
    /// with a separate implementation of the key schedule; its first 29 bytes are the RFC's, and only the tag differs.
    pub const CT_0_NO_AAD: &str =
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae821807a370ad4546513b00cf03048f6b793c";
    pub const CT_0: &str = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a";
}

#[test]
fn the_suite_is_the_rfc_9180_x25519_sha256_aes128_triple() {
    let suite = reader_seal_suite();
    assert_eq!(suite.hpke_kem, HpkeKemType::DhKem25519);
    assert_eq!(suite.hpke_kdf, HpkeKdfType::HkdfSha256);
    assert_eq!(suite.hpke_aead, HpkeAeadType::AesGcm128);
    // The wire ids 0x0020 / 0x0001 / 0x0001 are the ones the KEM, KDF and AEAD report.
    assert_eq!(suite.hpke_kem as u16, 0x0020);
    assert_eq!(suite.hpke_kdf as u16, 0x0001);
    assert_eq!(suite.hpke_aead as u16, 0x0001);
}

#[test]
fn derive_key_pair_matches_the_published_vector() {
    let derived =
        derive_from_ikm(reader_seal_suite(), &unhex(appendix_a_1_1::IKM_R)).expect("derives");
    assert_eq!(
        derived.public.as_bytes().as_slice(),
        unhex(appendix_a_1_1::PK_R)
    );
    assert_eq!(derived.secret.0.as_slice(), unhex(appendix_a_1_1::SK_R));
}

#[test]
fn a_seal_with_the_published_ephemeral_gives_the_published_encapsulation_and_the_no_aad_ciphertext()
{
    // The RFC's first encryption is `seq 0` of the context; a single-shot seal is that first encryption. The RFC
    // seals with aad "Count-0" and this module has none, so the ciphertext compared is the one for empty aad.
    let public = ReaderPublicKey::from_bytes(&unhex(appendix_a_1_1::PK_R)).expect("key");
    let (enc, ciphertext) = with_ephemeral(&unhex(appendix_a_1_1::IKM_E), || {
        seal(
            &public,
            &unhex(appendix_a_1_1::INFO),
            &unhex(appendix_a_1_1::PT_0),
        )
        .expect("seals")
    });
    assert_eq!(enc.as_slice(), unhex(appendix_a_1_1::PK_E));
    assert_eq!(ciphertext, unhex(appendix_a_1_1::CT_0_NO_AAD));
}

#[test]
fn the_published_no_aad_ciphertext_opens_through_the_facade() {
    let secret = ReaderSecretKey::from_bytes(&unhex(appendix_a_1_1::SK_R)).expect("key");
    let opened = open(
        &secret,
        &unhex(appendix_a_1_1::PK_E),
        &unhex(appendix_a_1_1::INFO),
        &unhex(appendix_a_1_1::CT_0_NO_AAD),
    )
    .expect("opens");
    assert_eq!(opened.as_slice(), unhex(appendix_a_1_1::PT_0));
}

#[test]
fn the_published_ciphertext_opens_through_the_same_key_schedule() {
    // The RFC ciphertext is bound to aad "Count-0", which this module does not take; opening it through the
    // backend with that aad proves the key schedule this module sits on matches the published one.
    use hpke_rs::{Hpke, HpkePrivateKey, Mode};
    let hpke = Hpke::<hpke_rs_rust_crypto::HpkeRustCrypto>::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes128Gcm,
    );
    let opened = hpke
        .open(
            &unhex(appendix_a_1_1::PK_E),
            &HpkePrivateKey::from(unhex(appendix_a_1_1::SK_R)),
            &unhex(appendix_a_1_1::INFO),
            &unhex(appendix_a_1_1::AAD_0),
            &unhex(appendix_a_1_1::CT_0),
            None,
            None,
            None,
        )
        .expect("the published ciphertext opens");
    assert_eq!(opened, unhex(appendix_a_1_1::PT_0));
}

#[test]
fn a_seal_opens_and_two_seals_of_the_same_input_differ() {
    let pair = pair();
    let (enc, ct) = seal(&pair.public, b"info", b"the drive key").expect("seals");
    let opened = open(&pair.secret, &enc, b"info", &ct).expect("opens");
    assert_eq!(opened.as_slice(), b"the drive key");
    let (enc_again, ct_again) = seal(&pair.public, b"info", b"the drive key").expect("seals");
    assert_ne!(enc, enc_again, "fresh ephemeral key each time");
    assert_ne!(ct, ct_again);
}

#[test]
fn the_derivation_is_fixed_by_seed_and_label() {
    let one = pair();
    let again = pair();
    assert_eq!(one.public, again.public);
    let other_label = derive_reader_keypair(&seed(), b"other").expect("derives");
    assert_ne!(one.public, other_label.public, "a label separates keys");
    let other_seed = derive_reader_keypair(&[8; KEY_LEN], b"drive").expect("derives");
    assert_ne!(one.public, other_seed.public);
    // Pinned: the public key for seed [7; 32] and label "drive".
    assert_eq!(hex::encode(one.public.as_bytes()), PINNED_PUBLIC);
}

#[test]
fn the_wrong_info_key_or_a_flipped_bit_refuses() {
    let pair = pair();
    let stranger = derive_reader_keypair(&seed(), b"stranger").expect("derives");
    let (enc, ct) = seal(&pair.public, b"info", b"payload").expect("seals");
    assert_eq!(
        open(&pair.secret, &enc, b"other info", &ct).unwrap_err(),
        ReaderSealError::Open
    );
    assert_eq!(
        open(&stranger.secret, &enc, b"info", &ct).unwrap_err(),
        ReaderSealError::Open
    );
    let mut flipped = ct.clone();
    flipped[0] ^= 1;
    assert_eq!(
        open(&pair.secret, &enc, b"info", &flipped).unwrap_err(),
        ReaderSealError::Open
    );
    let mut other_enc = enc;
    other_enc[0] ^= 1;
    assert!(open(&pair.secret, &other_enc, b"info", &ct).is_err());
}

#[test]
fn a_key_or_encapsulation_of_the_wrong_length_refuses() {
    assert_eq!(
        ReaderPublicKey::from_bytes(&[1; 31]).unwrap_err(),
        ReaderSealError::Key
    );
    assert_eq!(
        ReaderPublicKey::from_bytes(&[1; 33]).unwrap_err(),
        ReaderSealError::Key
    );
    assert_eq!(
        ReaderSecretKey::from_bytes(&[]).unwrap_err(),
        ReaderSealError::Key
    );
    let pair = pair();
    let (enc, ct) = seal(&pair.public, b"info", b"p").expect("seals");
    assert_eq!(
        open(&pair.secret, &enc[..31], b"info", &ct).unwrap_err(),
        ReaderSealError::Key
    );
}

/// The encodings of the points of small order on Curve25519 (RFC 7748), which make the DH output all zero.
fn small_order_points() -> Vec<[u8; KEY_LEN]> {
    let mut points = vec![[0u8; KEY_LEN], {
        let mut one = [0u8; KEY_LEN];
        one[0] = 1;
        one
    }];
    points.push(
        <[u8; KEY_LEN]>::try_from(unhex(
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        ))
        .expect("32"),
    );
    points.push(
        <[u8; KEY_LEN]>::try_from(unhex(
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        ))
        .expect("32"),
    );
    let mut p_minus_one = [0xff; KEY_LEN];
    p_minus_one[0] = 0xec;
    p_minus_one[31] = 0x7f;
    points.push(p_minus_one);
    points
}

#[test]
fn a_public_key_of_small_order_is_refused_when_it_is_received() {
    for point in small_order_points() {
        assert_eq!(
            ReaderPublicKey::from_bytes(&point).unwrap_err(),
            ReaderSealError::Key,
            "{}",
            hex::encode(point)
        );
        // The same point with the unused top bit set is the same point.
        let mut high = point;
        high[31] |= 0x80;
        assert_eq!(
            ReaderPublicKey::from_bytes(&high).unwrap_err(),
            ReaderSealError::Key,
            "{}",
            hex::encode(high)
        );
    }
    // A genuine key is still accepted.
    assert!(ReaderPublicKey::from_bytes(pair().public.as_bytes()).is_ok());
}

#[test]
fn sealing_to_a_small_order_key_refuses_even_if_one_is_built_around_the_check() {
    for point in small_order_points() {
        let public = ReaderPublicKey(point);
        assert!(
            seal(&public, b"info", b"p").is_err(),
            "{}",
            hex::encode(point)
        );
    }
}

#[test]
fn an_encapsulation_of_small_order_refuses_to_open() {
    let pair = pair();
    let (_, ct) = seal(&pair.public, b"info", b"p").expect("seals");
    for point in small_order_points() {
        assert!(
            open(&pair.secret, &point, b"info", &ct).is_err(),
            "{}",
            hex::encode(point)
        );
    }
}

#[test]
fn the_facade_reads_the_suite_from_the_policy_accessor() {
    let pair = pair();
    let (enc, ct) = seal(&pair.public, b"info", b"payload").expect("seals");
    // Under another AEAD the same bytes do not open, and a seal made there does not open under the default.
    let chacha =
        ReaderSealSuite::of(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);
    READER_SEAL_SUITE_OVERRIDE.with(|cell| cell.set(Some(chacha)));
    let under_override = open(&pair.secret, &enc, b"info", &ct);
    let (enc2, ct2) = seal(&pair.public, b"info", b"payload").expect("seals");
    READER_SEAL_SUITE_OVERRIDE.with(|cell| cell.set(None));
    assert!(under_override.is_err(), "the override reached the open");
    assert!(
        open(&pair.secret, &enc2, b"info", &ct2).is_err(),
        "the override reached the seal"
    );
    assert!(
        open(&pair.secret, &enc, b"info", &ct).is_ok(),
        "the default is back"
    );
}

#[test]
fn a_suite_whose_kem_is_not_x25519_is_refused() {
    let p256 = ReaderSealSuite::of(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256);
    READER_SEAL_SUITE_OVERRIDE.with(|cell| cell.set(Some(p256)));
    let derived = derive_reader_keypair(&seed(), b"drive");
    READER_SEAL_SUITE_OVERRIDE.with(|cell| cell.set(None));
    assert_eq!(derived.unwrap_err(), ReaderSealError::Suite);
}

/// The public key for seed `[7; 32]` and label `drive`, computed apart from this crate (HKDF-SHA256, then the RFC 9180
/// section 7.1.3 derivation and an X25519 base-point multiplication).
const PINNED_PUBLIC: &str = "46d73711e837b09b09a9b41feec41051615ba87776ac7a1303ed5a92478ab374";
