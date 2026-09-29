//! Every refusal of the recipient validation, in the draft's order, and the proof that the
//! signature is checked before any content decryption.

use openmls::prelude::*;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::VLBytes;

use super::support::*;
use crate::mls::targeted::wire::{
    from_bytes_exact, to_bytes, Envelope, SenderAuthData, SenderAuthDataAad, TargetedMessage,
};
use crate::mls::targeted::{
    epoch_secrets, hpke, leaf_key, open, seal, seal_content, sender_auth_key_nonce, OpenError,
    SealError,
};
use crate::mls::MlsSigner;
use crate::suite_policy::targeted_message_suite;

pub(super) fn parse(envelope: &[u8]) -> TargetedMessage {
    let envelope: Envelope = from_bytes_exact(envelope).expect("envelope");
    from_bytes_exact(envelope.targeted_message.as_slice()).expect("message")
}

pub(super) fn assemble(message: &TargetedMessage) -> Vec<u8> {
    to_bytes(&Envelope {
        draft_version: crate::mls::targeted::wire::DRAFT_VERSION_01,
        targeted_message: VLBytes::new(to_bytes(message).expect("message bytes")),
    })
    .expect("envelope bytes")
}

pub(super) fn mutate(envelope: &[u8], edit: impl FnOnce(&mut TargetedMessage)) -> Vec<u8> {
    let mut message = parse(envelope);
    edit(&mut message);
    assemble(&message)
}

fn flip(bytes: &mut VLBytes, at: usize) {
    let mut raw = bytes.as_slice().to_vec();
    let at = at % raw.len();
    raw[at] ^= 0x01;
    *bytes = VLBytes::new(raw);
}

/// Re-encrypt the sender authentication data with `edit` applied, using the exporter secret the
/// recipient's own group holds (any member of the epoch can do this: the secret is group-wide).
pub(super) fn forge_sender_auth(
    member: &Peer,
    envelope: &[u8],
    edit: impl FnOnce(&mut SenderAuthData),
) -> Vec<u8> {
    let group = member.group();
    let crypto = member.provider.crypto();
    let suite = targeted_message_suite(group.ciphersuite()).expect("suite");
    let secrets = epoch_secrets(crypto, group, &suite).expect("secrets");
    let mut message = parse(envelope);
    let (key, nonce) = sender_auth_key_nonce(
        crypto,
        &suite,
        &secrets.sender_auth_data,
        message.ciphertext.as_slice(),
    )
    .expect("key and nonce");
    let aad = to_bytes(&SenderAuthDataAad {
        group_id: message.group_id.as_slice(),
        epoch: message.epoch,
        recipient_leaf_index: message.recipient_leaf_index,
    })
    .expect("aad");
    let plain = crypto
        .aead_decrypt(
            suite.aead,
            &key,
            message.encrypted_sender_auth_data.as_slice(),
            &nonce,
            &aad,
        )
        .expect("decrypt sender auth data");
    let mut sender_auth: SenderAuthData = from_bytes_exact(&plain).expect("sender auth data");
    edit(&mut sender_auth);
    let forged = crypto
        .aead_encrypt(
            suite.aead,
            &key,
            &to_bytes(&sender_auth).expect("bytes"),
            &nonce,
            &aad,
        )
        .expect("encrypt sender auth data");
    message.encrypted_sender_auth_data = VLBytes::new(forged);
    assemble(&message)
}

/// Like [`forge_sender_auth`], but the decrypted sender data is replaced by arbitrary bytes.
pub(super) fn forge_sender_auth_raw(member: &Peer, envelope: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let group = member.group();
    let crypto = member.provider.crypto();
    let suite = targeted_message_suite(group.ciphersuite()).expect("suite");
    let secrets = epoch_secrets(crypto, group, &suite).expect("secrets");
    let mut message = parse(envelope);
    let (key, nonce) = sender_auth_key_nonce(
        crypto,
        &suite,
        &secrets.sender_auth_data,
        message.ciphertext.as_slice(),
    )
    .expect("key and nonce");
    let aad = to_bytes(&SenderAuthDataAad {
        group_id: message.group_id.as_slice(),
        epoch: message.epoch,
        recipient_leaf_index: message.recipient_leaf_index,
    })
    .expect("aad");
    let forged = crypto
        .aead_encrypt(suite.aead, &key, plaintext, &nonce, &aad)
        .expect("encrypt sender auth data");
    message.encrypted_sender_auth_data = VLBytes::new(forged);
    assemble(&message)
}

pub(super) fn reset_open_calls() {
    hpke::OPEN_CALLS.with(|calls| calls.set(0));
}

pub(super) fn open_calls() -> usize {
    hpke::OPEN_CALLS.with(std::cell::Cell::get)
}

pub(super) const PAYLOAD: &[u8] =
    b"a payload long enough that the ciphertext is well past the sample";

pub(super) fn sealed_a_to_b() -> (Peer, Peer, Peer, Vec<u8>) {
    let (a, b, c) = three();
    let sealed = seal(
        &a.provider,
        a.group(),
        &a.signer,
        b.leaf(),
        b"ad",
        PAYLOAD,
        0,
    )
    .expect("seal");
    (a, b, c, sealed)
}

#[test]
fn a_member_that_is_not_the_recipient_cannot_open() {
    let (_a, _b, c, sealed) = sealed_a_to_b();
    reset_open_calls();
    assert_eq!(
        open(&c.provider, c.group(), &sealed).err(),
        Some(OpenError::NotForThisMember)
    );
    assert_eq!(open_calls(), 0);
}

#[test]
fn re_addressing_a_message_to_another_member_is_refused() {
    let (_a, _b, c, sealed) = sealed_a_to_b();
    let readdressed = mutate(&sealed, |m| m.recipient_leaf_index = c.leaf().u32());
    reset_open_calls();
    assert_eq!(
        open(&c.provider, c.group(), &readdressed).err(),
        Some(OpenError::SenderAuthData)
    );
    assert_eq!(open_calls(), 0);
}

#[test]
fn a_tampered_ciphertext_is_refused_at_the_signature_and_never_decrypted() {
    let (_a, b, _c, sealed) = sealed_a_to_b();
    let tampered = mutate(&sealed, |m| {
        let last = m.ciphertext.as_slice().len() - 1;
        flip(&mut m.ciphertext, last);
    });
    reset_open_calls();
    assert_eq!(
        open(&b.provider, b.group(), &tampered).err(),
        Some(OpenError::Signature)
    );
    assert_eq!(
        open_calls(),
        0,
        "no decryption may be attempted before the signature verifies"
    );
}

#[test]
fn a_tampered_ciphertext_sample_breaks_the_sender_data_and_is_never_decrypted() {
    let (_a, b, _c, sealed) = sealed_a_to_b();
    let tampered = mutate(&sealed, |m| flip(&mut m.ciphertext, 0));
    reset_open_calls();
    assert_eq!(
        open(&b.provider, b.group(), &tampered).err(),
        Some(OpenError::SenderAuthData)
    );
    assert_eq!(open_calls(), 0);
}

#[test]
fn tampered_encrypted_sender_auth_data_is_refused() {
    let (_a, b, _c, sealed) = sealed_a_to_b();
    let tampered = mutate(&sealed, |m| flip(&mut m.encrypted_sender_auth_data, 3));
    reset_open_calls();
    assert_eq!(
        open(&b.provider, b.group(), &tampered).err(),
        Some(OpenError::SenderAuthData)
    );
    assert_eq!(open_calls(), 0);
}

#[test]
fn tampered_authenticated_data_is_refused_at_the_signature() {
    let (_a, b, _c, sealed) = sealed_a_to_b();
    let tampered = mutate(&sealed, |m| flip(&mut m.authenticated_data, 0));
    reset_open_calls();
    assert_eq!(
        open(&b.provider, b.group(), &tampered).err(),
        Some(OpenError::Signature)
    );
    assert_eq!(open_calls(), 0);
}

#[test]
fn a_message_signed_by_a_key_that_is_not_the_senders_leaf_key_is_refused() {
    let (a, b, _c) = three();
    let impostor = Peer::new("impostor", suite());
    let sealed = seal(
        &a.provider,
        a.group(),
        &impostor.signer,
        b.leaf(),
        b"",
        PAYLOAD,
        0,
    )
    .expect("the sealer does not check the key against the tree");
    reset_open_calls();
    assert_eq!(
        open(&b.provider, b.group(), &sealed).err(),
        Some(OpenError::Signature)
    );
    assert_eq!(open_calls(), 0);
}

#[test]
fn a_sender_index_naming_another_member_fails_the_signature() {
    let (_a, b, c, sealed) = sealed_a_to_b();
    let forged = forge_sender_auth(&b, &sealed, |auth| auth.sender_leaf_index = c.leaf().u32());
    reset_open_calls();
    assert_eq!(
        open(&b.provider, b.group(), &forged).err(),
        Some(OpenError::Signature)
    );
    assert_eq!(open_calls(), 0);
}

#[test]
fn a_sender_index_outside_the_tree_is_refused() {
    let (_a, b, _c, sealed) = sealed_a_to_b();
    let forged = forge_sender_auth(&b, &sealed, |auth| auth.sender_leaf_index = 40);
    reset_open_calls();
    assert_eq!(
        open(&b.provider, b.group(), &forged).err(),
        Some(OpenError::SenderLeaf)
    );
    assert_eq!(open_calls(), 0);
}

#[test]
fn a_sender_index_naming_a_blank_leaf_is_refused() {
    let (mut a, mut b, mut c) = three();
    let sealed = {
        let (a2, _b2, _c2) = (&a, &b, &c);
        seal(
            &a2.provider,
            a2.group(),
            &a2.signer,
            c.leaf(),
            b"",
            PAYLOAD,
            0,
        )
        .expect("seal")
    };
    // Removing B blanks leaf 1 while C keeps leaf 2; a fresh message is then sealed in the new epoch.
    let commit = a.remove(b.leaf());
    c.apply(&commit);
    let _ = &mut b;
    let sealed_after = seal(&a.provider, a.group(), &a.signer, c.leaf(), b"", PAYLOAD, 0)
        .expect("seal in the new epoch");
    assert!(c.group().member_at(LeafNodeIndex::new(1)).is_none());
    let forged = forge_sender_auth(&c, &sealed_after, |auth| auth.sender_leaf_index = 1);
    reset_open_calls();
    assert_eq!(
        open(&c.provider, c.group(), &forged).err(),
        Some(OpenError::SenderLeaf)
    );
    assert_eq!(open_calls(), 0);
    let _ = sealed;
}

#[test]
fn a_non_zero_padding_byte_is_refused_after_decryption_and_releases_nothing() {
    let (a, b, _c) = three();
    let mut content = to_bytes(&VLBytes::new(b"payload".to_vec())).expect("content");
    content.extend_from_slice(&[0, 0, 1, 0]);
    let sealed = seal_content(&a.provider, a.group(), &a.signer, b.leaf(), b"", &content)
        .expect("seal with a non-zero pad");
    reset_open_calls();
    assert_eq!(
        open(&b.provider, b.group(), &sealed).err(),
        Some(OpenError::Padding)
    );
    assert_eq!(
        open_calls(),
        1,
        "the padding is only visible after decryption"
    );
}

#[test]
fn a_message_from_a_past_epoch_is_refused() {
    let (mut a, mut b, mut c) = three();
    let sealed = seal(&a.provider, a.group(), &a.signer, b.leaf(), b"", PAYLOAD, 0).expect("seal");
    let commit = a.self_update();
    b.apply(&commit);
    c.apply(&commit);
    reset_open_calls();
    assert_eq!(
        open(&b.provider, b.group(), &sealed).err(),
        Some(OpenError::EpochNotCurrent)
    );
    assert_eq!(open_calls(), 0);
}

#[test]
fn a_message_for_a_different_group_is_refused() {
    let (_a, _b, _c, sealed) = sealed_a_to_b();
    let (_a2, b2, _c2) = three();
    assert_eq!(
        open(&b2.provider, b2.group(), &sealed).err(),
        Some(OpenError::GroupMismatch)
    );
}

#[test]
fn an_unknown_draft_version_is_refused_before_the_body_is_read() {
    let (_a, b, _c, sealed) = sealed_a_to_b();
    let mut envelope: Envelope = from_bytes_exact(&sealed).expect("envelope");
    envelope.draft_version = 2;
    envelope.targeted_message = VLBytes::new(vec![0xff; 3]);
    let bytes = to_bytes(&envelope).expect("bytes");
    assert_eq!(
        open(&b.provider, b.group(), &bytes).err(),
        Some(OpenError::UnsupportedVersion)
    );
}

#[test]
fn malformed_and_oversized_envelopes_are_refused() {
    let (_a, b, _c, sealed) = sealed_a_to_b();
    let open_b = |bytes: &[u8]| open(&b.provider, b.group(), bytes).err();

    let mut trailing = sealed.clone();
    trailing.push(0);
    assert_eq!(open_b(&trailing), Some(OpenError::Malformed));

    assert_eq!(
        open_b(&sealed[..sealed.len() - 1]),
        Some(OpenError::Malformed)
    );
    assert_eq!(open_b(&[]), Some(OpenError::Malformed));
    assert_eq!(open_b(&[0x01; 64]), Some(OpenError::Malformed));
    assert_eq!(open_b(&[0xff; 64]), Some(OpenError::Malformed));

    let mut envelope: Envelope = from_bytes_exact(&sealed).expect("envelope");
    let mut inner = envelope.targeted_message.as_slice().to_vec();
    inner.push(0);
    envelope.targeted_message = VLBytes::new(inner);
    assert_eq!(
        open_b(&to_bytes(&envelope).expect("bytes")),
        Some(OpenError::Malformed),
        "trailing bytes inside the message are refused too"
    );

    let huge = vec![0u8; crate::mls::MAX_MLS_WIRE_BYTES + 1];
    assert_eq!(open_b(&huge), Some(OpenError::TooLarge));
}

#[test]
fn a_group_outside_the_accepted_suites_is_refused_both_ways() {
    let other = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    assert_ne!(other, suite());
    let mut a = Peer::new("a", other);
    let mut b = Peer::new("b", other);
    a.found(other, &mut [&mut b]);
    assert_eq!(
        seal(&a.provider, a.group(), &a.signer, b.leaf(), b"", b"x", 0).err(),
        Some(SealError::Suite)
    );
    let (_a, b1, _c, sealed) = sealed_a_to_b();
    let _ = b1;
    assert_eq!(
        open(&b.provider, b.group(), &sealed).err(),
        Some(OpenError::Suite)
    );
}

#[test]
fn a_signer_of_another_scheme_is_refused() {
    let (a, b, _c) = three();
    let wrong = MlsSigner {
        key: zeroize::Zeroizing::new(vec![1u8; 32]),
        scheme: openmls_traits::types::SignatureScheme::ECDSA_SECP256R1_SHA256,
    };
    assert_eq!(
        seal(&a.provider, a.group(), &wrong, b.leaf(), b"", b"x", 0).err(),
        Some(SealError::SignerScheme)
    );
}

#[test]
fn a_provider_without_the_leaf_key_cannot_open() {
    let (_a, b, _c, sealed) = sealed_a_to_b();
    let empty = openmls_rust_crypto::OpenMlsRustCrypto::default();
    reset_open_calls();
    assert_eq!(
        open(&empty, b.group(), &sealed).err(),
        Some(OpenError::LeafKey)
    );
    assert_eq!(open_calls(), 0);
}

#[test]
fn the_suite_seam_supplies_the_lengths_and_refuses_foreign_suites() {
    let derived = targeted_message_suite(suite()).expect("accepted suite");
    assert_eq!(
        (derived.kdf_nh, derived.aead_nk, derived.aead_nn),
        (32, 16, 12)
    );
    assert!(targeted_message_suite(
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )
    .is_err());
}

/// The leaf-key access reads a layout owned by openmls's storage. These guards make an upgrade or a
/// layout change fail here, loudly, instead of failing open in a deployment.
#[test]
fn leaf_key_access_reads_the_real_key_and_completes_an_hpke_round_trip() {
    let (a, mut b, mut c) = three();
    for round in 0..2 {
        let key = leaf_key::own_leaf_private_key(&b.provider, b.group())
            .expect("the provider holds the leaf key");
        let public = b
            .group()
            .member_at(b.leaf())
            .expect("member")
            .encryption_key;
        let config = suite().hpke_config();
        let crypto = b.provider.crypto();
        let sealed = crypto
            .hpke_seal(config, &public, b"info", b"aad", b"round trip")
            .expect("seal to the leaf public key");
        let opened = crypto
            .hpke_open(suite().hpke_config(), &sealed, &key, b"info", b"aad")
            .expect("the private key read from storage opens what the public key sealed");
        assert_eq!(opened, b"round trip");
        if round == 0 {
            // A self-update stores the new leaf pair in the standalone slot.
            let commit = b.self_update();
            c.apply(&commit);
        }
    }
    drop(a);
}

#[test]
fn the_key_pair_mirror_can_be_read_and_can_never_be_written() {
    let (_a, b, _c) = three();
    let values = b.provider.storage().values.read().expect("storage");
    let mut checked = 0;
    for value in values.values() {
        if let Ok(pairs) = serde_json::from_slice::<Vec<leaf_key::StoredKeyPair>>(value) {
            for pair in pairs {
                assert!(
                    serde_json::to_vec(&pair).is_err(),
                    "the mirror must refuse to serialize"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked > 0,
        "the stored epoch key pairs were not recognised"
    );
}

fn locked_version(name: &str) -> String {
    let lock = include_str!("../../../../Cargo.lock");
    let marker = format!("name = \"{name}\"\nversion = \"");
    let start = lock.find(&marker).expect("package in the lockfile") + marker.len();
    lock[start..]
        .split('"')
        .next()
        .expect("version")
        .to_string()
}

#[test]
fn the_openmls_version_that_the_key_mirror_was_checked_against_has_not_changed() {
    assert_eq!(
        locked_version("openmls"),
        "0.8.1",
        "re-check the stored key-pair layout in leaf_key.rs"
    );
    assert_eq!(locked_version("openmls_memory_storage"), "0.5.0");
    assert_eq!(locked_version("openmls_rust_crypto"), "0.5.1");
}

#[test]
fn no_algorithm_or_suite_value_is_hard_coded_in_the_targeted_message_code() {
    for (name, source) in [
        ("mod.rs", include_str!("../mod.rs")),
        ("hpke.rs", include_str!("../hpke.rs")),
        ("labels.rs", include_str!("../labels.rs")),
        ("leaf_key.rs", include_str!("../leaf_key.rs")),
    ] {
        assert!(!source.contains("0x0001"), "{name}");
        assert!(!source.contains("MLS_128_DHKEMX25519"), "{name}");
    }
}
