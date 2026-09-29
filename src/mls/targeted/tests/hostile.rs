//! Hostile length prefixes and truncations, at every level a message is parsed: the outer
//! envelope, the `TargetedMessage`, the decrypted sender data and the decrypted content. Each must
//! be refused without a panic (debug and release alike) and without acting on the claimed length.

use tls_codec::VLBytes;

use super::refusals::*;
use super::support::*;
use crate::mls::targeted::wire::{to_bytes, Reader};
use crate::mls::targeted::{open, seal_content, OpenError};

/// A four-byte prefix claiming the largest length a four-byte prefix can carry (0x3fff_ffff).
const HUGE: [u8; 4] = [0xbf, 0xff, 0xff, 0xff];
/// The eight-byte form, which MLS does not use.
const EIGHT: [u8; 8] = [0xc0, 0, 0, 0, 0, 0, 0, 1];

fn vl(bytes: &[u8]) -> Vec<u8> {
    to_bytes(&VLBytes::new(bytes.to_vec())).expect("vector")
}

fn envelope_around(inner: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 1];
    bytes.extend_from_slice(&vl(inner));
    bytes
}

/// A `TargetedMessage` whose fields are empty except that field `at` (0 group id, 1 authenticated
/// data, 2 encrypted sender data, 3 ciphertext) carries `prefix` and no bytes after it.
fn message_with_bad_field(at: usize, prefix: &[u8]) -> Vec<u8> {
    let field = |index: usize| -> Vec<u8> {
        if index == at {
            prefix.to_vec()
        } else {
            vec![0]
        }
    };
    let mut inner = field(0);
    inner.extend_from_slice(&[0; 8]);
    inner.extend_from_slice(&[0; 4]);
    for index in 1..4 {
        inner.extend_from_slice(&field(index));
    }
    inner
}

fn assert_refused_everywhere(prefix: &[u8], label: &str, content_padding: usize) {
    let (a, b, _c, sealed) = sealed_a_to_b();

    let refused = |bytes: &[u8], want: OpenError, what: &str| {
        reset_open_calls();
        assert_eq!(
            open(&b.provider, b.group(), bytes).err(),
            Some(want),
            "{label}: {what}"
        );
        assert_eq!(open_calls(), 0, "{label}: {what}: nothing was decrypted");
    };

    let mut outer = vec![0, 1];
    outer.extend_from_slice(prefix);
    refused(&outer, OpenError::Malformed, "envelope");

    for field in 0..4 {
        refused(
            &envelope_around(&message_with_bad_field(field, prefix)),
            OpenError::Malformed,
            &format!("message field {field}"),
        );
    }

    let mut bad_signature = 7u32.to_be_bytes().to_vec();
    bad_signature.extend_from_slice(prefix);
    refused(
        &forge_sender_auth_raw(&b, &sealed, &bad_signature),
        OpenError::SenderAuthData,
        "sender data signature",
    );
    let mut bad_kem = 7u32.to_be_bytes().to_vec();
    bad_kem.push(0);
    bad_kem.extend_from_slice(prefix);
    refused(
        &forge_sender_auth_raw(&b, &sealed, &bad_kem),
        OpenError::SenderAuthData,
        "sender data kem output",
    );

    let mut content = prefix.to_vec();
    content.resize(content.len() + content_padding, 0);
    let sealed_content = seal_content(&a.provider, a.group(), &a.signer, b.leaf(), b"", &content)
        .expect("seal hostile content");
    reset_open_calls();
    assert_eq!(
        open(&b.provider, b.group(), &sealed_content).err(),
        Some(OpenError::Malformed),
        "{label}: decrypted content"
    );
}

#[test]
fn a_prefix_claiming_a_gigabyte_is_refused_at_every_level() {
    assert_refused_everywhere(&HUGE, "0x3fffffff", 16);
}

#[test]
fn an_eight_byte_prefix_is_refused_at_every_level() {
    assert_refused_everywhere(&EIGHT, "eight-byte prefix", 16);
}

#[test]
fn a_prefix_that_is_longer_than_needed_is_refused_at_every_level() {
    // Length 5 written in the two-byte form.
    assert_refused_everywhere(&[0x40, 0x05, 1, 2, 3, 4, 5], "non-minimal prefix", 0);
}

#[test]
fn a_prefix_claiming_more_than_remains_is_refused_at_every_level() {
    assert_refused_everywhere(&[0x05, 1, 2], "short body", 0);
}

#[test]
fn every_truncation_of_an_envelope_is_refused() {
    let (_a, b, _c, sealed) = sealed_a_to_b();
    for cut in 0..sealed.len() {
        assert_eq!(
            open(&b.provider, b.group(), &sealed[..cut]).err(),
            Some(OpenError::Malformed),
            "envelope cut at {cut}"
        );
    }
}

#[test]
fn every_truncation_of_the_inner_message_is_refused() {
    let (_a, b, _c, sealed) = sealed_a_to_b();
    let inner = to_bytes(&parse(&sealed)).expect("inner");
    for cut in 0..inner.len() {
        assert_eq!(
            open(&b.provider, b.group(), &envelope_around(&inner[..cut])).err(),
            Some(OpenError::Malformed),
            "inner message cut at {cut}"
        );
    }
}

#[test]
fn a_truncated_sender_data_or_content_is_refused() {
    let (a, b, _c, sealed) = sealed_a_to_b();
    for plaintext in [
        &[][..],
        &[0, 0][..],
        &[0, 0, 0, 1][..],
        &[0, 0, 0, 1, 0][..],
    ] {
        reset_open_calls();
        assert_eq!(
            open(
                &b.provider,
                b.group(),
                &forge_sender_auth_raw(&b, &sealed, plaintext)
            )
            .err(),
            Some(OpenError::SenderAuthData)
        );
    }
    for content in [&[][..], &[0x05, 1, 2][..], &[0x40][..]] {
        let sealed_content =
            seal_content(&a.provider, a.group(), &a.signer, b.leaf(), b"", content).expect("seal");
        assert_eq!(
            open(&b.provider, b.group(), &sealed_content).err(),
            Some(OpenError::Malformed)
        );
    }
}

#[test]
fn the_reader_agrees_with_the_serializer_on_valid_vectors_and_refuses_the_rest() {
    for length in [0usize, 1, 62, 63, 64, 300, 16_383, 16_384, 70_000] {
        let body = vec![0xa5u8; length];
        let encoded = vl(&body);
        let mut reader = Reader::new(&encoded);
        assert_eq!(reader.vector(), Some(body.as_slice()), "length {length}");
        assert!(reader.is_empty());
    }
    for bad in [
        &[][..],
        &[0x40][..],
        &[0x80, 0, 0][..],
        &[0xc0, 0, 0, 0, 0, 0, 0, 0][..],
        &[0x40, 0x01, 9][..],
        &[0x80, 0, 0, 0x01, 9][..],
        &[0x3f][..],
    ] {
        assert_eq!(Reader::new(bad).vector(), None, "{bad:?}");
    }
}

#[test]
fn a_large_payload_round_trips_through_the_reader() {
    // Serializer output at the three-width boundary is accepted by the reader.
    let (a, b, _c) = three();
    let sealed = crate::mls::targeted::seal(
        &a.provider,
        a.group(),
        &a.signer,
        b.leaf(),
        b"ad",
        &[7u8; 70_000],
        3,
    )
    .expect("seal");
    let opened = open(&b.provider, b.group(), &sealed).expect("open");
    assert_eq!(opened.application_data.len(), 70_000);
}
