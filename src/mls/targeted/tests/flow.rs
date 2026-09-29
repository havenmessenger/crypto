//! Sealing and opening between real group members.

use super::support::*;
use crate::mls::targeted::{open, seal, SealError};

#[test]
fn each_recipient_opens_its_own_message_and_authenticated_data_round_trips() {
    let (a, b, c) = three();
    let to_b = seal(
        &a.provider,
        a.group(),
        &a.signer,
        b.leaf(),
        b"ad-for-b",
        b"hello b",
        0,
    )
    .expect("seal to b");
    let to_c = seal(
        &a.provider,
        a.group(),
        &a.signer,
        c.leaf(),
        b"ad-for-c",
        b"hello c",
        0,
    )
    .expect("seal to c");

    let opened_b = open(&b.provider, b.group(), &to_b).expect("b opens its message");
    assert_eq!(opened_b.application_data.as_slice(), b"hello b");
    assert_eq!(opened_b.authenticated_data, b"ad-for-b");
    assert_eq!(opened_b.sender_leaf_index, a.leaf().u32());

    let opened_c = open(&c.provider, c.group(), &to_c).expect("c opens its message");
    assert_eq!(opened_c.application_data.as_slice(), b"hello c");
    assert_eq!(opened_c.authenticated_data, b"ad-for-c");
}

#[test]
fn a_message_between_two_non_founding_members_opens() {
    let (_a, b, c) = three();
    let sealed = seal(
        &b.provider,
        b.group(),
        &b.signer,
        c.leaf(),
        b"",
        b"from b",
        0,
    )
    .expect("seal");
    let opened = open(&c.provider, c.group(), &sealed).expect("open");
    assert_eq!(opened.sender_leaf_index, b.leaf().u32());
    assert_eq!(opened.application_data.as_slice(), b"from b");
}

#[test]
fn padding_of_any_length_is_accepted_and_hidden_from_the_application_data() {
    let (a, b, _c) = three();
    let mut lengths = std::collections::BTreeSet::new();
    for padding in [0usize, 1, 31, 300] {
        let sealed = seal(
            &a.provider,
            a.group(),
            &a.signer,
            b.leaf(),
            b"",
            b"payload",
            padding,
        )
        .expect("seal");
        lengths.insert(sealed.len());
        let opened = open(&b.provider, b.group(), &sealed).expect("open");
        assert_eq!(opened.application_data.as_slice(), b"payload");
    }
    assert_eq!(lengths.len(), 4, "each padding length changes the size");
}

#[test]
fn an_empty_payload_and_empty_authenticated_data_round_trip() {
    let (a, b, _c) = three();
    let sealed = seal(&a.provider, a.group(), &a.signer, b.leaf(), b"", b"", 0).expect("seal");
    let opened = open(&b.provider, b.group(), &sealed).expect("open");
    assert!(opened.application_data.is_empty());
    assert!(opened.authenticated_data.is_empty());
}

#[test]
fn a_message_opens_after_the_recipient_updated_its_own_leaf() {
    let (mut a, mut b, mut c) = three();
    let commit = b.self_update();
    a.apply(&commit);
    c.apply(&commit);
    let sealed = seal(
        &a.provider,
        a.group(),
        &a.signer,
        b.leaf(),
        b"",
        b"after",
        0,
    )
    .expect("seal");
    let opened = open(&b.provider, b.group(), &sealed).expect("open with the updated leaf key");
    assert_eq!(opened.application_data.as_slice(), b"after");
}

#[test]
fn a_message_opens_after_the_epoch_advanced_before_sealing() {
    let (mut a, mut b, mut c) = three();
    let commit = a.self_update();
    b.apply(&commit);
    c.apply(&commit);
    let sealed = seal(
        &a.provider,
        a.group(),
        &a.signer,
        c.leaf(),
        b"",
        b"epoch 2",
        0,
    )
    .expect("seal");
    let opened = open(&c.provider, c.group(), &sealed).expect("open");
    assert_eq!(opened.application_data.as_slice(), b"epoch 2");
}

#[test]
fn sealing_to_oneself_or_to_a_stranger_is_refused() {
    let (a, _b, _c) = three();
    assert_eq!(
        seal(&a.provider, a.group(), &a.signer, a.leaf(), b"", b"x", 0).err(),
        Some(SealError::Recipient)
    );
    let stranger = openmls::prelude::LeafNodeIndex::new(40);
    assert_eq!(
        seal(&a.provider, a.group(), &a.signer, stranger, b"", b"x", 0).err(),
        Some(SealError::Recipient)
    );
}

#[test]
fn oversized_inputs_are_refused_before_any_work() {
    let (a, b, _c) = three();
    let big = vec![0u8; crate::mls::targeted::MAX_CONTENT_BYTES + 1];
    assert_eq!(
        seal(&a.provider, a.group(), &a.signer, b.leaf(), b"", &big, 0).err(),
        Some(SealError::TooLarge)
    );
    assert_eq!(
        seal(
            &a.provider,
            a.group(),
            &a.signer,
            b.leaf(),
            b"",
            b"x",
            usize::MAX
        )
        .err(),
        Some(SealError::TooLarge)
    );
    let big_ad = vec![0u8; crate::mls::targeted::MAX_AUTHENTICATED_DATA_BYTES + 1];
    assert_eq!(
        seal(
            &a.provider,
            a.group(),
            &a.signer,
            b.leaf(),
            &big_ad,
            b"x",
            0
        )
        .err(),
        Some(SealError::TooLarge)
    );
}

#[test]
fn the_debug_form_of_an_opened_message_does_not_show_the_payload() {
    let (a, b, _c) = three();
    let sealed = seal(
        &a.provider,
        a.group(),
        &a.signer,
        b.leaf(),
        b"",
        b"very-secret-payload",
        0,
    )
    .expect("seal");
    let opened = open(&b.provider, b.group(), &sealed).expect("open");
    let shown = format!("{opened:?}");
    assert!(!shown.contains("very-secret-payload"));
    assert!(!shown.contains("118, 101"), "no byte dump of the payload");
}
