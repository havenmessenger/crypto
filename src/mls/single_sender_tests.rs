// SPDX-FileCopyrightText: 2026 The Haven Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Under the virtual-clients feature, a message this crate sends is confirmed as it is created, so the sender keeps no
//! secret for it.
//!
//! The group is a virtual client's: created from an emulation group's derivation epoch, so openmls decrypts a message
//! from the client's own leaf with a kept secret, the way an emulator decrypts a sibling's. The control is a message
//! openmls leaves unconfirmed: its sender decrypts it. A confirmed one comes back undecrypted, as
//! `ProcessedMessageContent::OwnPrivateMessage`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use openmls::component::{ComponentType, ComponentsList};
use openmls::components::vc_derivation_info::VC_COMPONENT_ID;
use openmls::prelude::test_utils::new_credential;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize as _, Serialize as _};

const CS: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn capabilities() -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![CS])
        .credentials(vec![CredentialType::Basic])
        .extensions(vec![ExtensionType::AppDataDictionary])
        .build()
}

/// A leaf that advertises the virtual-clients component.
fn leaf_extensions() -> Extensions<LeafNode> {
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(
        ComponentType::AppComponents.into(),
        vec![VC_COMPONENT_ID].tls_serialize_detached().unwrap(),
    );
    Extensions::from_vec(vec![Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dictionary),
    )])
    .unwrap()
}

/// An emulation group requires Safe AAD framing.
fn safe_aad() -> Extensions<GroupContext> {
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(
        ComponentType::SafeAad.into(),
        ComponentsList::new(Vec::new())
            .tls_serialize_detached()
            .unwrap(),
    );
    Extensions::single(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dictionary),
    ))
    .unwrap()
}

/// A virtual client's room: an emulation group of one emulator, and a group the virtual client creates from it,
/// whose application messages are PrivateMessages. Returns the provider, the room and the virtual client's signer.
fn virtual_client_room() -> (
    OpenMlsRustCrypto,
    MlsGroup,
    impl openmls_traits::signatures::Signer,
) {
    let provider = OpenMlsRustCrypto::default();
    let (emulator_credential, emulator_signer) =
        new_credential(&provider, b"emulator", CS.signature_algorithm());
    let emulation = MlsGroup::new(
        &provider,
        &emulator_signer,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(CS)
            .use_ratchet_tree_extension(true)
            .capabilities(capabilities())
            .with_leaf_node_extensions(leaf_extensions())
            .unwrap()
            .emulation_group(true)
            .with_group_context_extensions(safe_aad())
            .build(),
        emulator_credential,
    )
    .unwrap();
    let (client_credential, client_signer) =
        new_credential(&provider, b"virtual client", CS.signature_algorithm());
    let room = MlsGroup::builder()
        .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(CS)
        .use_ratchet_tree_extension(true)
        .with_capabilities(capabilities())
        .with_leaf_node_extensions(leaf_extensions())
        .unwrap()
        .vc_emulation(emulation.group_id())
        .build(&provider, &client_signer, client_credential)
        .unwrap();
    (provider, room, client_signer)
}

/// The plaintext the sender gets back from processing its own message: `Some` only if it kept the message's secret.
fn read_back(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    message: &MlsMessageOut,
) -> Option<Vec<u8>> {
    let bytes = message.tls_serialize_detached().unwrap();
    let protocol = MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    match group
        .process_message(provider, protocol)
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::ApplicationMessage(message) => Some(message.into_bytes()),
        ProcessedMessageContent::OwnPrivateMessage { .. } => None,
        other => panic!("not an application message: {other:?}"),
    }
}

#[test]
fn an_unconfirmed_message_is_decrypted_by_its_sender() {
    let (provider, mut room, signer) = virtual_client_room();
    let created = room
        .create_unconfirmed_message(&provider, &signer, b"unconfirmed")
        .unwrap();
    assert_eq!(
        read_back(&mut room, &provider, &created.message).as_deref(),
        Some(&b"unconfirmed"[..]),
        "the control: openmls keeps the secret of a message it has not been told is confirmed"
    );
}

#[test]
fn a_message_sent_through_this_crate_keeps_no_secret() {
    let (provider, mut room, signer) = virtual_client_room();
    let sent = super::create_message(&mut room, &provider, &signer, b"confirmed").unwrap();
    assert_eq!(
        read_back(&mut room, &provider, &sent),
        None,
        "the sender kept the message's secret: it was not confirmed as it was created"
    );
}
