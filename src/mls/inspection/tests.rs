use super::*;
use crate::{identity::generate_identity, mls::groups::*};

fn pair() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (_, _, alice) = generate_identity("inspection-alice".into(), now).unwrap();
    let (_, package, bob) = generate_identity("inspection-bob".into(), now).unwrap();
    let initial = create_group("inspection-room".into(), alice.clone()).unwrap();
    let (joined, welcome, commit) = add_member(initial.clone(), alice, package).unwrap();
    let (bob_state, bob_bundle) = process_welcome(welcome.clone(), bob).unwrap();
    let (_, message) =
        encrypt_message(bob_state.clone(), bob_bundle, b"private body".to_vec()).unwrap();
    (initial, joined, bob_state, message, commit)
}

#[test]
fn private_framing_reports_the_actual_group_epoch_and_content_without_processing() {
    let (initial, joined, receiver, message, commit) = pair();
    let before = message.clone();
    let local = inspect_group_state(&joined).unwrap();
    let header = inspect_private_message(&message).unwrap().unwrap();
    assert_eq!(header.group_id, b"inspection-room");
    assert_eq!(header.epoch, local.epoch);
    assert_eq!(header.content_type, PrivateContentType::Application);
    assert_eq!(
        inspect_group_state(&initial).unwrap().epoch + 1,
        header.epoch
    );
    assert_eq!(
        message, before,
        "inspection never consumes the caller's message"
    );
    assert_eq!(inspect_group_state(&receiver).unwrap().epoch, local.epoch);
    let commit_header = inspect_private_message(&commit).unwrap().unwrap();
    assert_eq!(commit_header.content_type, PrivateContentType::Commit);
    assert_eq!(commit_header.epoch + 1, header.epoch);
}

#[test]
fn private_commit_and_proposal_framing_keep_their_clear_content_type() {
    let (_, _, _, message, _) = pair();
    let mut reader = std::io::Cursor::new(message.as_slice());
    u16::tls_deserialize(&mut reader).unwrap();
    WireFormat::tls_deserialize(&mut reader).unwrap();
    GroupId::tls_deserialize(&mut reader).unwrap();
    u64::tls_deserialize(&mut reader).unwrap();
    let at = reader.position() as usize;
    for (byte, expected) in [
        (2, PrivateContentType::Proposal),
        (3, PrivateContentType::Commit),
    ] {
        let mut other = message.clone();
        other[at] = byte;
        assert_eq!(
            inspect_private_message(&other)
                .unwrap()
                .unwrap()
                .content_type,
            expected
        );
    }
}

#[test]
fn inspection_refuses_malformed_trailing_and_oversized_wire_and_invalid_local_state() {
    let (_, state, _, message, _) = pair();
    let mut trailing = message.clone();
    trailing.push(0);
    for bytes in [
        vec![],
        vec![0, 1, 2],
        trailing,
        vec![0; crate::mls::MAX_MLS_WIRE_BYTES + 1],
    ] {
        assert!(inspect_private_message(&bytes).is_err());
    }
    assert!(inspect_group_state(b"invalid").is_err());
    let mut missing: super::super::GroupState = serde_json::from_slice(&state).unwrap();
    missing.storage_map.clear();
    assert!(inspect_group_state(&serde_json::to_vec(&missing).unwrap()).is_err());
}

#[test]
fn created_and_welcome_installed_groups_have_three_past_epoch_retention() {
    let (initial, joined, receiver, _, _) = pair();
    for state in [&initial, &joined, &receiver] {
        assert_eq!(
            inspect_group_state(state).unwrap().max_past_epochs,
            3,
            "creation and Welcome join use the shared receive-retention policy"
        );
    }
}

#[test]
fn public_messages_are_not_private_framing_and_configured_retention_is_read_from_state() {
    let (initial, _, _, _, _) = pair();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (_, _, alice) = generate_identity("public-inspection-alice".into(), now).unwrap();
    let (_, package, _) = generate_identity("public-inspection-bob".into(), now).unwrap();
    let fresh = create_group("public-inspection".into(), alice.clone()).unwrap();
    let mut state: super::super::GroupState = serde_json::from_slice(&fresh).unwrap();
    let provider = InspectionProvider(OpenMlsRustCrypto::default());
    *provider.0.storage().values.write().unwrap() =
        std::mem::take(&mut state.storage_map).into_iter().collect();
    let group_id = GroupId::from_slice(&state.group_id);
    let mut group = openmls::prelude::MlsGroup::load(provider.0.storage(), &group_id)
        .unwrap()
        .unwrap();
    let config = MlsGroupJoinConfig::builder()
        .wire_format_policy(openmls::prelude::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(1)
        .build();
    group
        .set_configuration(provider.0.storage(), &config)
        .unwrap();
    state.storage_map = provider
        .0
        .storage()
        .values
        .read()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let configured = serde_json::to_vec(&state).unwrap();
    assert_eq!(
        inspect_group_state(&configured).unwrap().max_past_epochs,
        1,
        "retention is metadata, not a hardcoded zero"
    );
    assert_eq!(inspect_group_state(&initial).unwrap().max_past_epochs, 3);
    let (_, welcome, public_commit) = add_member(configured, alice, package).unwrap();
    assert_eq!(inspect_private_message(&public_commit).unwrap(), None);
    let (welcome_wire, _): (Vec<u8>, Vec<u8>) = serde_json::from_slice(&welcome).unwrap();
    assert_eq!(inspect_private_message(&welcome_wire).unwrap(), None);
}

#[test]
fn the_wire_size_guard_runs_before_the_tls_decoder() {
    let bytes = vec![0; crate::mls::MAX_MLS_WIRE_BYTES + 1];
    let error = inspect_private_message(&bytes).unwrap_err();
    assert!(
        error.to_string().contains("MLS wire-input cap"),
        "oversized framing must be refused by the pre-decode bound: {error}"
    );
}

fn refuses_without_unwinding(bytes: &[u8]) {
    let inspected = std::panic::catch_unwind(|| inspect_group_state(bytes));
    assert!(
        inspected.is_ok(),
        "corrupt stored metadata must return an error, never unwind through the caller"
    );
    assert!(
        inspected.unwrap().is_err(),
        "incomplete or corrupt metadata cannot yield a group epoch"
    );
}

#[test]
fn missing_or_corrupt_context_and_configuration_are_errors_without_unwinding() {
    let (_, joined, _, _, _) = pair();
    for case in [
        "missing-config",
        "missing-context",
        "corrupt-context",
        "corrupt-config",
    ] {
        let mut state: super::super::GroupState = serde_json::from_slice(&joined).unwrap();
        let provider = InspectionProvider(OpenMlsRustCrypto::default());
        *provider.0.storage().values.write().unwrap() =
            std::mem::take(&mut state.storage_map).into_iter().collect();
        let id = GroupId::from_slice(&state.group_id);
        match case {
            "missing-config" => provider.0.storage().delete_group_config(&id).unwrap(),
            "missing-context" => provider.0.storage().delete_context(&id).unwrap(),
            corrupt => {
                let label: &[u8] = if corrupt == "corrupt-config" {
                    b"MlsGroupJoinConfig"
                } else {
                    b"GroupContext"
                };
                let mut values = provider.0.storage().values.write().unwrap();
                let record = values
                    .iter_mut()
                    .find(|(key, _)| key.starts_with(label))
                    .expect("the actual metadata entry");
                *record.1 = b"malformed metadata".to_vec();
            }
        }
        state.storage_map = provider
            .0
            .storage()
            .values
            .read()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        refuses_without_unwinding(&serde_json::to_vec(&state).unwrap());
    }
}

#[test]
fn truncated_storage_maps_and_serialized_snapshots_are_errors_without_unwinding() {
    let (_, joined, _, _, _) = pair();
    for length in [0, joined.len() / 2, joined.len() - 1] {
        refuses_without_unwinding(&joined[..length]);
    }
    let mut state: super::super::GroupState = serde_json::from_slice(&joined).unwrap();
    state.storage_map.clear();
    refuses_without_unwinding(&serde_json::to_vec(&state).unwrap());
}
