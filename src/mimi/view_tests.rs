//! The read-only views: what they show of a group, a KeyPackage and a Commit, that they show no key, and that they
//! refuse input that is not what they read.

#![allow(deprecated)] // the group-building helpers below are the legacy entry points the other MIMI tests use

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use super::*;
use crate::mimi::{
    mimi_add_member, mimi_add_member_commit_appsync, mimi_create_group, mimi_generate_identity,
    mimi_process_commit_summarized, mimi_process_welcome_non_atomic,
    MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
};
use crate::mls::GroupState;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Alice's group with Bob in it: Alice's state, Bob's state and bundle, and Carol's KeyPackage and identity name.
fn two_member_group() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let now = now_secs();
    let (_, _, alice) = mimi_generate_identity("alice@view.test".to_string(), now).unwrap();
    let (_, bob_kp, bob) = mimi_generate_identity("bob@view.test".to_string(), now).unwrap();
    let (_, carol_kp, _) = mimi_generate_identity("carol@view.test".to_string(), now).unwrap();
    let alice_state = mimi_create_group("view-group".to_string(), alice.clone()).unwrap();
    let (alice_state, welcome) = mimi_add_member(alice_state, alice.clone(), bob_kp).unwrap();
    let (bob_state, _) =
        mimi_process_welcome_non_atomic(welcome, bob.clone(), Vec::new(), String::new()).unwrap();
    (alice_state, alice, bob_state, bob, carol_kp)
}

/// Every secret and key a member holds for the group in `state`: the exporter secret, the epoch authenticator, and
/// every member's encryption and signature keys.
fn keys_of(state: &[u8]) -> Vec<Vec<u8>> {
    let state: GroupState = serde_json::from_slice(state).unwrap();
    let provider = OpenMlsRustCrypto::default();
    *provider.storage().values.write().unwrap() = state.storage_map.iter().cloned().collect();
    let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&state.group_id))
        .unwrap()
        .unwrap();
    let mut keys = vec![
        group
            .export_secret(provider.crypto(), "view test", b"", 32)
            .unwrap()
            .as_ref()
            .to_vec(),
        group.epoch_authenticator().as_slice().to_vec(),
    ];
    for member in group.members() {
        keys.push(member.encryption_key.clone());
        keys.push(member.signature_key.clone());
    }
    keys
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn a_group_view_shows_the_members_epoch_and_suite() {
    let (alice_state, _, bob_state, _, _) = two_member_group();
    let view = mimi_group_view(&bob_state).unwrap();
    assert_eq!(view.group_id, b"view-group");
    assert_eq!(view.epoch, 1);
    assert_eq!(view.cipher_suite, 0x0001);
    assert_eq!(view.leaves.len(), 2);
    let identities: Vec<&[u8]> = view
        .leaves
        .iter()
        .map(|leaf| leaf.identity.as_slice())
        .collect();
    assert!(identities.contains(&&b"alice@view.test"[..]));
    assert!(identities.contains(&&b"bob@view.test"[..]));
    assert!(view.leaves.iter().all(|leaf| leaf.credential_type == 1));
    let bob_leaf = view
        .leaves
        .iter()
        .find(|leaf| leaf.identity == b"bob@view.test")
        .unwrap();
    assert_eq!(view.own_leaf, bob_leaf.index, "Bob's own leaf is his");
    let (not_before, not_after) = bob_leaf
        .lifetime
        .expect("a leaf added from a KeyPackage carries its lifetime");
    assert!(not_before < not_after);
    assert_eq!(
        mimi_group_view(&alice_state).unwrap().epoch,
        view.epoch,
        "both members see one epoch"
    );
}

#[test]
fn a_key_package_view_shows_its_suite_lifetime_and_capabilities() {
    let now = now_secs();
    let (_, key_package, _) = mimi_generate_identity("dan@view.test".to_string(), now).unwrap();
    let view = mimi_key_package_view(&key_package).unwrap();
    assert_eq!(view.cipher_suite, 0x0001);
    assert!(view.not_before <= now as u64 && (now as u64) < view.not_after);
    assert!(
        view.capability_credentials.contains(&1),
        "basic credentials"
    );
    assert!(!view.last_resort);
}

#[cfg(feature = "mimi-app-data")]
#[test]
fn a_last_resort_key_package_view_says_so() {
    let now = now_secs();
    let (_, _, bundle) =
        crate::mimi::app_data::mimi_generate_identity_app_data("erin@view.test".to_string(), now)
            .unwrap();
    let (_, added) = crate::mimi::app_data::mimi_add_key_packages(bundle, 1, true, now).unwrap();
    let marks: Vec<bool> = added
        .iter()
        .map(|key_package| mimi_key_package_view(key_package).unwrap().last_resort)
        .collect();
    assert_eq!(marks.iter().filter(|&&mark| mark).count(), 1, "{marks:?}");
}

#[test]
fn a_commit_summary_names_the_epoch_committer_and_proposals() {
    let (alice_state, alice, bob_state, bob, carol_kp) = two_member_group();
    let alice_leaf = mimi_group_view(&alice_state).unwrap().own_leaf;
    let roster = vec![0x81, 0x83, 0x02];
    let (_, _, commit) =
        mimi_add_member_commit_appsync(alice_state, alice, carol_kp, roster).unwrap();
    let (bob_state, _, _, summary) =
        mimi_process_commit_summarized(bob_state, bob, commit, crate::mls::JoinLifetimes::Verify)
            .unwrap();
    assert_eq!(summary.epoch, 2);
    assert_eq!(summary.epoch, mimi_group_view(&bob_state).unwrap().epoch);
    assert_eq!(summary.committer_leaf, alice_leaf);
    assert!(
        summary.proposal_types.contains(&0x0001),
        "the Add: {:?}",
        summary.proposal_types
    );
    assert!(
        summary
            .proposal_types
            .contains(&MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE),
        "the participant list change: {:?}",
        summary.proposal_types
    );
}

#[test]
fn no_view_carries_a_secret_or_a_key() {
    let (_, _, bob_state, _, carol_kp) = two_member_group();
    let view = mimi_group_view(&bob_state).unwrap();
    let key_package = mimi_key_package_view(&carol_kp).unwrap();
    // Every byte a view holds, laid end to end per field so a key could not hide across two fields.
    let mut fields: Vec<Vec<u8>> = vec![view.group_id.clone()];
    fields.extend(view.leaves.iter().map(|leaf| leaf.identity.clone()));
    let numbers: Vec<u8> = view
        .context_extension_types
        .iter()
        .chain(&view.components)
        .chain(&key_package.extension_types)
        .chain(&key_package.capability_extensions)
        .chain(&key_package.capability_proposals)
        .chain(&key_package.capability_credentials)
        .flat_map(|value| value.to_be_bytes())
        .collect();
    fields.push(numbers);
    let printed = format!("{view:?}{key_package:?}").into_bytes();
    for key in keys_of(&bob_state) {
        for field in &fields {
            assert!(
                !contains(field, &key),
                "PLANT-VIEW-NO-KEY: a view field holds a member's secret or key"
            );
        }
        assert!(
            !contains(&printed, &key),
            "the printed view holds a key's bytes"
        );
    }
}

#[test]
fn views_refuse_what_they_cannot_read() {
    assert!(mimi_group_view(b"not a group state").is_err());
    assert!(mimi_group_view(br#"{"group_id":[1],"storage_map":[]}"#).is_err());
    let now = now_secs();
    let (_, key_package, _) = mimi_generate_identity("fay@view.test".to_string(), now).unwrap();
    assert!(mimi_key_package_view(&key_package[..key_package.len() - 1]).is_err());
    let mut trailing = key_package.clone();
    trailing.push(0);
    assert!(mimi_key_package_view(&trailing).is_err());
    let mut forged = key_package;
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert!(
        mimi_key_package_view(&forged).is_err(),
        "a KeyPackage whose signature fails"
    );
}
