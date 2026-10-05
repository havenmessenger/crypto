//! Pending commits: staged by every outbound generator, confirmed only against an acceptance of the
//! exact commit, abandoned to an installable predecessor-epoch state, and durable across restarts.

#![allow(deprecated)] // the joining side uses the non-atomic Welcome helper the mimi suite uses

use std::collections::BTreeSet;

use super::*;
use crate::identity::generate_identity;
use crate::mimi::{
    mimi_accept_external_remove_proposal_pending, mimi_add_member, mimi_add_member_commit_appsync,
    mimi_add_member_commit_appsync_pending, mimi_add_member_commit_pending,
    mimi_add_member_pending, mimi_add_members_bulk_commit_appsync_pending, mimi_create_group,
    mimi_generate_identity, mimi_process_welcome_non_atomic,
    mimi_remove_member_commit_appsync_pending, mimi_remove_member_commit_by_leaf_index_pending,
    mimi_remove_member_commit_pending, mls_process_commit_appsync,
};
use crate::mls::groups::{
    add_member, add_member_pending, add_members_bulk_pending, create_group, decrypt_message,
    encrypt_message, list_members_with_indices, mls_process_commit, process_welcome,
    remove_member_by_credential_pending, remove_member_by_leaf_index_pending,
};

const SUBMISSION: &[u8] = b"submission-1";

fn now() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    i64::try_from(secs).expect("a current time fits i64")
}

/// A MIMI group: alice made it, bob joined through a Welcome. Returns alice's state, both bundles and
/// bob's state.
struct Mimi {
    alice: Vec<u8>,
    alice_state: Vec<u8>,
    bob: Vec<u8>,
    bob_state: Vec<u8>,
}

fn mimi_pair(tag: &str) -> Mimi {
    let t = now();
    let (_, _, alice) = mimi_generate_identity(format!("alice-{tag}@as.test"), t).unwrap();
    let (_, bob_kp, bob) = mimi_generate_identity(format!("bob-{tag}@as.test"), t).unwrap();
    let state = mimi_create_group(format!("pending-{tag}"), alice.clone()).unwrap();
    let (alice_state, welcome) = mimi_add_member(state, alice.clone(), bob_kp).unwrap();
    let (bob_state, _) =
        mimi_process_welcome_non_atomic(welcome, bob.clone(), Vec::new(), String::new()).unwrap();
    Mimi {
        alice,
        alice_state,
        bob,
        bob_state,
    }
}

fn mimi_kp(name: &str) -> (Vec<u8>, Vec<u8>) {
    let (_, kp, bundle) = mimi_generate_identity(format!("{name}@as.test"), now()).unwrap();
    (kp, bundle)
}

fn accept(pending: &PendingCommit) -> CommitAcceptance {
    CommitAcceptance::new(
        pending.group_id(),
        pending.predecessor_epoch(),
        pending.commit(),
        SUBMISSION,
    )
}

fn confirm(mut pending: PendingCommit, canonical: &[u8]) -> Vec<u8> {
    pending.bind_submission(SUBMISSION).unwrap();
    let acceptance = accept(&pending);
    pending
        .confirm(canonical, &acceptance)
        .expect("acceptance of this exact commit confirms")
        .into_bytes()
        .to_vec()
}

fn format_of(pending: &PendingCommit) -> String {
    let value: serde_json::Value = serde_json::from_slice(&pending.to_bytes().unwrap()).unwrap();
    value["format"].as_str().unwrap().to_owned()
}

fn storage_set(state: &[u8]) -> BTreeSet<(Vec<u8>, Vec<u8>)> {
    let state: GroupState = serde_json::from_slice(state).unwrap();
    state.storage_map.iter().cloned().collect()
}

fn signature_keys(state: &[u8]) -> BTreeSet<String> {
    list_members_with_indices(state.to_vec())
        .unwrap()
        .into_iter()
        .map(|m| m.signature_key)
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)] // one fixture per generator, listed side by side so none is missed
fn every_generator_stages_and_leaves_the_canonical_state_untouched() {
    let m = mimi_pair("all");
    let (carol_kp, _) = mimi_kp("carol-all");
    let (dave_kp, _) = mimi_kp("dave-all");
    let bob_leaf = list_members_with_indices(m.alice_state.clone())
        .unwrap()
        .into_iter()
        .find(|member| member.credential_identity == b"bob-all@as.test")
        .unwrap();

    let t = now();
    let (_, _, native_alice) = generate_identity("alice-native-all".into(), t).unwrap();
    let (_, native_bob_kp, _) = generate_identity("bob-native-all".into(), t).unwrap();
    let (_, native_carol_kp, _) = generate_identity("carol-native-all".into(), t).unwrap();
    let native = create_group("native-all".into(), native_alice.clone()).unwrap();
    let (native, _, _) = add_member(native, native_alice.clone(), native_bob_kp).unwrap();
    let native_bob_leaf = list_members_with_indices(native.clone())
        .unwrap()
        .into_iter()
        .find(|member| member.credential_identity == b"bob-native-all")
        .unwrap();

    let (s, a) = (&m.alice_state, &m.alice);
    let pendings: Vec<(&str, PendingCommit, &Vec<u8>)> = vec![
        (
            "add_member",
            add_member_pending(
                native.clone(),
                native_alice.clone(),
                native_carol_kp.clone(),
            )
            .unwrap(),
            &native,
        ),
        (
            "add_members_bulk",
            add_members_bulk_pending(native.clone(), native_alice.clone(), vec![native_carol_kp])
                .unwrap(),
            &native,
        ),
        (
            "remove_member_by_credential",
            remove_member_by_credential_pending(
                native.clone(),
                native_alice.clone(),
                "bob-native-all".into(),
            )
            .unwrap(),
            &native,
        ),
        (
            "remove_member_by_leaf_index",
            remove_member_by_leaf_index_pending(
                native.clone(),
                native_alice,
                native_bob_leaf.leaf_index,
                native_bob_leaf.signature_key,
            )
            .unwrap(),
            &native,
        ),
        (
            "mimi_add_member",
            mimi_add_member_pending(s.clone(), a.clone(), carol_kp.clone()).unwrap(),
            s,
        ),
        (
            "mimi_add_member_commit",
            mimi_add_member_commit_pending(s.clone(), a.clone(), carol_kp.clone()).unwrap(),
            s,
        ),
        (
            "mimi_remove_member_commit",
            mimi_remove_member_commit_pending(s.clone(), a.clone(), "bob-all@as.test".into())
                .unwrap(),
            s,
        ),
        (
            "mimi_remove_member_commit_by_leaf_index",
            mimi_remove_member_commit_by_leaf_index_pending(
                s.clone(),
                a.clone(),
                bob_leaf.leaf_index,
                bob_leaf.signature_key,
            )
            .unwrap(),
            s,
        ),
        (
            "mimi_add_member_commit_appsync",
            mimi_add_member_commit_appsync_pending(s.clone(), a.clone(), carol_kp.clone(), vec![1])
                .unwrap(),
            s,
        ),
        (
            "mimi_add_members_bulk_commit_appsync",
            mimi_add_members_bulk_commit_appsync_pending(
                s.clone(),
                a.clone(),
                vec![carol_kp, dave_kp],
                vec![2],
            )
            .unwrap(),
            s,
        ),
        (
            "mimi_remove_member_commit_appsync",
            mimi_remove_member_commit_appsync_pending(
                s.clone(),
                a.clone(),
                "bob-all@as.test".into(),
                vec![3],
            )
            .unwrap(),
            s,
        ),
    ];
    for (name, pending, canonical) in &pendings {
        assert_eq!(format_of(pending), STAGED_FORMAT, "{name} writes staged/1");
        assert!(
            pending.applies_to(canonical).unwrap(),
            "{name} leaves its input the canonical predecessor"
        );
        assert!(!pending.is_installed_in(canonical).unwrap(), "{name}");
        assert_eq!(pending.summary().to_epoch, pending.predecessor_epoch() + 1);
    }
    // The twelfth generator, external Remove acceptance, has its own round trip below.
    assert_eq!(pendings.len(), 11);
    for (_, pending, canonical) in pendings {
        let _ = confirm(pending, canonical);
    }
}

#[test]
fn a_confirmed_appsync_add_reaches_the_existing_member_and_the_new_one() {
    let m = mimi_pair("confirm");
    let (carol_kp, carol) = mimi_kp("carol-confirm");
    let pending = mimi_add_members_bulk_commit_appsync_pending(
        m.alice_state.clone(),
        m.alice.clone(),
        vec![carol_kp],
        vec![0x81, 0x01],
    )
    .unwrap();
    // Persisted before the first send, read back after a restart.
    let pending = PendingCommit::from_bytes(&pending.to_bytes().unwrap()).unwrap();
    let commit = pending.commit().to_vec();
    let welcome = pending.welcome().unwrap().to_vec();
    let summary = pending.summary().clone();

    let alice_state = confirm(pending, &m.alice_state);
    let (bob_state, roster, _) =
        mls_process_commit_appsync(m.bob_state, m.bob.clone(), commit).unwrap();
    assert_eq!(roster, vec![0x81, 0x01]);
    let prepared =
        crate::mimi::prepare_welcome_retirement(welcome, carol.clone(), Vec::new(), String::new())
            .unwrap();
    let (carol_state, _) = crate::mimi::complete_welcome(prepared).unwrap();

    let (_, ct) = encrypt_message(alice_state.clone(), m.alice, b"after".to_vec()).unwrap();
    let (_, pt, _) = decrypt_message(bob_state, m.bob, ct.clone()).unwrap();
    assert_eq!(pt, b"after");
    let (_, pt, _) = decrypt_message(carol_state, carol, ct).unwrap();
    assert_eq!(pt, b"after");

    assert_eq!(
        summary.members_after,
        list_members_with_indices(alice_state).unwrap()
    );
    assert_eq!(summary.added.len(), 1);
    assert_eq!(
        summary.added[0].credential_identity,
        b"carol-confirm@as.test"
    );
    assert!(summary.removed.is_empty());
}

#[test]
fn a_confirmed_native_add_keeps_every_member_in_sync() {
    let t = now();
    let (_, _, alice) = generate_identity("alice-native".into(), t).unwrap();
    let (_, bob_kp, bob) = generate_identity("bob-native".into(), t).unwrap();
    let (_, carol_kp, carol) = generate_identity("carol-native".into(), t).unwrap();
    let state = create_group("native-confirm".into(), alice.clone()).unwrap();
    let (alice_state, welcome, _) = add_member(state, alice.clone(), bob_kp).unwrap();
    let (bob_state, _) = process_welcome(welcome, bob.clone()).unwrap();

    let pending = add_member_pending(alice_state.clone(), alice.clone(), carol_kp).unwrap();
    let pending = PendingCommit::from_bytes(&pending.to_bytes().unwrap()).unwrap();
    let (commit, welcome) = (
        pending.commit().to_vec(),
        pending.welcome().unwrap().to_vec(),
    );
    let alice_state = confirm(pending, &alice_state);
    let (bob_state, _) = mls_process_commit(bob_state, bob.clone(), commit).unwrap();
    let (carol_state, _) = process_welcome(welcome, carol.clone()).unwrap();

    let (_, ct) = encrypt_message(alice_state, alice, b"native".to_vec()).unwrap();
    let (_, pt, _) = decrypt_message(bob_state, bob, ct.clone()).unwrap();
    assert_eq!(pt, b"native");
    let (_, pt, _) = decrypt_message(carol_state, carol, ct).unwrap();
    assert_eq!(pt, b"native");
}

#[test]
fn a_hub_signed_external_remove_confirms_and_the_remaining_member_follows() {
    let t = now();
    let (_, _, alice) = generate_identity("alice-ext@w3.test".into(), t).unwrap();
    let (_, bob_kp, _) = generate_identity("bob-ext@w3.test".into(), t).unwrap();
    let (_, carol_kp, carol) = generate_identity("carol-ext@w3.test".into(), t).unwrap();
    let (_, _, hub) = generate_identity("hub-ext@w3.test".into(), t).unwrap();
    let hub_identity: IdentityBundle = serde_json::from_slice(&hub).unwrap();
    let hub_signer = MlsSigner {
        key: Zeroizing::new(hub_identity.private_key.clone()),
        scheme: hub_identity.signature_scheme,
    };
    let hub_key = hub_identity.public_key_bytes.clone();

    let state = crate::mimi::mimi_create_group_with_external_senders(
        "pending-ext".into(),
        alice.clone(),
        hub_key.clone(),
        "hub-ext@w3.test".into(),
    )
    .unwrap();
    let (state, _) = mimi_add_member(state, alice.clone(), bob_kp).unwrap();
    let (state, carol_welcome, _) =
        crate::mimi::mimi_add_member_commit(state, alice.clone(), carol_kp).unwrap();
    let (carol_state, _) = mimi_process_welcome_non_atomic(
        carol_welcome,
        carol.clone(),
        hub_key,
        "hub-ext@w3.test".into(),
    )
    .unwrap();

    let (provider, group) = load_group(&serde_json::from_slice(&state).unwrap()).unwrap();
    let remove = ExternalProposal::new_remove::<OpenMlsRustCrypto>(
        LeafNodeIndex::new(1),
        group.group_id().clone(),
        group.epoch(),
        &hub_signer,
        SenderExtensionIndex::new(0),
    )
    .unwrap()
    .tls_serialize_detached()
    .unwrap();
    drop((provider, group));

    let pending =
        mimi_accept_external_remove_proposal_pending(state.clone(), alice, remove).unwrap();
    assert_eq!(format_of(&pending), STAGED_FORMAT);
    assert!(pending.applies_to(&state).unwrap());
    let removed = pending.summary().removed.clone();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].credential_identity, b"bob-ext@w3.test");
    let commit = pending.commit().to_vec();
    let after = confirm(pending, &state);
    assert!(!signature_keys(&after).contains(&removed[0].signature_key));
    mls_process_commit(carol_state, carol, commit).expect("carol follows the hub's Remove");
}

#[test]
fn each_mismatched_acceptance_is_refused_and_hands_the_pending_back_intact() {
    let m = mimi_pair("refuse");
    let (carol_kp, _) = mimi_kp("carol-refuse");
    let mut pending = mimi_add_member_commit_appsync_pending(
        m.alice_state.clone(),
        m.alice.clone(),
        carol_kp,
        vec![7],
    )
    .unwrap();
    let digest = pending.commit_digest();
    let (group, epoch, commit) = (
        pending.group_id().to_vec(),
        pending.predecessor_epoch(),
        pending.commit().to_vec(),
    );

    let refuse = |pending: PendingCommit, acceptance: CommitAcceptance, why: PendingCommitError| {
        let refused = pending
            .confirm(&m.alice_state, &acceptance)
            .expect_err("a mismatched acceptance confirms nothing");
        assert_eq!(refused.reason, why);
        assert_eq!(
            refused.pending.commit_digest(),
            digest,
            "handed back intact"
        );
        *refused.pending
    };

    pending = refuse(
        pending,
        CommitAcceptance::new(&group, epoch, &commit, SUBMISSION),
        PendingCommitError::SubmissionUnbound,
    );
    pending.bind_submission(SUBMISSION).unwrap();
    pending = refuse(
        pending,
        CommitAcceptance::new(b"another-group", epoch, &commit, SUBMISSION),
        PendingCommitError::WrongGroup,
    );
    pending = refuse(
        pending,
        CommitAcceptance::new(&group, epoch + 1, &commit, SUBMISSION),
        PendingCommitError::WrongEpoch,
    );
    pending = refuse(
        pending,
        CommitAcceptance::new(&group, epoch, b"some other commit", SUBMISSION),
        PendingCommitError::CommitMismatch,
    );
    pending = refuse(
        pending,
        CommitAcceptance::new(&group, epoch, &commit, b"a retry under another identity"),
        PendingCommitError::SubmissionMismatch,
    );
    // Still confirmable after every refusal.
    let after = pending
        .confirm(
            &m.alice_state,
            &CommitAcceptance::new(&group, epoch, &commit, SUBMISSION),
        )
        .unwrap();
    assert_eq!(
        signature_keys(&after.into_bytes()).len(),
        3,
        "carol joined only through the matching acceptance"
    );
}

#[test]
fn a_pending_commit_is_refused_once_the_canonical_state_has_moved_on() {
    let m = mimi_pair("moved");
    let (carol_kp, _) = mimi_kp("carol-moved");
    let (dave_kp, _) = mimi_kp("dave-moved");
    let mut pending =
        mimi_add_member_commit_pending(m.alice_state.clone(), m.alice.clone(), carol_kp).unwrap();
    pending.bind_submission(SUBMISSION).unwrap();
    // The hub sequenced bob's commit instead; alice's canonical state processes it.
    let (_, _, bob_commit) =
        crate::mimi::mimi_add_member_commit(m.bob_state, m.bob, dave_kp).unwrap();
    let (moved, _) = mls_process_commit(m.alice_state.clone(), m.alice, bob_commit).unwrap();
    assert!(!pending.applies_to(&moved).unwrap());
    let acceptance = accept(&pending);
    let refused = pending.confirm(&moved, &acceptance).unwrap_err();
    assert_eq!(refused.reason, PendingCommitError::PredecessorMoved);
}

#[test]
fn a_submission_identity_binds_once() {
    let m = mimi_pair("bind");
    let (carol_kp, _) = mimi_kp("carol-bind");
    let mut pending = mimi_add_member_commit_pending(m.alice_state, m.alice, carol_kp).unwrap();
    pending.bind_submission(b"first").unwrap();
    pending.bind_submission(b"first").unwrap();
    assert_eq!(
        pending.bind_submission(b"second"),
        Err(PendingCommitError::SubmissionMismatch)
    );
    let pending = PendingCommit::from_bytes(&pending.to_bytes().unwrap()).unwrap();
    assert_eq!(
        pending.submission(),
        Some(&b"first"[..]),
        "survives a restart"
    );
}

#[test]
fn a_confirmed_successor_is_recognised_as_installed() {
    let m = mimi_pair("installed");
    let (carol_kp, _) = mimi_kp("carol-installed");
    let mut pending =
        mimi_add_member_commit_pending(m.alice_state.clone(), m.alice, carol_kp).unwrap();
    pending.bind_submission(SUBMISSION).unwrap();
    let durable = pending.to_bytes().unwrap();
    let acceptance = accept(&pending);
    let installed = pending
        .confirm(&m.alice_state, &acceptance)
        .unwrap()
        .into_bytes();
    // A restart between installing the successor and clearing the pending row.
    let again = PendingCommit::from_bytes(&durable).unwrap();
    assert!(again.is_installed_in(&installed).unwrap());
    assert!(!again.applies_to(&installed).unwrap());
    let refused = again.confirm(&installed, &acceptance).unwrap_err();
    assert_eq!(refused.reason, PendingCommitError::PredecessorMoved);
}

#[test]
fn abandoning_a_plaintext_lane_commit_returns_the_predecessor_and_withdraws_its_roster_proposal() {
    let m = mimi_pair("abandon");
    let (carol_kp, _) = mimi_kp("carol-abandon");
    let pending = mimi_add_member_commit_appsync_pending(
        m.alice_state.clone(),
        m.alice.clone(),
        carol_kp,
        vec![0xAA],
    )
    .unwrap();
    let abandoned = pending.abandon().unwrap().into_bytes().to_vec();
    assert_eq!(
        abandoned, m.alice_state,
        "a PublicMessage commit consumed nothing: abandoning returns the predecessor, byte for byte"
    );
}

#[test]
fn every_plaintext_lane_generator_abandons_to_the_exact_predecessor() {
    let m = mimi_pair("exact");
    let (carol_kp, _) = mimi_kp("carol-exact");
    let bob_leaf = list_members_with_indices(m.alice_state.clone())
        .unwrap()
        .into_iter()
        .find(|member| member.credential_identity == b"bob-exact@as.test")
        .unwrap();
    let (s, a) = (&m.alice_state, &m.alice);
    for pending in [
        mimi_add_member_pending(s.clone(), a.clone(), carol_kp.clone()).unwrap(),
        mimi_add_member_commit_pending(s.clone(), a.clone(), carol_kp.clone()).unwrap(),
        mimi_remove_member_commit_pending(s.clone(), a.clone(), "bob-exact@as.test".into())
            .unwrap(),
        mimi_remove_member_commit_by_leaf_index_pending(
            s.clone(),
            a.clone(),
            bob_leaf.leaf_index,
            bob_leaf.signature_key,
        )
        .unwrap(),
        mimi_add_members_bulk_commit_appsync_pending(s.clone(), a.clone(), vec![carol_kp], vec![4])
            .unwrap(),
        mimi_remove_member_commit_appsync_pending(
            s.clone(),
            a.clone(),
            "bob-exact@as.test".into(),
            vec![5],
        )
        .unwrap(),
    ] {
        let durable = PendingCommit::from_bytes(&pending.to_bytes().unwrap()).unwrap();
        assert_eq!(
            pending.abandon().unwrap().into_bytes().as_slice(),
            s.as_slice()
        );
        assert_eq!(
            durable.abandon().unwrap().into_bytes().as_slice(),
            s.as_slice(),
            "and after a restart"
        );
    }
}

#[test]
fn one_pending_commit_always_confirms_to_the_same_bytes() {
    let m = mimi_pair("stable");
    let (carol_kp, _) = mimi_kp("carol-stable");
    let mut pending =
        mimi_add_member_commit_pending(m.alice_state.clone(), m.alice, carol_kp).unwrap();
    pending.bind_submission(SUBMISSION).unwrap();
    let durable = pending.to_bytes().unwrap();
    let first = confirm(PendingCommit::from_bytes(&durable).unwrap(), &m.alice_state);
    let second = confirm(PendingCommit::from_bytes(&durable).unwrap(), &m.alice_state);
    assert_eq!(first, second);
}

#[test]
fn an_abandoned_roster_proposal_does_not_ride_the_next_commit() {
    let m = mimi_pair("stale");
    let (carol_kp, _) = mimi_kp("carol-stale");
    let (dave_kp, _) = mimi_kp("dave-stale");
    let pending = mimi_add_member_commit_appsync_pending(
        m.alice_state.clone(),
        m.alice.clone(),
        carol_kp,
        vec![0xAA],
    )
    .unwrap();
    let abandoned = pending.abandon().unwrap().into_bytes().to_vec();
    let (_, _, commit) =
        mimi_add_member_commit_appsync(abandoned, m.alice, dave_kp, vec![0xBB]).unwrap();
    let (_, roster, _) = mls_process_commit_appsync(m.bob_state, m.bob, commit).unwrap();
    assert_eq!(
        roster,
        vec![0xBB],
        "only the new roster proposal is carried"
    );
}

#[test]
fn abandoning_a_ciphertext_lane_commit_keeps_the_consumed_handshake_ratchet() {
    let t = now();
    let (_, _, alice) = generate_identity("alice-cipher".into(), t).unwrap();
    let (_, bob_kp, bob) = generate_identity("bob-cipher".into(), t).unwrap();
    let (_, carol_kp, _) = generate_identity("carol-cipher".into(), t).unwrap();
    let (_, dave_kp, _) = generate_identity("dave-cipher".into(), t).unwrap();
    let state = create_group("native-abandon".into(), alice.clone()).unwrap();
    let (alice_state, welcome, _) = add_member(state, alice.clone(), bob_kp).unwrap();
    let (bob_state, _) = process_welcome(welcome, bob.clone()).unwrap();

    let pending = add_member_pending(alice_state.clone(), alice.clone(), carol_kp).unwrap();
    let abandoned = pending.abandon().unwrap().into_bytes().to_vec();
    assert_ne!(
        storage_set(&abandoned),
        storage_set(&alice_state),
        "the encrypted commit consumed a handshake generation the abandoned state must keep"
    );
    let next = add_member_pending(abandoned.clone(), alice, dave_kp).unwrap();
    assert!(
        next.applies_to(&alice_state).unwrap(),
        "still the predecessor epoch"
    );
    let commit = next.commit().to_vec();
    let _ = confirm(next, &abandoned);
    mls_process_commit(bob_state, bob, commit).expect("the next commit is processable");
}

#[test]
fn the_durable_form_is_not_a_json_byte_array() {
    let m = mimi_pair("size");
    let (carol_kp, _) = mimi_kp("carol-size");
    let pending =
        mimi_add_member_commit_appsync_pending(m.alice_state, m.alice, carol_kp, vec![1]).unwrap();
    let durable = pending.to_bytes().unwrap();
    let Body::Staged { storage, .. } = &pending.body else {
        unreachable!("a generator always stages");
    };
    let raw: usize = storage
        .storage_map
        .iter()
        .map(|(k, v)| k.len() + v.len())
        .sum::<usize>()
        + pending.commit().len()
        + pending.welcome().map_or(0, <[u8]>::len);
    assert!(
        durable.len() * 10 < raw * 15,
        "{} encoded bytes for {raw} raw: base64 is 4/3, a JSON number array is about 3.5x",
        durable.len()
    );
}

#[test]
fn a_durable_record_that_does_not_agree_with_itself_is_refused_by_name() {
    let m = mimi_pair("tamper");
    let (carol_kp, _) = mimi_kp("carol-tamper");
    let pending = mimi_add_member_commit_pending(m.alice_state.clone(), m.alice, carol_kp).unwrap();
    let durable: serde_json::Value = serde_json::from_slice(&pending.to_bytes().unwrap()).unwrap();
    let edited = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut value = durable.clone();
        edit(&mut value);
        PendingCommit::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap_err()
    };
    assert_eq!(
        edited(&|v| v["format"] = "pending-commit/staged/9".into()),
        PendingCommitError::UnsupportedFormat
    );
    assert!(matches!(
        edited(&|v| v["predecessor_epoch"] = 7.into()),
        PendingCommitError::Malformed(_)
    ));
    assert!(matches!(
        edited(&|v| {
            v["predecessor_epoch"] = u64::MAX.into();
            v["summary"]["from_epoch"] = u64::MAX.into();
        }),
        PendingCommitError::Malformed(_)
    ));
    // The canonical predecessor's storage in place of the staged storage: no staged commit inside.
    let canonical: GroupState = serde_json::from_slice(&m.alice_state).unwrap();
    let entries: Vec<serde_json::Value> = canonical
        .storage_map
        .iter()
        .map(|(k, v)| serde_json::json!([BASE64.encode(k), BASE64.encode(v)]))
        .collect();
    assert_eq!(
        edited(&|v| v["state"] = entries.clone().into()),
        PendingCommitError::Malformed("no staged commit")
    );
    assert!(matches!(
        PendingCommit::from_bytes(b"[1,2,3]").unwrap_err(),
        PendingCommitError::Malformed(_)
    ));
}

#[test]
fn a_legacy_merged_row_recovers_confirms_and_abandons_to_its_predecessor() {
    let m = mimi_pair("legacy");
    let (carol_kp, _) = mimi_kp("carol-legacy");
    let (successor, welcome, commit) =
        crate::mimi::mimi_add_member_commit(m.alice_state.clone(), m.alice.clone(), carol_kp)
            .unwrap();
    let mut pending =
        PendingCommit::from_legacy_merged(&m.alice_state, &successor, &commit, Some(&welcome))
            .unwrap();
    assert_eq!(format_of(&pending), LEGACY_FORMAT);
    assert!(pending.applies_to(&m.alice_state).unwrap());
    assert!(pending.is_installed_in(&successor).unwrap());
    assert_eq!(pending.summary().added.len(), 1);
    pending.bind_submission(SUBMISSION).unwrap();
    let pending = PendingCommit::from_bytes(&pending.to_bytes().unwrap()).unwrap();
    assert_eq!(pending.welcome(), Some(welcome.as_slice()));

    let abandoned = PendingCommit::from_bytes(&pending.to_bytes().unwrap())
        .unwrap()
        .abandon()
        .unwrap()
        .into_bytes();
    assert_eq!(abandoned.as_slice(), m.alice_state.as_slice());

    let acceptance = accept(&pending);
    let confirmed = pending
        .confirm(&m.alice_state, &acceptance)
        .unwrap()
        .into_bytes();
    assert_eq!(confirmed.as_slice(), successor.as_slice());
    mls_process_commit(m.bob_state, m.bob, commit).unwrap();
}

#[test]
fn a_legacy_row_whose_parts_do_not_belong_together_is_refused() {
    let m = mimi_pair("legacy-bad");
    let other = mimi_pair("legacy-other");
    let (carol_kp, _) = mimi_kp("carol-legacy-bad");
    let (dave_kp, _) = mimi_kp("dave-legacy-bad");
    let (successor, _, commit) =
        crate::mimi::mimi_add_member_commit(m.alice_state.clone(), m.alice.clone(), carol_kp)
            .unwrap();
    let (two_ahead, _, _) =
        crate::mimi::mimi_add_member_commit(successor.clone(), m.alice.clone(), dave_kp).unwrap();
    let (_, application) =
        encrypt_message(m.alice_state.clone(), m.alice.clone(), b"x".to_vec()).unwrap();
    let (other_successor, _, other_commit) = crate::mimi::mimi_add_member_commit(
        other.alice_state.clone(),
        other.alice,
        mimi_kp("erin-legacy-bad").0,
    )
    .unwrap();

    let refused = |pred: &[u8], succ: &[u8], commit: &[u8]| match PendingCommit::from_legacy_merged(
        pred, succ, commit, None,
    )
    .unwrap_err()
    {
        PendingCommitError::LegacyBindingInvalid(why) => why,
        other => unreachable!("expected a named legacy refusal, got {other:?}"),
    };
    assert_eq!(
        refused(&m.alice_state, &other_successor, &commit),
        "states are different groups"
    );
    assert_eq!(
        refused(&m.alice_state, &two_ahead, &commit),
        "successor is not the next epoch"
    );
    assert_eq!(
        refused(&m.alice_state, &successor, &other_commit),
        "commit is framed in another group or epoch"
    );
    assert_eq!(
        refused(&m.alice_state, &successor, &application),
        "message is not a commit"
    );
}

/// `state` as written before encoding was sorted: the same entries, in another order.
fn unsorted(state: &[u8]) -> Vec<u8> {
    let parsed: GroupState = serde_json::from_slice(state).unwrap();
    let mut entries = parsed.storage_map.clone();
    entries.reverse();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "group_id": parsed.group_id.clone(),
        "storage_map": entries,
    }))
    .unwrap();
    assert_ne!(bytes, state, "the fixture really is in another order");
    bytes
}

/// `state` in a form no encoder of this crate writes: pretty-printed, entries reversed.
fn noncanonical(state: &[u8]) -> Vec<u8> {
    let parsed: GroupState = serde_json::from_slice(state).unwrap();
    let mut entries = parsed.storage_map.clone();
    entries.reverse();
    serde_json::to_vec_pretty(&serde_json::json!({
        "group_id": parsed.group_id.clone(),
        "storage_map": entries,
    }))
    .unwrap()
}

#[test]
fn an_unsorted_predecessor_abandons_to_its_original_bytes() {
    let m = mimi_pair("r11");
    let (carol_kp, _) = mimi_kp("carol-r11");
    let bob_leaf = list_members_with_indices(m.alice_state.clone())
        .unwrap()
        .into_iter()
        .find(|member| member.credential_identity == b"bob-r11@as.test")
        .unwrap();
    for original in [unsorted(&m.alice_state), noncanonical(&m.alice_state)] {
        let (s, a) = (&original, &m.alice);
        for pending in [
            mimi_add_member_pending(s.clone(), a.clone(), carol_kp.clone()).unwrap(),
            mimi_add_member_commit_pending(s.clone(), a.clone(), carol_kp.clone()).unwrap(),
            mimi_remove_member_commit_pending(s.clone(), a.clone(), "bob-r11@as.test".into())
                .unwrap(),
            mimi_remove_member_commit_by_leaf_index_pending(
                s.clone(),
                a.clone(),
                bob_leaf.leaf_index,
                bob_leaf.signature_key.clone(),
            )
            .unwrap(),
            mimi_add_members_bulk_commit_appsync_pending(
                s.clone(),
                a.clone(),
                vec![carol_kp.clone()],
                vec![6],
            )
            .unwrap(),
            mimi_remove_member_commit_appsync_pending(
                s.clone(),
                a.clone(),
                "bob-r11@as.test".into(),
                vec![7],
            )
            .unwrap(),
        ] {
            assert!(
                pending.applies_to(&m.alice_state).unwrap(),
                "same epoch either way"
            );
            let durable = PendingCommit::from_bytes(&pending.to_bytes().unwrap()).unwrap();
            assert_eq!(
                pending.abandon().unwrap().into_bytes().as_slice(),
                s.as_slice()
            );
            assert_eq!(
                durable.abandon().unwrap().into_bytes().as_slice(),
                s.as_slice(),
                "and after a restart"
            );
        }
    }
}

#[test]
fn a_legacy_row_with_unsorted_states_returns_their_original_bytes() {
    let m = mimi_pair("legacy-r11");
    let (carol_kp, _) = mimi_kp("carol-legacy-r11");
    let (successor, welcome, commit) =
        crate::mimi::mimi_add_member_commit(m.alice_state.clone(), m.alice.clone(), carol_kp)
            .unwrap();
    let (predecessor, successor) = (unsorted(&m.alice_state), noncanonical(&successor));
    let mut pending =
        PendingCommit::from_legacy_merged(&predecessor, &successor, &commit, Some(&welcome))
            .unwrap();
    pending.bind_submission(SUBMISSION).unwrap();
    let durable = pending.to_bytes().unwrap();
    let abandoned = PendingCommit::from_bytes(&durable)
        .unwrap()
        .abandon()
        .unwrap()
        .into_bytes();
    assert_eq!(abandoned.as_slice(), predecessor.as_slice());
    let pending = PendingCommit::from_bytes(&durable).unwrap();
    let acceptance = accept(&pending);
    let confirmed = pending
        .confirm(&predecessor, &acceptance)
        .unwrap()
        .into_bytes();
    assert_eq!(confirmed.as_slice(), successor.as_slice());
}

#[test]
fn a_record_whose_original_order_was_altered_is_refused() {
    let m = mimi_pair("order");
    let (carol_kp, _) = mimi_kp("carol-order");
    let pending =
        mimi_add_member_commit_pending(unsorted(&m.alice_state), m.alice, carol_kp).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&pending.to_bytes().unwrap()).unwrap();
    let order = value["predecessor_original"]["order"]
        .as_array_mut()
        .unwrap();
    order.swap(0, 1);
    assert_eq!(
        PendingCommit::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
        PendingCommitError::Malformed("original bytes")
    );
}

#[test]
fn debug_output_names_the_commit_and_never_shows_group_secrets() {
    let m = mimi_pair("debug");
    let (carol_kp, _) = mimi_kp("carol-debug");
    let (dave_kp, _) = mimi_kp("dave-debug");
    let mut pending =
        mimi_add_member_commit_pending(m.alice_state.clone(), m.alice.clone(), carol_kp).unwrap();
    let shown = format!("{pending:?}");
    assert!(shown.starts_with("PendingCommit {"), "{shown}");
    assert!(shown.contains(&hex::encode(pending.group_id())), "{shown}");
    assert!(
        shown.contains(&hex::encode(pending.commit_digest())),
        "{shown}"
    );
    assert!(shown.contains(STAGED_FORMAT), "{shown}");
    let Body::Staged { storage, .. } = &pending.body else {
        unreachable!("a generator always stages");
    };
    assert!(!shown.contains("storage"), "{shown}");
    // Values short enough to occur by chance inside a digest (an empty list is two bytes) prove
    // nothing either way; secret material is longer.
    for (_, value) in storage.storage_map.iter().filter(|(_, v)| v.len() >= 16) {
        assert!(
            !shown.contains(&hex::encode(value)),
            "no storage value is shown"
        );
        assert!(
            !shown.contains(&BASE64.encode(value)),
            "no storage value is shown"
        );
    }
    pending.bind_submission(SUBMISSION).unwrap();
    let acceptance = accept(&pending);
    let confirmed = pending.confirm(&m.alice_state, &acceptance).unwrap();
    assert_eq!(
        format!("{confirmed:?}"),
        "ConfirmedGroupState(<group secrets>)"
    );
    let abandoned = mimi_add_member_commit_pending(m.alice_state, m.alice, dave_kp)
        .unwrap()
        .abandon()
        .unwrap();
    assert_eq!(
        format!("{abandoned:?}"),
        "AbandonedGroupState(<group secrets>)"
    );
}

#[test]
fn abandon_refuses_a_restored_state_that_still_holds_the_staged_commit() {
    let m = mimi_pair("abandon-pending");
    let (carol_kp, _) = mimi_kp("carol-abandon-pending");
    let mut pending =
        mimi_add_member_commit_pending(m.alice_state.clone(), m.alice, carol_kp).unwrap();
    // Nothing undone: the "restored" state is the staged storage, same epoch, staged commit inside.
    let Body::Staged {
        restore: Some((set, _)),
        ..
    } = &mut pending.body
    else {
        unreachable!("a plaintext-lane generator records a restore set");
    };
    set.clear();
    assert!(
        pending.applies_to(&m.alice_state).unwrap(),
        "the epoch binding alone still matches"
    );
    assert_eq!(
        pending.abandon().unwrap_err(),
        PendingCommitError::Malformed("restored state is not the predecessor")
    );
}

#[test]
fn abandon_refuses_a_restored_state_of_another_epoch() {
    let m = mimi_pair("abandon-binding");
    let (carol_kp, _) = mimi_kp("carol-abandon-binding");
    let mut pending =
        mimi_add_member_commit_pending(m.alice_state.clone(), m.alice, carol_kp).unwrap();
    // The restored state holds no staged commit; only the binding it must match differs.
    pending.predecessor_binding = [0; 32];
    assert_eq!(
        pending.abandon().unwrap_err(),
        PendingCommitError::Malformed("restored state is not the predecessor")
    );
}

/// A staged record, as JSON, with `edit` applied, read back.
fn read_edited(
    pending: &PendingCommit,
    edit: impl Fn(&mut serde_json::Value),
) -> Result<PendingCommit, PendingCommitError> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&pending.to_bytes().unwrap()).unwrap();
    edit(&mut value);
    PendingCommit::from_bytes(&serde_json::to_vec(&value).unwrap())
}

#[test]
fn a_staged_record_is_refused_when_either_its_epoch_or_its_binding_disagrees() {
    let m = mimi_pair("staged-checks");
    let (carol_kp, _) = mimi_kp("carol-staged-checks");
    let pending = mimi_add_member_commit_pending(m.alice_state, m.alice, carol_kp).unwrap();
    let epoch = pending.predecessor_epoch();
    assert_eq!(
        read_edited(&pending, |v| v["predecessor_epoch"] = (epoch + 1).into()).unwrap_err(),
        PendingCommitError::Malformed("predecessor binding"),
        "the epoch alone"
    );
    assert_eq!(
        read_edited(&pending, |v| v["predecessor_binding"] =
            "00".repeat(32).into())
        .unwrap_err(),
        PendingCommitError::Malformed("predecessor binding"),
        "the binding alone"
    );
}

#[test]
fn a_restore_set_that_leaves_the_staged_commit_in_place_is_refused() {
    let m = mimi_pair("restore-pending");
    let (carol_kp, _) = mimi_kp("carol-restore-pending");
    let pending = mimi_add_member_commit_pending(m.alice_state, m.alice, carol_kp).unwrap();
    assert_eq!(
        read_edited(&pending, |v| v["restore"] = serde_json::json!([])).unwrap_err(),
        PendingCommitError::Malformed("restore set")
    );
}

#[test]
fn a_restore_set_that_restores_another_epoch_is_refused() {
    let m = mimi_pair("restore-epoch");
    let (carol_kp, _) = mimi_kp("carol-restore-epoch");
    let (dave_kp, _) = mimi_kp("dave-restore-epoch");
    let earlier = m.alice_state.clone();
    let (later, _, _) =
        crate::mimi::mimi_add_member_commit(earlier.clone(), m.alice.clone(), carol_kp).unwrap();
    let pending = mimi_add_member_commit_pending(later, m.alice, dave_kp).unwrap();
    // Every staged entry is "restored" to the earlier epoch's value: a loadable group with no staged
    // commit, at the wrong epoch.
    let earlier: GroupState = serde_json::from_slice(&earlier).unwrap();
    let old: std::collections::HashMap<&Vec<u8>, &Vec<u8>> =
        earlier.storage_map.iter().map(|(k, v)| (k, v)).collect();
    let Body::Staged { storage, .. } = &pending.body else {
        unreachable!("a generator always stages");
    };
    let restore: Vec<serde_json::Value> = storage
        .storage_map
        .iter()
        .map(|(k, _)| serde_json::json!([BASE64.encode(k), old.get(k).map(|v| BASE64.encode(v))]))
        .collect();
    assert_eq!(
        read_edited(&pending, |v| v["restore"] = restore.clone().into()).unwrap_err(),
        PendingCommitError::Malformed("restore set")
    );
}

#[test]
fn a_legacy_record_is_refused_when_either_binding_disagrees() {
    let m = mimi_pair("legacy-checks");
    let (carol_kp, _) = mimi_kp("carol-legacy-checks");
    let (successor, welcome, commit) =
        crate::mimi::mimi_add_member_commit(m.alice_state.clone(), m.alice, carol_kp).unwrap();
    let pending =
        PendingCommit::from_legacy_merged(&m.alice_state, &successor, &commit, Some(&welcome))
            .unwrap();
    for field in ["predecessor_binding", "successor_binding"] {
        assert_eq!(
            read_edited(&pending, |v| v[field] = "00".repeat(32).into()).unwrap_err(),
            PendingCommitError::Malformed("legacy binding"),
            "{field} alone"
        );
    }
}

#[test]
fn same_entries_needs_the_same_group_and_the_same_entries() {
    let state = |group: &[u8], entries: &[(&[u8], &[u8])]| GroupState {
        group_id: group.to_vec(),
        storage_map: entries
            .iter()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect(),
    };
    let a = state(b"g", &[(b"k1", b"v1"), (b"k2", b"v2")]);
    assert!(
        same_entries(&a, &state(b"g", &[(b"k2", b"v2"), (b"k1", b"v1")])),
        "any order"
    );
    assert!(
        !same_entries(&a, &state(b"h", &[(b"k1", b"v1"), (b"k2", b"v2")])),
        "other group"
    );
    assert!(
        !same_entries(&a, &state(b"g", &[(b"k1", b"v1")])),
        "an entry missing"
    );
    assert!(
        !same_entries(&a, &state(b"g", &[(b"k1", b"v1"), (b"k2", b"v9")])),
        "a value changed"
    );
}
