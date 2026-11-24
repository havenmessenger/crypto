use super::*;
use crate::mimi::{complete_welcome, prepare_welcome_retirement};
use crate::mls::CommitAcceptance;

/// The participant list's component (draft-ietf-mimi-room-policy).
const LIST: u16 = 0x0022;
const SUBMISSION: &[u8] = b"submission";

fn now_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// A stand-in for the participant list's rules: the value is the names, comma separated, each update appends one in
/// the commit's order, and a removal is allowed.
fn append(
    _: u16,
    before: Option<&[u8]>,
    changes: &[Change<'_>],
) -> anyhow::Result<Option<Vec<u8>>> {
    let mut value = before.map(<[u8]>::to_vec);
    for change in changes {
        let Change::Update(update) = change else {
            return Ok(None);
        };
        anyhow::ensure!(!update.contains(&b','), "a name has no comma");
        value = Some(match value {
            Some(list) if !list.is_empty() => [list.as_slice(), b",", update].concat(),
            _ => update.to_vec(),
        });
    }
    Ok(value)
}

/// A member whose rules differ: it appends with a semicolon.
fn append_differently(
    _: u16,
    before: Option<&[u8]>,
    changes: &[Change<'_>],
) -> anyhow::Result<Option<Vec<u8>>> {
    let mut value = before.unwrap_or_default().to_vec();
    for change in changes {
        let Change::Update(update) = change else {
            return Ok(None);
        };
        value = [value.as_slice(), b";", update].concat();
    }
    Ok(Some(value))
}

fn refuse(_: u16, _: Option<&[u8]>, _: &[Change<'_>]) -> anyhow::Result<Option<Vec<u8>>> {
    anyhow::bail!("this member's rules refuse the change")
}

fn identity(name: &str) -> (Vec<u8>, Vec<u8>) {
    let (_, key_package, bundle) =
        mimi_generate_identity_app_data(format!("mimi://hub.example/u/{name}"), now_secs())
            .unwrap();
    (key_package, bundle)
}

/// Install `pending` as the room's hub accepted it.
fn confirm(mut pending: PendingCommit, canonical: &[u8]) -> Vec<u8> {
    pending.bind_submission(SUBMISSION).unwrap();
    let acceptance = CommitAcceptance::new(
        pending.group_id(),
        pending.predecessor_epoch(),
        pending.commit(),
        SUBMISSION,
    );
    pending
        .confirm(canonical, &acceptance)
        .expect("the accepted commit installs")
        .into_bytes()
        .to_vec()
}

fn join(welcome: &[u8], bundle: Vec<u8>) -> Vec<u8> {
    let prepared = prepare_welcome_retirement(welcome.to_vec(), bundle, Vec::new(), String::new())
        .unwrap_or_else(|_| panic!("the Welcome opens"));
    complete_welcome(prepared)
        .unwrap_or_else(|_| panic!("the joiner gets in"))
        .0
}

fn list(state: &[u8]) -> Vec<u8> {
    mimi_app_data_value(state, LIST)
        .unwrap()
        .unwrap_or_default()
}

/// Alice's room with Bob added by an AppDataUpdate: Alice's state after the commit, Bob's after joining, and the commit.
fn room_with_bob() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let (alice_state, alice, bob_state, welcome, _) = room_with_bob_and_his_bundle();
    (alice_state, alice, bob_state, welcome)
}

/// [`room_with_bob`], and Bob's identity bundle.
fn room_with_bob_and_his_bundle() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let (_, alice) = identity("alice");
    let (bob_kp, bob) = identity("bob");
    let room = mimi_create_group_app_data(
        "room".into(),
        alice.clone(),
        vec![(LIST, b"alice".to_vec())],
    )
    .unwrap();
    let pending = mimi_commit_app_data_pending(
        room.clone(),
        alice.clone(),
        vec![bob_kp],
        Vec::new(),
        vec![(LIST, b"bob".to_vec())],
        &append,
        Vec::new(),
    )
    .unwrap();
    let welcome = pending.welcome().expect("an add has a Welcome").to_vec();
    let alice_state = confirm(pending, &room);
    let bob_state = join(&welcome, bob.clone());
    (alice_state, alice, bob_state, welcome, bob)
}

/// Every member computes the same list: the committer from its own update, the joiner from the Welcome, an existing
/// member from the commit. Revert check: have the committer store the update itself as the value and its own list is
/// wrong; have a receiver take the update itself as the value and it refuses the commit.
#[test]
fn every_member_holds_the_same_list_after_each_change() {
    let (alice_state, alice, bob_state, _) = room_with_bob();
    assert_eq!(
        list(&alice_state),
        b"alice,bob",
        "PLANT-APP-DATA-AGREE: the committer resolves its own update"
    );
    assert_eq!(
        list(&bob_state),
        b"alice,bob",
        "the joiner reads the list from the Welcome"
    );
    let (carol_kp, carol) = identity("carol");
    let pending = mimi_commit_app_data_pending(
        alice_state.clone(),
        alice.clone(),
        vec![carol_kp],
        Vec::new(),
        vec![(LIST, b"carol".to_vec())],
        &append,
        Vec::new(),
    )
    .unwrap();
    let commit = pending.commit().to_vec();
    let welcome = pending.welcome().unwrap().to_vec();
    let alice_state = confirm(pending, &alice_state);
    let (bob_state, sender) =
        mimi_process_commit_app_data(bob_state, identity("bob").1, commit, &append)
            .expect("PLANT-APP-DATA-RECEIVE: Bob resolves and reads Alice's commit");
    assert_eq!(sender.leaf_index, 0, "Alice, the creator, sent it");
    let carol_state = join(&welcome, carol);
    for state in [&alice_state, &bob_state, &carol_state] {
        assert_eq!(list(state), b"alice,bob,carol");
    }
}

/// The native receive paths never resolve an app data commit. Bob's room state, handed to the native commit and decrypt
/// functions with Alice's AppDataUpdate commit, is refused by name both times, and nothing comes back to store; the
/// MIMI lane then still reads the same commit.
#[test]
fn the_native_receive_paths_refuse_an_app_data_commit() {
    let (alice_state, alice, bob_state, _, bob) = room_with_bob_and_his_bundle();
    let (carol_kp, _) = identity("carol");
    let pending = mimi_commit_app_data_pending(
        alice_state,
        alice,
        vec![carol_kp],
        Vec::new(),
        vec![(LIST, b"carol".to_vec())],
        &append,
        Vec::new(),
    )
    .unwrap();
    let commit = pending.commit().to_vec();
    let refused =
        crate::mls::groups::mls_process_commit(bob_state.clone(), bob.clone(), commit.clone())
            .expect_err("PLANT-NATIVE-APP-DATA-COMMIT: the native commit path refuses it");
    assert!(
        refused
            .to_string()
            .contains(crate::mls::groups::NATIVE_REFUSES_APP_DATA_COMMIT),
        "refused by name: {refused}"
    );
    let refused =
        crate::mls::groups::decrypt_message(bob_state.clone(), bob.clone(), commit.clone())
            .expect_err("PLANT-NATIVE-APP-DATA-DECRYPT: the native decrypt path refuses it");
    assert!(
        refused
            .to_string()
            .contains(crate::mls::groups::NATIVE_REFUSES_APP_DATA_COMMIT),
        "refused by name: {refused}"
    );
    let (after, _) = mimi_process_commit_app_data(bob_state, bob, commit, &append)
        .expect("the MIMI lane still reads the commit");
    assert_eq!(list(&after), b"alice,bob,carol");
}

/// A member whose rules give another value, or refuse the update, refuses the commit: its GroupContext would differ
/// from the committer's, which openmls refuses on the confirmation tag.
#[test]
fn a_member_whose_rules_disagree_refuses_the_commit() {
    let (alice_state, alice, bob_state, _) = room_with_bob();
    let (dan_kp, _) = identity("dan");
    let pending = mimi_commit_app_data_pending(
        alice_state,
        alice,
        vec![dan_kp],
        Vec::new(),
        vec![(LIST, b"dan".to_vec())],
        &append,
        Vec::new(),
    )
    .unwrap();
    let commit = pending.commit().to_vec();
    assert!(
        mimi_process_commit_app_data(
            bob_state.clone(),
            Vec::new(),
            commit.clone(),
            &append_differently
        )
        .is_err(),
        "another value for the list"
    );
    assert!(
        mimi_process_commit_app_data(bob_state, Vec::new(), commit, &refuse).is_err(),
        "the member's rules refuse the update"
    );
}

/// The committer's own rules refusing an update build no commit.
#[test]
fn a_commit_the_committers_rules_refuse_is_not_built() {
    let (alice_state, alice, _, _) = room_with_bob();
    assert!(mimi_commit_app_data_pending(
        alice_state,
        alice,
        Vec::new(),
        Vec::new(),
        vec![(LIST, b"eve,mallory".to_vec())],
        &append,
        Vec::new(),
    )
    .is_err());
}

/// A removal and its list update ride one commit, and the remaining member takes it.
#[test]
fn a_removal_and_its_list_update_ride_one_commit() {
    let (alice_state, alice, bob_state, _) = room_with_bob();
    let (carol_kp, _) = identity("carol");
    let pending = mimi_commit_app_data_pending(
        alice_state.clone(),
        alice.clone(),
        vec![carol_kp],
        Vec::new(),
        vec![(LIST, b"carol".to_vec())],
        &append,
        Vec::new(),
    )
    .unwrap();
    let commit = pending.commit().to_vec();
    let alice_state = confirm(pending, &alice_state);
    let (bob_state, _) =
        mimi_process_commit_app_data(bob_state, Vec::new(), commit, &append).unwrap();
    let pending = mimi_commit_app_data_pending(
        alice_state.clone(),
        alice,
        Vec::new(),
        vec!["mimi://hub.example/u/carol".into()],
        vec![(LIST, b"-carol".to_vec())],
        &append,
        Vec::new(),
    )
    .unwrap();
    let commit = pending.commit().to_vec();
    let alice_state = confirm(pending, &alice_state);
    let (bob_state, _) =
        mimi_process_commit_app_data(bob_state, Vec::new(), commit, &append).unwrap();
    assert_eq!(list(&alice_state), list(&bob_state));
    assert_eq!(list(&bob_state), b"alice,bob,carol,-carol");
}

struct Member {
    state: Vec<u8>,
    bundle: Vec<u8>,
}

/// A room `names[0]` created, every other name added in one commit whose list update appends "added"; every member's
/// state and identity, in the order of `names`.
fn room(names: &[&str]) -> Vec<Member> {
    let (_, creator) = identity(names[0]);
    let state = mimi_create_group_app_data(
        "room".into(),
        creator.clone(),
        vec![(LIST, names[0].as_bytes().to_vec())],
    )
    .unwrap();
    let (key_packages, bundles): (Vec<_>, Vec<_>) =
        names[1..].iter().map(|name| identity(name)).unzip();
    let pending = mimi_commit_app_data_pending(
        state.clone(),
        creator.clone(),
        key_packages,
        Vec::new(),
        vec![(LIST, b"added".to_vec())],
        &append,
        Vec::new(),
    )
    .unwrap();
    let welcome = pending.welcome().unwrap().to_vec();
    let mut members = vec![Member {
        state: confirm(pending, &state),
        bundle: creator,
    }];
    for bundle in bundles {
        members.push(Member {
            state: join(&welcome, bundle.clone()),
            bundle,
        });
    }
    members
}

/// Alice's room with Bob and Carol in it.
fn three_member_room() -> (Member, Member, Member) {
    let mut members = room(&["alice", "bob", "carol"]).into_iter();
    (
        members.next().unwrap(),
        members.next().unwrap(),
        members.next().unwrap(),
    )
}

/// The proposals of Bob's leave, stored by `member`.
fn store(member: &mut Member, proposals: &[Vec<u8>]) {
    for proposal in proposals {
        member.state = mimi_process_proposal_app_data(
            member.state.clone(),
            member.bundle.clone(),
            proposal.clone(),
        )
        .expect("a member's leave proposal is stored");
    }
}

/// A member leaves by proposals; the others store them, and the next commit includes them by reference and resolves
/// the leave's list update as every receiver does. Revert check: resolve only the commit's own updates and the commit
/// is not built.
#[test]
fn a_leave_by_proposals_is_committed_by_reference_and_every_member_agrees() {
    let (mut alice, bob, mut carol) = three_member_room();
    let (_, proposals) = mimi_leave_app_data(
        bob.state,
        bob.bundle,
        vec![(LIST, b"-bob".to_vec())],
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        proposals.len(),
        2,
        "a Remove of Bob's leaf and the list update"
    );
    store(&mut alice, &proposals);
    store(&mut carol, &proposals);
    let pending = mimi_commit_app_data_pending(
        alice.state.clone(),
        alice.bundle.clone(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        &append,
        Vec::new(),
    )
    .expect("PLANT-APP-DATA-BYREF: the commit resolves the leave's update");
    let commit = pending.commit().to_vec();
    let alice_state = confirm(pending, &alice.state);
    let (carol_state, _) = mimi_process_commit_app_data(carol.state, carol.bundle, commit, &append)
        .expect("Carol takes the commit");
    assert_eq!(list(&alice_state), b"alice,added,-bob");
    assert_eq!(list(&carol_state), list(&alice_state));
}

/// A pending leave's list update and the commit's own update to the list ride one commit: each is resolved, in the
/// commit's order, from the value the one before it left, and a receiver agrees.
#[test]
fn a_pending_leave_and_the_commits_own_update_to_the_list_both_apply() {
    let (mut alice, bob, mut carol) = three_member_room();
    let (_, proposals) = mimi_leave_app_data(
        bob.state,
        bob.bundle,
        vec![(LIST, b"-bob".to_vec())],
        Vec::new(),
    )
    .unwrap();
    store(&mut alice, &proposals);
    store(&mut carol, &proposals);
    let pending = mimi_commit_app_data_pending(
        alice.state.clone(),
        alice.bundle.clone(),
        Vec::new(),
        Vec::new(),
        vec![(LIST, b"dan".to_vec())],
        &append,
        Vec::new(),
    )
    .expect("two updates to one component ride one commit");
    let commit = pending.commit().to_vec();
    let alice_state = confirm(pending, &alice.state);
    assert_eq!(list(&alice_state), b"alice,added,-bob,dan");
    let (carol_state, _) = mimi_process_commit_app_data(carol.state, carol.bundle, commit, &append)
        .expect("Carol resolves the two updates in the same order");
    assert_eq!(list(&carol_state), list(&alice_state));
}

/// Bob and Carol leave together and Alice commits both leaves; Dave, who stored them in the other order, takes the
/// commit. Revert check: hand the rules only a component's last change, and one leave is lost from the list.
#[test]
fn two_members_leaving_together_are_committed_in_one_commit() {
    let mut members = room(&["alice", "bob", "carol", "dave"]).into_iter();
    let (mut alice, bob, carol, mut dave) = (
        members.next().unwrap(),
        members.next().unwrap(),
        members.next().unwrap(),
        members.next().unwrap(),
    );
    let (_, bob_leave) = mimi_leave_app_data(
        bob.state,
        bob.bundle,
        vec![(LIST, b"-bob".to_vec())],
        Vec::new(),
    )
    .unwrap();
    let (_, carol_leave) = mimi_leave_app_data(
        carol.state,
        carol.bundle,
        vec![(LIST, b"-carol".to_vec())],
        Vec::new(),
    )
    .unwrap();
    store(&mut alice, &bob_leave);
    store(&mut alice, &carol_leave);
    store(&mut dave, &carol_leave);
    store(&mut dave, &bob_leave);
    let pending = mimi_commit_app_data_pending(
        alice.state.clone(),
        alice.bundle.clone(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        &append,
        Vec::new(),
    )
    .expect("both leaves ride one commit");
    let commit = pending.commit().to_vec();
    let alice_state = confirm(pending, &alice.state);
    let value = String::from_utf8(list(&alice_state)).unwrap();
    assert!(
        value.split(',').filter(|name| *name == "-bob").count() == 1
            && value.split(',').filter(|name| *name == "-carol").count() == 1,
        "PLANT-APP-DATA-ALL-CHANGES: each leave's update applies once, got {value}"
    );
    let (dave_state, _) = mimi_process_commit_app_data(dave.state, dave.bundle, commit, &append)
        .expect("Dave resolves the leaves in the commit's order");
    assert_eq!(list(&dave_state), list(&alice_state));
}

/// Carol's proposal to remove Bob is not a leave: Alice doesn't store it for her next commit.
#[test]
fn a_members_remove_of_another_member_is_not_taken() {
    let (alice, _bob, carol) = three_member_room();
    let mut opened = open_group(carol.state, carol.bundle).unwrap();
    let bob_leaf = member_index(&opened, "mimi://hub.example/u/bob").unwrap();
    let (proposal, _) = opened
        .group
        .propose_remove_member(&opened.provider, &opened.signer, bob_leaf)
        .unwrap();
    let proposal = proposal.tls_serialize_detached().unwrap();
    assert!(
        mimi_process_proposal_app_data(alice.state, alice.bundle, proposal).is_err(),
        "PLANT-APP-DATA-OWN-REMOVE: a Remove of another member is refused"
    );
}

/// Carol's proposal to remove the list component is not a leave: Alice doesn't store it for her next commit.
#[test]
fn a_members_proposal_removing_a_component_is_not_taken() {
    let (alice, _bob, carol) = three_member_room();
    let mut opened = open_group(carol.state, carol.bundle).unwrap();
    let (proposal, _) = opened
        .group
        .propose_app_data_update(
            &opened.provider,
            &opened.signer,
            LIST,
            AppDataUpdateOperation::Remove,
        )
        .unwrap();
    let proposal = proposal.tls_serialize_detached().unwrap();
    assert!(
        mimi_process_proposal_app_data(alice.state, alice.bundle, proposal).is_err(),
        "PLANT-APP-DATA-NO-COMPONENT-REMOVAL: a component's removal is refused"
    );
}

/// A commit removing a component, as another client may send one: the receiver's rules judge the removal like any
/// change, and refuse it when they refuse every change. Revert check: apply a removal without asking the rules.
#[test]
fn a_commit_removing_a_component_is_judged_by_the_receivers_rules() {
    let (alice, _bob, carol) = three_member_room();
    let mut opened = open_group(carol.state, carol.bundle).unwrap();
    let mut stage = opened
        .group
        .commit_builder()
        .add_proposals([Proposal::AppDataUpdate(Box::new(
            AppDataUpdateProposal::remove(LIST),
        ))])
        .load_psks(opened.provider.storage())
        .unwrap();
    let mut updater = stage.app_data_dictionary_updater();
    updater.remove(&LIST);
    let changes = updater.changes();
    stage.with_app_data_dictionary_updates(changes);
    let (commit, _, _) = stage
        .build(
            opened.provider.rand(),
            opened.provider.crypto(),
            &opened.signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(&opened.provider)
        .unwrap()
        .into_messages();
    let commit = commit.tls_serialize_detached().unwrap();
    assert!(
        mimi_process_commit_app_data(
            alice.state.clone(),
            alice.bundle.clone(),
            commit.clone(),
            &refuse
        )
        .is_err(),
        "PLANT-APP-DATA-REMOVAL-JUDGED: the receiver's rules refuse the removal"
    );
    let (alice_state, _) = mimi_process_commit_app_data(alice.state, alice.bundle, commit, &append)
        .expect("rules that allow the removal take the commit");
    assert_eq!(mimi_app_data_value(&alice_state, LIST).unwrap(), None);
}

/// A member whose KeyPackage opened a Welcome refreshes it, and a room requiring the app data capabilities still adds
/// it. Revert check: refresh without the capabilities and the add is refused.
#[test]
fn a_refreshed_key_package_can_still_join_a_room() {
    let (alice_state, alice, _, _) = room_with_bob();
    let (_, carol) = identity("carol");
    let mut spent: crate::mls::IdentityBundle = serde_json::from_slice(&carol).unwrap();
    spent.key_package_bundle = None;
    let (_, carol_kp, _) =
        mimi_regenerate_key_package_app_data(serde_json::to_vec(&spent).unwrap(), now_secs() + 1)
            .unwrap();
    mimi_commit_app_data_pending(
        alice_state,
        alice,
        vec![carol_kp],
        Vec::new(),
        vec![(LIST, b"carol".to_vec())],
        &append,
        Vec::new(),
    )
    .expect(
        "PLANT-APP-DATA-REFRESH: the refreshed KeyPackage meets the room's required capabilities",
    );
}

/// The KeyPackages a bundle holds, as their storage keys, and how many of them are last-resort; checked to be in its
/// storage by [`held`].
fn held_unchecked(bundle: &[u8]) -> (Vec<Vec<u8>>, usize, bool) {
    let identity: crate::mls::IdentityBundle = serde_json::from_slice(bundle).unwrap();
    let provider = OpenMlsRustCrypto::default();
    let all: Vec<&KeyPackageBundle> = identity
        .key_package_bundle
        .iter()
        .chain(&identity.key_package_bundles)
        .collect();
    let stored: std::collections::HashSet<&Vec<u8>> =
        identity.storage_map.iter().map(|(k, _)| k).collect();
    let keys: Vec<Vec<u8>> = all
        .iter()
        .map(|kpb| crate::mls::groups::kp_storage_key(kpb.key_package(), &provider).unwrap())
        .collect();
    let in_storage = keys.iter().all(|key| stored.contains(key));
    let last_resort = all
        .iter()
        .filter(|kpb| kpb.key_package().last_resort())
        .count();
    (keys, last_resort, in_storage)
}

/// [`held_unchecked`], with every KeyPackage held asserted to be in the bundle's storage.
fn held(bundle: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let (keys, last_resort, in_storage) = held_unchecked(bundle);
    assert!(in_storage, "every KeyPackage held is in storage");
    (keys, last_resort)
}

fn storage_key_of(key_package: &[u8]) -> Vec<u8> {
    let key_package = KeyPackageIn::tls_deserialize_exact(key_package)
        .unwrap()
        .validate(
            OpenMlsRustCrypto::default().crypto(),
            ProtocolVersion::Mls10,
        )
        .unwrap();
    crate::mls::groups::kp_storage_key(&key_package, &OpenMlsRustCrypto::default()).unwrap()
}

/// A room of Alice's that adds the member whose KeyPackage is `key_package`: the Welcome.
fn welcome_for(key_package: Vec<u8>) -> Vec<u8> {
    let (_, alice) = identity("alice");
    let room = mimi_create_group_app_data(
        "room".into(),
        alice.clone(),
        vec![(LIST, b"alice".to_vec())],
    )
    .unwrap();
    let pending = mimi_commit_app_data_pending(
        room,
        alice,
        vec![key_package],
        Vec::new(),
        vec![(LIST, b"joiner".to_vec())],
        &append,
        Vec::new(),
    )
    .unwrap();
    pending.welcome().unwrap().to_vec()
}

/// Join from `welcome` with `bundle`: the bundle to keep afterwards, and whether the join completed.
fn join_with(welcome: &[u8], bundle: Vec<u8>) -> (Vec<u8>, bool) {
    match prepare_welcome_retirement(welcome.to_vec(), bundle.clone(), Vec::new(), String::new()) {
        Err(_) => (bundle, false),
        Ok(prepared) => match complete_welcome(prepared) {
            Ok((_, bundle)) => (bundle, true),
            Err(crate::mimi::MimiWelcomeError::Spent { retired_bundle, .. }) => {
                (retired_bundle, false)
            }
            Err(crate::mimi::MimiWelcomeError::Unspent(_)) => (bundle, false),
        },
    }
}

/// Bob publishes three KeyPackages; a Welcome naming the second spends only that one, so the other two still open
/// Welcomes and the second never opens another. Revert check: keep every further KeyPackage after a join, and the
/// spent one is still held.
#[test]
fn a_welcome_spends_only_the_key_package_it_names() {
    let (_, bob) = identity("bob");
    let (bob, key_packages) = mimi_add_key_packages(bob, 3, false, now_secs()).unwrap();
    assert_eq!(key_packages.len(), 3);
    assert_eq!(held(&bob).0.len(), 4, "the first KeyPackage and three more");
    let (bob, joined) = join_with(&welcome_for(key_packages[1].clone()), bob);
    assert!(joined);
    let (keys, _, in_storage) = held_unchecked(&bob);
    assert!(
        !keys.contains(&storage_key_of(&key_packages[1])),
        "PLANT-MIMI-KP-SPENT: the spent KeyPackage is no longer held"
    );
    assert!(in_storage);
    assert_eq!(keys.len(), 3);
    let (bob, joined) = join_with(&welcome_for(key_packages[0].clone()), bob);
    assert!(joined, "another KeyPackage still opens a Welcome");
    let (_, joined) = join_with(&welcome_for(key_packages[1].clone()), bob);
    assert!(!joined, "the spent one opens no second Welcome");
}

/// A last-resort KeyPackage opens two Welcomes, and a new one replaces it: the bundle holds one, and the old one opens
/// nothing more. Revert check: keep the old last-resort KeyPackage when adding a new one, and the bundle holds two.
#[test]
fn a_last_resort_key_package_serves_twice_and_a_new_one_replaces_it() {
    let (_, bob) = identity("bob");
    let (bob, first) = mimi_add_key_packages(bob, 0, true, now_secs()).unwrap();
    let (bob, joined) = join_with(&welcome_for(first[0].clone()), bob);
    assert!(joined);
    let (bob, joined) = join_with(&welcome_for(first[0].clone()), bob);
    assert!(
        joined,
        "PLANT-MIMI-KP-LAST-RESORT: a last-resort KeyPackage opens a second Welcome"
    );
    let (bob, second) = mimi_add_key_packages(bob, 0, true, now_secs()).unwrap();
    assert_eq!(
        held(&bob).1,
        1,
        "PLANT-MIMI-KP-ONE-LAST-RESORT: one last-resort KeyPackage at a time"
    );
    let (bob, joined) = join_with(&welcome_for(first[0].clone()), bob);
    assert!(!joined, "the replaced one opens nothing");
    let (_, joined) = join_with(&welcome_for(second[0].clone()), bob);
    assert!(joined);
}

/// A KeyPackage whose lifetime has ended is dropped when more are added, and past the cap the oldest one-time ones go,
/// never the last-resort one. Revert checks: keep ended ones, or skip the cap, and the bundle holds them.
#[test]
fn ended_key_packages_and_those_past_the_cap_are_dropped() {
    let (_, bob) = identity("bob");
    let now = now_secs();
    let (bob, early) = mimi_add_key_packages(bob, 2, true, now).unwrap();
    let later = now + i64::try_from(crate::mls::KP_LIFETIME_SECS).unwrap() + 10;
    let (bob, _) = mimi_add_key_packages(bob, 1, false, later).unwrap();
    let (keys, last_resort) = held(&bob);
    assert_eq!(
        keys.len(),
        1,
        "PLANT-MIMI-KP-ENDED: only the KeyPackage made after the others ended"
    );
    assert_eq!(last_resort, 0);
    assert!(!keys.contains(&storage_key_of(&early[0])));

    let (_, bob) = identity("carol");
    let (mut bob, _) = mimi_add_key_packages(bob, 1, true, now).unwrap();
    for _ in 0..3 {
        bob = mimi_add_key_packages(bob, 31, false, now).unwrap().0;
    }
    let (keys, last_resort) = held(&bob);
    assert_eq!(
        keys.len(),
        MAX_KEY_PACKAGES_HELD,
        "PLANT-MIMI-KP-CAP: an identity holds at most the cap"
    );
    assert_eq!(
        last_resort, 1,
        "the last-resort KeyPackage is never dropped for the cap"
    );
}

#[test]
fn adding_too_many_or_none_is_refused() {
    let (_, bob) = identity("bob");
    assert!(mimi_add_key_packages(bob.clone(), MAX_KEY_PACKAGES_ADDED, true, now_secs()).is_err());
    assert!(mimi_add_key_packages(bob, 0, false, now_secs()).is_err());
}

/// The bundle a join persists before it opens the Welcome no longer holds the KeyPackage the Welcome names, and still
/// holds the others, so a crash between the two leaves no spent KeyPackage live and no live one lost. Revert check:
/// keep every further KeyPackage in that bundle, and the named one is still held.
#[test]
fn the_bundle_persisted_before_a_join_drops_only_the_named_key_package() {
    let (_, bob) = identity("bob");
    let (bob, key_packages) = mimi_add_key_packages(bob, 3, false, now_secs()).unwrap();
    let prepared = prepare_welcome_retirement(
        welcome_for(key_packages[2].clone()),
        bob,
        Vec::new(),
        String::new(),
    )
    .unwrap();
    let (keys, _, in_storage) = held_unchecked(prepared.retired_bundle());
    assert!(
        !keys.contains(&storage_key_of(&key_packages[2])),
        "PLANT-MIMI-KP-CANDIDATE: the named KeyPackage is retired before the join"
    );
    assert!(in_storage);
    assert!(keys.contains(&storage_key_of(&key_packages[0])));
    assert!(keys.contains(&storage_key_of(&key_packages[1])));
}

/// Refreshing replaces a bundle's storage, so a bundle holding added KeyPackages is refused rather than losing ones its
/// provider may still hand out. Revert check: let refresh run, and the added KeyPackages are gone from the bundle.
#[test]
fn a_refresh_refuses_a_bundle_holding_added_key_packages() {
    let (_, bob) = identity("bob");
    let (bob, _) = mimi_add_key_packages(bob, 2, false, now_secs()).unwrap();
    assert!(
        mimi_regenerate_key_package_app_data(bob, now_secs()).is_err(),
        "PLANT-MIMI-KP-REFRESH-REFUSED: a refresh would drop KeyPackages still published"
    );
}

/// The summarized form of taking a commit says what it did: the epoch it moved the group to, its committer, an Add and
/// an AppDataUpdate among its proposals. The group's view lists the participant list among its components. Revert
/// check: report the epoch before the commit, and the summary disagrees with the view.
#[test]
fn a_summarized_commit_says_what_it_did() {
    let (alice_state, alice, bob_state, _, bob) = room_with_bob_and_his_bundle();
    let (carol_kp, _) = identity("carol");
    let pending = mimi_commit_app_data_pending(
        alice_state,
        alice,
        vec![carol_kp],
        Vec::new(),
        vec![(LIST, b"carol".to_vec())],
        &append,
        Vec::new(),
    )
    .unwrap();
    let commit = pending.commit().to_vec();
    let (bob_state, sender, summary) =
        mimi_process_commit_app_data_summarized(bob_state, bob, commit, &append).unwrap();
    let view = crate::mimi::view::mimi_group_view(&bob_state).unwrap();
    assert_eq!(
        summary.epoch, view.epoch,
        "PLANT-COMMIT-SUMMARY-EPOCH: the summary's epoch is not the group's after the commit"
    );
    assert_eq!(summary.committer_leaf, sender.leaf_index);
    assert_eq!(summary.committer_leaf, 0, "Alice, the creator");
    assert!(
        summary.proposal_types.contains(&0x0001),
        "the Add: {:?}",
        summary.proposal_types
    );
    assert!(
        summary.proposal_types.contains(&0x0008),
        "the AppDataUpdate: {:?}",
        summary.proposal_types
    );
    assert!(view.components.contains(&LIST), "{:?}", view.components);
}
