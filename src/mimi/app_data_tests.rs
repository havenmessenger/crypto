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

/// A stand-in for the participant list's rules: the value is the names, comma separated, and an update appends one.
fn append(_: u16, before: Option<&[u8]>, update: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(!update.contains(&b','), "a name has no comma");
    Ok(match before {
        Some(list) if !list.is_empty() => [list, b",", update].concat(),
        _ => update.to_vec(),
    })
}

/// A member whose rules differ: it appends with a semicolon.
fn append_differently(_: u16, before: Option<&[u8]>, update: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok([before.unwrap_or_default(), b";", update].concat())
}

fn refuse(_: u16, _: Option<&[u8]>, _: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::bail!("this member's rules refuse the update")
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
    let bob_state = join(&welcome, bob);
    (alice_state, alice, bob_state, welcome)
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

/// The committer's own rules refusing an update build no commit, and one commit updates a component once.
#[test]
fn a_commit_the_committers_rules_refuse_is_not_built() {
    let (alice_state, alice, _, _) = room_with_bob();
    assert!(mimi_commit_app_data_pending(
        alice_state.clone(),
        alice.clone(),
        Vec::new(),
        Vec::new(),
        vec![(LIST, b"eve,mallory".to_vec())],
        &append,
        Vec::new(),
    )
    .is_err());
    assert!(mimi_commit_app_data_pending(
        alice_state,
        alice,
        Vec::new(),
        Vec::new(),
        vec![(LIST, b"x".to_vec()), (LIST, b"y".to_vec())],
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

/// Alice's room with Bob and Carol in it, every member's state and identity.
fn three_member_room() -> (Member, Member, Member) {
    let (_, alice) = identity("alice");
    let (bob_kp, bob) = identity("bob");
    let (carol_kp, carol) = identity("carol");
    let room = mimi_create_group_app_data(
        "room".into(),
        alice.clone(),
        vec![(LIST, b"alice".to_vec())],
    )
    .unwrap();
    let pending = mimi_commit_app_data_pending(
        room.clone(),
        alice.clone(),
        vec![bob_kp, carol_kp],
        Vec::new(),
        vec![(LIST, b"bob".to_vec())],
        &append,
        Vec::new(),
    )
    .unwrap();
    let welcome = pending.welcome().unwrap().to_vec();
    let alice_state = confirm(pending, &room);
    let bob_state = join(&welcome, bob.clone());
    let carol_state = join(&welcome, carol.clone());
    (
        Member {
            state: alice_state,
            bundle: alice,
        },
        Member {
            state: bob_state,
            bundle: bob,
        },
        Member {
            state: carol_state,
            bundle: carol,
        },
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
    assert_eq!(list(&alice_state), b"alice,bob,-bob");
    assert_eq!(list(&carol_state), list(&alice_state));
}

/// A pending leave's list update and the commit's own change to the list cannot ride one commit: committer and
/// receivers would have no agreed order between them.
#[test]
fn a_commit_changing_a_component_twice_is_refused() {
    let (mut alice, bob, _) = three_member_room();
    let (_, proposals) = mimi_leave_app_data(
        bob.state,
        bob.bundle,
        vec![(LIST, b"-bob".to_vec())],
        Vec::new(),
    )
    .unwrap();
    store(&mut alice, &proposals);
    assert!(mimi_commit_app_data_pending(
        alice.state,
        alice.bundle,
        Vec::new(),
        Vec::new(),
        vec![(LIST, b"dan".to_vec())],
        &append,
        Vec::new(),
    )
    .is_err());
}
