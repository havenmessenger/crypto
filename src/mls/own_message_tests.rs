use super::OwnMessage;
use crate::identity::generate_identity;
use crate::mls::groups::{
    add_member, add_member_pending, create_group, decrypt_message, encrypt_message, list_members,
    mls_process_commit, process_welcome, self_update_pending,
};

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
        .try_into()
        .expect("a clock before 2262")
}

/// Alice's group with Bob in it, Alice's bundle, and a key package for Carol.
fn alice_with_bob() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let (_, _, alice) = generate_identity("alice".to_string(), now()).expect("alice");
    let (_, bob_key_package, bob) = generate_identity("bob".to_string(), now()).expect("bob");
    let (_, carol_key_package, _) = generate_identity("carol".to_string(), now()).expect("carol");
    let group = create_group("own-message".to_string(), alice.clone()).expect("create_group");
    let (group, welcome, _) = add_member(group, alice.clone(), bob_key_package).expect("add bob");
    let (bob_state, _) = process_welcome(welcome, bob.clone()).expect("bob joins");
    (group, alice, bob_state, bob, carol_key_package)
}

fn is_own(error: &anyhow::Error) -> bool {
    error.downcast_ref::<OwnMessage>().is_some()
}

#[test]
fn an_own_application_message_is_refused_as_own() {
    let (group, alice, bob_state, bob, _) = alice_with_bob();
    let (group, ciphertext) =
        encrypt_message(group, alice.clone(), b"hello".to_vec()).expect("send");
    let error = decrypt_message(group, alice, ciphertext.clone()).expect_err("own message");
    assert!(is_own(&error), "{error}");
    let (_, plaintext, _) = decrypt_message(bob_state, bob, ciphertext).expect("bob reads it");
    assert_eq!(plaintext, b"hello");
}

/// An Add-only commit carries no UpdatePath. Without the refusal its author would stage it from the
/// wire and move its canonical state outside `PendingCommit::confirm`.
#[test]
fn an_own_commit_without_an_update_path_is_refused_and_moves_nothing() {
    let (group, alice, _, _, carol_key_package) = alice_with_bob();
    let pending =
        add_member_pending(group.clone(), alice.clone(), carol_key_package).expect("stage add");
    let error = mls_process_commit(group.clone(), alice.clone(), pending.commit().to_vec())
        .expect_err("own commit");
    assert!(is_own(&error), "{error}");
    assert_eq!(list_members(group).expect("members").len(), 2);
}

#[test]
fn an_own_commit_with_an_update_path_is_refused_as_own() {
    let (group, alice, _, _, _) = alice_with_bob();
    let pending = self_update_pending(group.clone(), alice.clone()).expect("stage update");
    let error =
        mls_process_commit(group, alice, pending.commit().to_vec()).expect_err("own commit");
    assert!(is_own(&error), "{error}");
}

#[test]
fn another_members_commit_is_not_refused_as_own() {
    let (group, alice, bob_state, bob, carol_key_package) = alice_with_bob();
    let pending = add_member_pending(group, alice, carol_key_package).expect("stage add");
    let (bob_state, _) =
        mls_process_commit(bob_state, bob, pending.commit().to_vec()).expect("bob applies it");
    assert_eq!(list_members(bob_state).expect("members").len(), 3);
}
