//! A member replacing its leaf's signing key ([`rotate_signer_pending`]): every other member takes the new key for that
//! leaf, verifies the member's messages under it, and refuses a message signed with the old key. A new bundle that
//! names another user, uses another signature scheme, carries the leaf's current key, or holds a private key that
//! does not sign for its public key, stages nothing.

use openmls::prelude::*;
use tls_codec::Serialize as _;

use super::{leaf_uses_bundle, rotate_signer_pending};
use crate::identity::generate_identity;
use crate::mls::groups::{
    add_member, create_group, decrypt_message, encrypt_message, mls_process_commit, process_welcome,
};
use crate::mls::pending::open_group;
use crate::mls::IdentityBundle;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap()
}

/// The signature key `holder_state` holds for the member at `leaf`.
fn leaf_key(holder_state: &[u8], holder_bundle: &[u8], leaf: u32) -> Vec<u8> {
    let opened = open_group(holder_state.to_vec(), holder_bundle.to_vec()).unwrap();
    let key = opened
        .group
        .members()
        .find(|member| member.index.u32() == leaf)
        .unwrap()
        .signature_key;
    key
}

/// The public signature key a bundle carries.
fn public_key(bundle: &[u8]) -> Vec<u8> {
    let identity: IdentityBundle = serde_json::from_slice(bundle).unwrap();
    identity.public_key_bytes.clone()
}

/// Alice in a group with Bob: Alice's state and bundle, Bob's state and bundle.
fn alice_and_bob() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let (_, _, alice_bundle) = generate_identity("alice".into(), now()).unwrap();
    let (_, bob_kp, bob_bundle) = generate_identity("bob".into(), now()).unwrap();
    let state = create_group("rotation".into(), alice_bundle.clone()).unwrap();
    let (alice_state, welcome, _) = add_member(state, alice_bundle.clone(), bob_kp).unwrap();
    let (bob_state, bob_bundle) = process_welcome(welcome, bob_bundle).unwrap();
    (alice_state, alice_bundle, bob_state, bob_bundle)
}

/// Alice rotates to a new bundle's key. Bob holds the new key for her leaf, reads her message under the new bundle,
/// and refuses one signed with the old key. Revert check: skip the rotation, and Bob still holds the old key and reads
/// the old-key message.
#[test]
fn a_rotated_signing_key_replaces_the_old_one_for_every_member() {
    let (alice_state, alice_bundle, bob_state, bob_bundle) = alice_and_bob();
    let (_, _, new_bundle) = generate_identity("alice".into(), now()).unwrap();
    let old_key = leaf_key(&bob_state, &bob_bundle, 0);

    let (alice_state, _, commit) =
        rotate_signer_pending(alice_state, alice_bundle.clone(), new_bundle.clone())
            .unwrap()
            .into_merged()
            .unwrap();
    let (bob_state, _) = mls_process_commit(bob_state, bob_bundle.clone(), commit).unwrap();

    let held = leaf_key(&bob_state, &bob_bundle, 0);
    assert_ne!(
        held, old_key,
        "PLANT-H3-NEW-KEY: Bob still holds Alice's old signing key after her rotation"
    );
    assert_eq!(
        held,
        public_key(&new_bundle),
        "Bob holds the key Alice rotated to"
    );
    assert_eq!(
        leaf_key(&alice_state, &new_bundle, 0),
        held,
        "Alice's own copy of her leaf carries the new key"
    );

    let (alice_state, signed_new) =
        encrypt_message(alice_state.to_vec(), new_bundle, b"new key".to_vec()).unwrap();
    let (bob_state, read, _) = decrypt_message(bob_state, bob_bundle.clone(), signed_new).unwrap();
    assert_eq!(read, b"new key");

    // The same state, signed with the key a lost device would still hold.
    let mut stale = open_group(alice_state, alice_bundle).unwrap();
    let signed_old = stale
        .group
        .create_message(&stale.provider, &stale.signer, b"old key")
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    assert!(
        decrypt_message(bob_state, bob_bundle, signed_old).is_err(),
        "PLANT-H3-OLD-KEY-REFUSED: Bob read a message signed with Alice's old key after her rotation"
    );
}

/// The commit is signed with the key Alice held before it (RFC 9420: receivers verify a commit against the committer's
/// leaf as it stood), so Bob, who holds only her old key, processes it; the new key alone could not have signed it.
#[test]
fn the_rotation_commit_is_signed_with_the_current_key() {
    let (alice_state, alice_bundle, bob_state, bob_bundle) = alice_and_bob();
    let (_, _, new_bundle) = generate_identity("alice".into(), now()).unwrap();
    let before = leaf_key(&bob_state, &bob_bundle, 0);
    assert_eq!(
        before,
        public_key(&alice_bundle),
        "Bob holds Alice's current key"
    );
    let (_, _, commit) = rotate_signer_pending(alice_state, alice_bundle, new_bundle)
        .unwrap()
        .into_merged()
        .unwrap();
    assert!(mls_process_commit(bob_state, bob_bundle, commit).is_ok());
}

/// A new bundle for another user, or with a signature scheme the group's ciphersuite does not use, is refused before
/// anything is staged.
#[test]
fn a_new_bundle_for_another_user_or_scheme_is_refused() {
    let (alice_state, alice_bundle, _, _) = alice_and_bob();
    let (_, _, mallory) = generate_identity("mallory".into(), now()).unwrap();
    assert!(
        rotate_signer_pending(alice_state.clone(), alice_bundle.clone(), mallory).is_err(),
        "a bundle naming another user"
    );

    let (_, _, other_scheme) = generate_identity("alice".into(), now()).unwrap();
    let mut identity: IdentityBundle = serde_json::from_slice(&other_scheme).unwrap();
    identity.signature_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    let other_scheme = serde_json::to_vec(&identity).unwrap();
    assert!(
        rotate_signer_pending(alice_state, alice_bundle, other_scheme).is_err(),
        "a bundle with another signature scheme"
    );
}

/// A "rotation" to the key the leaf already holds is refused: it would move the epoch and report success while the
/// key a lost device holds stays valid. Revert check: drop the refusal, and the rotation stages.
#[test]
fn a_rotation_to_the_leafs_current_key_is_refused() {
    let (alice_state, alice_bundle, _, _) = alice_and_bob();
    let refused = rotate_signer_pending(alice_state, alice_bundle.clone(), alice_bundle);
    assert!(
        refused.is_err(),
        "PLANT-H3-SAME-KEY: a rotation to the leaf's current key was staged"
    );
}

/// A new bundle whose private key does not sign for its public key is refused before staging: every receiver would
/// verify the new leaf under that public key and refuse the commit. Revert check: drop the probe, and it stages.
#[test]
fn a_new_bundle_whose_key_pair_does_not_match_is_refused() {
    let (alice_state, alice_bundle, _, _) = alice_and_bob();
    let (_, _, first) = generate_identity("alice".into(), now()).unwrap();
    let (_, _, second) = generate_identity("alice".into(), now()).unwrap();
    // The first bundle's public key with the second's private key.
    let mut mismatched: IdentityBundle = serde_json::from_slice(&first).unwrap();
    let other: IdentityBundle = serde_json::from_slice(&second).unwrap();
    mismatched.private_key = other.private_key.clone();
    let mismatched = serde_json::to_vec(&mismatched).unwrap();

    let refused = rotate_signer_pending(alice_state, alice_bundle, mismatched);
    assert!(
        refused.is_err(),
        "PLANT-H3-PROBE: a bundle whose private key does not sign for its public key was staged"
    );
}

/// The group state tells which key the member's leaf carries: the current bundle's before a rotation, the new one's
/// after it is installed, and never both. Revert check: answer true for any bundle, and the old bundle still matches
/// after the rotation.
#[test]
fn the_group_state_tells_whether_the_leaf_was_rotated() {
    let (alice_state, alice_bundle, _, _) = alice_and_bob();
    let (_, _, new_bundle) = generate_identity("alice".into(), now()).unwrap();
    assert!(leaf_uses_bundle(alice_state.clone(), alice_bundle.clone()).unwrap());
    assert!(
        !leaf_uses_bundle(alice_state.clone(), new_bundle.clone()).unwrap(),
        "PLANT-H3-LEAF-KEY: the leaf reads as carrying a key it was never rotated to"
    );

    let (rotated, _, _) =
        rotate_signer_pending(alice_state, alice_bundle.clone(), new_bundle.clone())
            .unwrap()
            .into_merged()
            .unwrap();
    assert!(leaf_uses_bundle(rotated.to_vec(), new_bundle).unwrap());
    assert!(
        !leaf_uses_bundle(rotated.to_vec(), alice_bundle).unwrap(),
        "the rotated leaf no longer carries the old key"
    );
}
