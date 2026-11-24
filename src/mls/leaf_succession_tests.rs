//! A member's renewed leaf keeps its credential identity: a Commit whose `UpdatePath` leaf names another identity than the
//! committer's leaf is refused on every receive path, the receiver's state stays as it was, and a removal by credential
//! still finds the member by its own name. A renewal that keeps the identity, a signing-key rotation included, is taken.

use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::prelude::*;
use tls_codec::Serialize as _;

use crate::identity::generate_identity;
use crate::mimi::{
    complete_welcome, mimi_add_member, mimi_create_group, mimi_generate_identity,
    mls_process_commit_appsync, prepare_welcome_retirement,
};
use crate::mls::commit_refusal::{CommitRefusal, CommitRefusalReason};
use crate::mls::groups::{
    add_member, create_group, list_members_with_indices, mls_process_commit, process_welcome,
    remove_member_by_credential_pending, self_update_pending,
};
use crate::mls::pending::open_group;
use crate::mls::rotation::rotate_signer_pending;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap()
}

/// A Commit by the member holding `state` that renews its leaf, keeping its signing key, with a Basic credential
/// naming `identity`: what a member that renames its leaf would send.
pub fn self_update_naming(state: Vec<u8>, bundle: Vec<u8>, identity: &str) -> Vec<u8> {
    let mut opened = open_group(state, bundle).unwrap();
    let key = opened
        .group
        .own_leaf_node()
        .unwrap()
        .signature_key()
        .clone();
    let parameters = LeafNodeParameters::builder()
        .with_credential_with_key(CredentialWithKey {
            credential: BasicCredential::new(identity.as_bytes().to_vec()).into(),
            signature_key: key,
        })
        .build();
    let (commit, _, _) = opened
        .group
        .self_update(&opened.provider, &opened.signer, parameters)
        .unwrap()
        .into_messages();
    commit.tls_serialize_detached().unwrap()
}

/// The reason a refused Commit gives, when it is a [`CommitRefusal`].
fn refusal_reason(error: &anyhow::Error) -> Option<CommitRefusalReason> {
    error
        .downcast_ref::<CommitRefusal>()
        .map(CommitRefusal::reason)
}

/// The identities `state` holds, by leaf.
fn identities(state: &[u8]) -> Vec<(u32, String)> {
    list_members_with_indices(state.to_vec())
        .unwrap()
        .into_iter()
        .map(|member| {
            (
                member.leaf_index,
                String::from_utf8(member.credential_identity).unwrap(),
            )
        })
        .collect()
}

/// A native group of Alice, Bob and Mallory: each one's state and bundle, in that order.
fn alice_bob_mallory() -> [(Vec<u8>, Vec<u8>); 3] {
    let (_, _, alice) = generate_identity("alice".into(), now()).unwrap();
    let (_, bob_kp, bob) = generate_identity("bob".into(), now()).unwrap();
    let (_, mallory_kp, mallory) = generate_identity("mallory".into(), now()).unwrap();
    let state = create_group("succession".into(), alice.clone()).unwrap();
    let (alice_state, bob_welcome, _) = add_member(state, alice.clone(), bob_kp).unwrap();
    let (bob_state, bob) = process_welcome(bob_welcome, bob).unwrap();
    let (alice_state, mallory_welcome, add_mallory) =
        add_member(alice_state, alice.clone(), mallory_kp).unwrap();
    let (bob_state, _) = mls_process_commit(bob_state, bob.clone(), add_mallory).unwrap();
    let (mallory_state, mallory) = process_welcome(mallory_welcome, mallory).unwrap();
    [
        (alice_state, alice),
        (bob_state, bob),
        (mallory_state, mallory),
    ]
}

/// Mallory renews her leaf keeping her key with a credential naming Bob. Alice refuses the Commit as a credential
/// refusal, keeps her state, and still finds Mallory by her own name: removing "mallory" removes Mallory's leaf and no
/// other. Revert check: drop the check from `mls_process_commit`, and Alice takes the Commit.
#[test]
fn a_native_commit_renaming_its_committers_leaf_is_refused() {
    let [(alice_state, alice), (_, _), (mallory_state, mallory)] = alice_bob_mallory();
    let renamed = self_update_naming(mallory_state, mallory, "bob");

    let refused = mls_process_commit(alice_state.clone(), alice.clone(), renamed);
    let error = refused.as_ref().err();
    assert_eq!(
        error.and_then(refusal_reason),
        Some(CommitRefusalReason::Credential),
        "PLANT-LEAF-ID-NATIVE: a Commit renaming its committer's leaf was taken: {:?}",
        refused.map(|_| ())
    );
    assert_eq!(
        identities(&alice_state),
        vec![
            (0, "alice".to_string()),
            (1, "bob".to_string()),
            (2, "mallory".to_string())
        ],
        "Alice's group still names each member by its own credential"
    );

    let (after_removal, _, _) =
        remove_member_by_credential_pending(alice_state, alice, "mallory".into())
            .unwrap()
            .into_merged()
            .unwrap();
    assert_eq!(
        identities(&after_removal),
        vec![(0, "alice".to_string()), (1, "bob".to_string())],
        "removing Mallory by her name removes her leaf, and Bob's stays"
    );
}

/// The same rename with a new signing key too (a rotation to a key naming Carol) is refused.
#[test]
fn a_native_rotation_that_also_renames_the_leaf_is_refused() {
    let [(alice_state, alice), (_, _), (mallory_state, mallory)] = alice_bob_mallory();
    let (_, _, carol) = generate_identity("carol".into(), now()).unwrap();
    let carol: crate::mls::IdentityBundle = serde_json::from_slice(&carol).unwrap();
    let mut opened = open_group(mallory_state, mallory).unwrap();
    let scheme = opened.group.ciphersuite().signature_algorithm();
    let new_signer = crate::mls::MlsSigner {
        key: zeroize::Zeroizing::new(carol.private_key.clone()),
        scheme,
    };
    let bundle = opened
        .group
        .commit_builder()
        .leaf_node_parameters(LeafNodeParameters::default())
        .load_psks(opened.provider.storage())
        .unwrap()
        .build_with_new_signer(
            opened.provider.rand(),
            opened.provider.crypto(),
            &opened.signer,
            openmls::credentials::NewSignerBundle {
                signer: &new_signer,
                credential_with_key: CredentialWithKey {
                    credential: BasicCredential::new(b"carol".to_vec()).into(),
                    signature_key: carol.public_key_bytes.clone().into(),
                },
            },
            |_| true,
        )
        .unwrap()
        .stage_commit(&opened.provider)
        .unwrap();
    let (commit, _, _) = bundle.into_messages();

    let refused = mls_process_commit(alice_state, alice, commit.tls_serialize_detached().unwrap());
    assert_eq!(
        refused.as_ref().err().and_then(refusal_reason),
        Some(CommitRefusalReason::Credential),
        "a rotation to a key that also renames the leaf was taken"
    );
}

/// A renewal that keeps the identity is taken: a plain self-update, and a signing-key rotation to a new key for the same
/// user, each from the same epoch.
#[test]
fn a_native_renewal_that_keeps_the_identity_is_taken() {
    let [(alice_state, alice), (bob_state, bob), (_, _)] = alice_bob_mallory();
    let (_, _, update) = self_update_pending(bob_state.clone(), bob.clone())
        .unwrap()
        .into_merged()
        .unwrap();
    mls_process_commit(alice_state.clone(), alice.clone(), update)
        .expect("a self-update keeping Bob's identity is taken");

    let (_, _, bob_new_key) = generate_identity("bob".into(), now()).unwrap();
    let (_, _, rotation) = rotate_signer_pending(bob_state, bob, bob_new_key)
        .unwrap()
        .into_merged()
        .unwrap();
    mls_process_commit(alice_state, alice, rotation)
        .expect("a rotation to a new key for Bob's identity is taken");
}

/// A MIMI group of Alice and Bob (credentials are user URIs): Alice's state and bundle, Bob's state and bundle.
fn mimi_alice_and_bob() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let (_, _, alice) = mimi_generate_identity("mimi://hub.example/u/alice".into(), now()).unwrap();
    let (_, bob_kp, bob) =
        mimi_generate_identity("mimi://hub.example/u/bob".into(), now()).unwrap();
    let state = mimi_create_group("room".into(), alice.clone()).unwrap();
    let (alice_state, welcome) = mimi_add_member(state, alice.clone(), bob_kp).unwrap();
    let prepared = prepare_welcome_retirement(welcome, bob, Vec::new(), String::new())
        .unwrap_or_else(|_| panic!("Bob's Welcome opens"));
    let (bob_state, bob) = complete_welcome(prepared).unwrap_or_else(|_| panic!("Bob joins"));
    (alice_state, alice, bob_state, bob)
}

/// On the MIMI lane, Bob renews his leaf with a credential naming another user, here a differently spelled URI for
/// himself as well as another user: Alice refuses both. His renewal under his own identity is taken. Revert check: drop
/// the check from `mimi_process_commit_summarized`, and Alice takes the renamed Commit.
#[test]
fn a_mimi_commit_renaming_its_committers_leaf_is_refused() {
    let (alice_state, alice, bob_state, bob) = mimi_alice_and_bob();
    for other in ["mimi://hub.example/u/carol", "mimi://HUB.example/u/bob"] {
        let renamed = self_update_naming(bob_state.clone(), bob.clone(), other);
        let refused = mls_process_commit_appsync(alice_state.clone(), alice.clone(), renamed);
        assert_eq!(
            refused.as_ref().err().and_then(refusal_reason),
            Some(CommitRefusalReason::Credential),
            "PLANT-LEAF-ID-APPSYNC: a MIMI Commit renaming its committer's leaf to {other} was taken: {:?}",
            refused.map(|_| ())
        );
    }
    let kept = self_update_naming(bob_state, bob, "mimi://hub.example/u/bob");
    mls_process_commit_appsync(alice_state, alice, kept)
        .expect("a MIMI renewal keeping Bob's identity is taken");
}
