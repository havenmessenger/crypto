//! A member replacing its leaf's signing key in a commit (openmls `self_update_with_new_signer`): every other member
//! takes the new key for that leaf, verifies the member's messages under it, and refuses a message signed with the old
//! key. This is the rotation a member needs after one of its devices is lost, since the leaf renewal
//! (`self_update_pending`) keeps the signing key.

use openmls::credentials::{CredentialWithKey, NewSignerBundle};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use tls_codec::Serialize as _;
use zeroize::Zeroizing;

use super::{add_member, create_group, decrypt_message, mls_process_commit, process_welcome};
use crate::identity::generate_identity;
use crate::mls::pending::open_group;
use crate::mls::MlsSigner;

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

/// Alice rotates her signing key in a group with Bob. Bob holds the new key for her leaf, reads her message signed
/// with it, and refuses one signed with the old key. Revert check: rotate to the same key, and Bob still holds the old
/// key and reads the old-key message.
#[test]
fn a_rotated_signing_key_replaces_the_old_one_for_every_member() {
    let (_, _, alice_bundle) = generate_identity("alice".into(), now()).unwrap();
    let (_, bob_kp, bob_bundle) = generate_identity("bob".into(), now()).unwrap();
    let state = create_group("rotation".into(), alice_bundle.clone()).unwrap();
    let (alice_state, welcome, _) = add_member(state, alice_bundle.clone(), bob_kp).unwrap();
    let (mut bob_state, bob_bundle) = process_welcome(welcome, bob_bundle).unwrap();

    let mut alice = open_group(alice_state, alice_bundle).unwrap();
    let old_key = leaf_key(&bob_state, &bob_bundle, 0);
    let scheme = alice.group.ciphersuite().signature_algorithm();
    let (private, public) = alice.provider.crypto().signature_key_gen(scheme).unwrap();
    let new_signer = MlsSigner {
        key: Zeroizing::new(private),
        scheme,
    };
    let credential = alice.group.own_leaf_node().unwrap().credential().clone();
    let (commit, _, _) = alice
        .group
        .self_update_with_new_signer(
            &alice.provider,
            &alice.signer,
            NewSignerBundle {
                signer: &new_signer,
                credential_with_key: CredentialWithKey {
                    credential,
                    signature_key: public.clone().into(),
                },
            },
            LeafNodeParameters::default(),
        )
        .unwrap()
        .into_messages();
    alice.group.merge_pending_commit(&alice.provider).unwrap();
    let (state, _) = mls_process_commit(
        bob_state,
        bob_bundle.clone(),
        commit.tls_serialize_detached().unwrap(),
    )
    .unwrap();
    bob_state = state;

    let held = leaf_key(&bob_state, &bob_bundle, 0);
    assert_ne!(
        held, old_key,
        "PLANT-H3-NEW-KEY: Bob still holds Alice's old signing key after her rotation"
    );
    assert_eq!(held, public, "Bob holds the key Alice rotated to");

    let signed_new = alice
        .group
        .create_message(&alice.provider, &new_signer, b"new key")
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    let (state, read, _) = decrypt_message(bob_state, bob_bundle.clone(), signed_new).unwrap();
    bob_state = state;
    assert_eq!(read, b"new key");

    let signed_old = alice
        .group
        .create_message(&alice.provider, &alice.signer, b"old key")
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    assert!(
        decrypt_message(bob_state, bob_bundle, signed_old).is_err(),
        "PLANT-H3-OLD-KEY-REFUSED: Bob read a message signed with Alice's old key after her rotation"
    );
}
