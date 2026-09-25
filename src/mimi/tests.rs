//! Cross-provider (MIMI) group-flow proofs: epoch sync across add/remove commits, the
//! mimiParticipantList AppSync roster proposal riding atomically with a commit, and the
//! self-contained Welcome (ratchet tree embedded, no out-of-band export) a foreign MIMI
//! implementation would byte-inspect.

#![allow(deprecated)] // legacy API coverage remains until its external caller migrates

use super::*;
use crate::mls::groups::{decrypt_message, encrypt_message, mls_process_commit};

#[test]
fn refreshed_mimi_key_package_keeps_appsync_adds_possible() {
    let now = now_secs();
    let (_, _, alice) = mimi_generate_identity("alice@as.test".into(), now).unwrap();
    let (_, _, bob) = mimi_generate_identity("bob@as.test".into(), now).unwrap();
    let (_, carol_kp, _) = mimi_generate_identity("carol@as.test".into(), now).unwrap();
    let (_, bob_kp, _) = crate::mls::groups::regenerate_key_package(bob, now + 1).unwrap();
    let group = mimi_create_group("refresh-caps".into(), alice.clone()).unwrap();
    let (group, _, _) =
        mimi_add_member_commit_appsync(group, alice.clone(), bob_kp, vec![1]).unwrap();
    mimi_add_member_commit_appsync(group, alice, carol_kp, vec![2])
        .expect("a refreshed MIMI leaf must still support the next AppSync proposal");
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64
}

/// An existing member advances its epoch after another member's Add/Remove commit, proven by a
/// successful decrypt at the new epoch. alice (committer) + bob (existing member) + carol (the
/// added-then-removed 3rd member) - the round trip behind the cross-provider add/remove flow.
#[test]
fn member_add_remove_commit_epoch_sync() {
    let now = now_secs();
    let (_aid, _akp, alice) = crate::identity::generate_identity("alice@mls.test".to_string(), now)
        .expect("generate alice");
    let (_bid, bob_kp, bob) =
        crate::identity::generate_identity("bob@mls.test".to_string(), now).expect("generate bob");
    let (_cid, carol_kp, carol) =
        crate::identity::generate_identity("carol@mls.test".to_string(), now)
            .expect("generate carol");

    let alice_s = mimi_create_group("mls_group".to_string(), alice.clone()).expect("create_group");
    let (alice_s, welcome_bob) = mimi_add_member(alice_s, alice.clone(), bob_kp).expect("add bob");
    let (bob_s, _) =
        mimi_process_welcome_non_atomic(welcome_bob, bob.clone(), Vec::new(), String::new())
            .expect("bob joins");

    let (alice_s, welcome_carol, add_commit) =
        mimi_add_member_commit(alice_s, alice.clone(), carol_kp).expect("add carol");
    let (carol_s, _) =
        mimi_process_welcome_non_atomic(welcome_carol, carol.clone(), Vec::new(), String::new())
            .expect("carol joins");
    let (bob_s, _sender) =
        mls_process_commit(bob_s, bob.clone(), add_commit).expect("bob processes add");

    // Proof of epoch sync after ADD: alice encrypts at the new epoch; bob and carol both decrypt.
    let msg = b"after-add message".to_vec();
    let (alice_s, ct) = encrypt_message(alice_s, alice.clone(), msg.clone()).expect("encrypt");
    let (bob_s, pt_bob, _sender) =
        decrypt_message(bob_s, bob.clone(), ct.clone()).expect("bob decrypt");
    let (_carol_s, pt_carol, _sender) =
        decrypt_message(carol_s, carol.clone(), ct).expect("carol decrypt");
    assert_eq!(pt_bob, msg, "bob must decrypt at the post-add epoch");
    assert_eq!(
        pt_carol, msg,
        "carol must decrypt as a freshly-added member"
    );

    // Remove carol; bob must process the commit and stay synced.
    let (alice_s, rm_commit) =
        mimi_remove_member_commit(alice_s, alice.clone(), "carol@mls.test".to_string())
            .expect("remove carol");
    let (bob_s, _sender) =
        mls_process_commit(bob_s, bob.clone(), rm_commit).expect("bob processes remove");

    let msg2 = b"after-remove message".to_vec();
    let (_alice_s, ct2) = encrypt_message(alice_s, alice.clone(), msg2.clone()).expect("encrypt2");
    let (_bob_s, pt_bob2, _sender) = decrypt_message(bob_s, bob, ct2).expect("bob decrypt2");
    assert_eq!(pt_bob2, msg2, "bob must decrypt at the post-remove epoch");
}

#[test]
fn indexed_mimi_remove_is_fenced_to_the_observed_leaf() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        mimi_generate_identity("alice-indexed@as.test".to_string(), now).expect("generate alice");
    let (_bid, bob_kp, bob) =
        mimi_generate_identity("bob-indexed@as.test".to_string(), now).expect("generate bob");
    let (_cid, carol_kp, _carol) =
        mimi_generate_identity("carol-indexed@as.test".to_string(), now).expect("generate carol");
    let state = mimi_create_group("indexed_mimi".to_string(), alice.clone()).expect("create");
    let (state, welcome_bob) = mimi_add_member(state, alice.clone(), bob_kp).expect("add bob");
    let (bob_state, _) =
        mimi_process_welcome_non_atomic(welcome_bob, bob.clone(), Vec::new(), String::new())
            .expect("bob joins");
    let (state, _welcome_carol, add_commit) =
        mimi_add_member_commit(state, alice.clone(), carol_kp).expect("add carol");
    let (bob_state, _sender) =
        mls_process_commit(bob_state, bob.clone(), add_commit).expect("bob processes add");
    let carol = crate::mls::groups::list_members_with_indices(state.clone())
        .expect("list members")
        .into_iter()
        .find(|member| member.credential_identity == b"carol-indexed@as.test")
        .expect("find carol leaf");

    let mismatch = mimi_remove_member_commit_by_leaf_index(
        state.clone(),
        alice.clone(),
        carol.leaf_index,
        "00".repeat(32),
    )
    .expect_err("a stale leaf/key observation must fail closed");
    assert!(mismatch.to_string().contains("expected signature key"));

    let (state, remove_commit) = mimi_remove_member_commit_by_leaf_index(
        state,
        alice.clone(),
        carol.leaf_index,
        carol.signature_key.clone(),
    )
    .expect("remove exact leaf");
    let (_bob_state, _sender) =
        mls_process_commit(bob_state, bob, remove_commit).expect("bob processes remove");
    assert!(!crate::mls::groups::list_members_with_indices(state)
        .expect("list repaired group")
        .iter()
        .any(|member| member.signature_key == carol.signature_key));
}

/// Add/remove commits can carry a mimiParticipantList roster custom proposal IN the commit
/// (atomic with the MLS op); an existing member's `mls_process_commit_appsync` must surface the
/// roster payload AND stay epoch-synced. Uses `mimi_generate_identity` so every member
/// advertises the custom proposal type (else the commit wouldn't validate).
#[test]
fn member_add_remove_appsync_roster_round_trip() {
    let now = now_secs();
    let (_a, _akp, alice) =
        mimi_generate_identity("alice@as.test".to_string(), now).expect("generate alice");
    let (_b, bob_kp, bob) =
        mimi_generate_identity("bob@as.test".to_string(), now).expect("generate bob");
    let (_c, carol_kp, carol) =
        mimi_generate_identity("carol@as.test".to_string(), now).expect("generate carol");

    let alice_s = mimi_create_group("as_group".to_string(), alice.clone()).expect("create_group");
    let (alice_s, welcome_bob) = mimi_add_member(alice_s, alice.clone(), bob_kp).expect("add bob");
    let (bob_s, _) =
        mimi_process_welcome_non_atomic(welcome_bob, bob.clone(), Vec::new(), String::new())
            .expect("bob joins");

    let roster_add = vec![0x81, 0x81, 0x00]; // opaque payload; surfacing correctness is what matters
    let (alice_s, welcome_carol, add_commit) =
        mimi_add_member_commit_appsync(alice_s, alice.clone(), carol_kp, roster_add.clone())
            .expect("add carol with roster");
    let prepared =
        prepare_welcome_retirement(welcome_carol, carol.clone(), Vec::new(), String::new())
            .expect("prepare carol Welcome retirement");
    let (carol_s, _) = complete_welcome(prepared).expect("carol joins");
    let (bob_s, surfaced_add, _sender) =
        mls_process_commit_appsync(bob_s, bob.clone(), add_commit).expect("bob processes add");
    assert_eq!(
        surfaced_add, roster_add,
        "bob must surface the roster payload carried in the add commit"
    );

    // Epoch sync after add (the roster rode WITH the Add): alice -> bob+carol decrypt.
    let msg = b"after-appsync-add".to_vec();
    let (alice_s, ct) = encrypt_message(alice_s, alice.clone(), msg.clone()).expect("encrypt");
    let (bob_s, pt_bob, _sender) =
        decrypt_message(bob_s, bob.clone(), ct.clone()).expect("bob decrypt");
    let (_carol_s, pt_carol, _sender) =
        decrypt_message(carol_s, carol.clone(), ct).expect("carol decrypt");
    assert_eq!(pt_bob, msg);
    assert_eq!(pt_carol, msg);

    let roster_rem = vec![0x81, 0x82, 0x01];
    let (alice_s, rm_commit) = mimi_remove_member_commit_appsync(
        alice_s,
        alice.clone(),
        "carol@as.test".to_string(),
        roster_rem.clone(),
    )
    .expect("remove carol with roster");
    let (bob_s, surfaced_rem, _sender) =
        mls_process_commit_appsync(bob_s, bob.clone(), rm_commit).expect("bob processes remove");
    assert_eq!(
        surfaced_rem, roster_rem,
        "bob must surface the roster payload carried in the remove commit"
    );

    let msg2 = b"after-appsync-remove".to_vec();
    let (_alice_s, ct2) = encrypt_message(alice_s, alice, msg2.clone()).expect("encrypt2");
    let (_bob_s, pt_bob2, _sender) = decrypt_message(bob_s, bob, ct2).expect("bob decrypt2");
    assert_eq!(
        pt_bob2, msg2,
        "bob stays epoch-synced after the appsync remove"
    );
}

/// The joiner receives ONLY the `MlsMessage(Welcome)` - no out-of-band ratchet tree - and must
/// still join and exchange messages bidirectionally. Proves `use_ratchet_tree_extension(true)`
/// embeds the tree and `mimi_process_welcome_non_atomic` reads it from the Welcome alone. This is the
/// conformant wire form a foreign MIMI implementation would byte-inspect.
#[test]
fn mimi_self_contained_welcome_round_trip() {
    let now = now_secs();
    let (_snd_id, _snd_kp, snd_bundle) =
        crate::identity::generate_identity("alice_mimi@acme-demo.org".to_string(), now)
            .expect("generate sender");
    let (_rcv_id, rcv_kp, rcv_bundle) =
        crate::identity::generate_identity("researcher@havenmessenger.com".to_string(), now)
            .expect("generate receiver");

    let snd_state =
        mimi_create_group("mimi_demo_group".to_string(), snd_bundle.clone()).expect("create");
    let (snd_state_2, welcome_msg) =
        mimi_add_member(snd_state, snd_bundle.clone(), rcv_kp).expect("add receiver");

    let (rcv_state, _) = mimi_process_welcome_non_atomic(
        welcome_msg.clone(),
        rcv_bundle.clone(),
        Vec::new(),
        String::new(),
    )
    .expect("receiver joins");

    let m1 = b"hello over MIMI (self-contained welcome)".to_vec();
    let (_snd_state_3, ct1) =
        encrypt_message(snd_state_2, snd_bundle, m1.clone()).expect("sender encrypts");
    let (rcv_state_2, p1, _sender) =
        decrypt_message(rcv_state, rcv_bundle.clone(), ct1).expect("receiver decrypts");
    assert_eq!(p1, m1, "receiver must decrypt the sender's message");

    let m2 = b"reply: received over MIMI".to_vec();
    let (_rcv_state_3, ct2) =
        encrypt_message(rcv_state_2, rcv_bundle, m2).expect("receiver encrypts reply");
    assert!(!ct2.is_empty(), "receiver produced a reply ciphertext");

    // The relayed object is an MlsMessage(Welcome) - the conformant wire form.
    use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn};
    use tls_codec::Deserialize as TlsDeserialize;
    let mut s = welcome_msg.as_slice();
    let parsed = MlsMessageIn::tls_deserialize(&mut s).expect("welcome is a valid MlsMessage");
    assert!(
        matches!(parsed.extract(), MlsMessageBodyIn::Welcome(_)),
        "the relayed object must be an MlsMessage(Welcome)"
    );
}

// ===========================================================================
// external_senders + INV-MLS-001b clause-2 acceptance + the wire_format_policy knob. See
// `crate::profile`'s module doc for the policy this acceptance path is designed against.
// ===========================================================================

/// Build a raw (signer, public-key) pair from a `generate_identity`-produced bundle, for
/// constructing an external-sender-signed proposal directly against openmls's API. The "hub" is
/// never a group member, so it has no `GroupState` of its own, only a signing identity.
fn raw_signer_and_pubkey(bundle_bytes: &[u8]) -> (MlsSigner, SignaturePublicKey) {
    let identity: IdentityBundle = serde_json::from_slice(bundle_bytes).expect("valid bundle");
    let signer = MlsSigner {
        key: Zeroizing::new(identity.private_key.clone()),
        scheme: identity.signature_scheme,
    };
    let pubkey = SignaturePublicKey::try_from(identity.public_key_bytes.clone())
        .expect("valid public key bytes");
    (signer, pubkey)
}

/// Load a member's current `(GroupId, epoch)` from their serialized `GroupState` - mirrors
/// the load dance every `mimi_*` function does internally (fresh provider, storage_map restored,
/// `MlsGroup::load`), needed here only to construct a well-formed external proposal in tests (real
/// production code never needs to peek at the epoch from outside `mimi_accept_external_remove_proposal`
/// itself).
fn group_id_and_epoch(state_bytes: &[u8]) -> (GroupId, GroupEpoch) {
    let state: GroupState = serde_json::from_slice(state_bytes).expect("valid state");
    let provider = OpenMlsRustCrypto::default();
    {
        let mut values = provider.storage().values.write().unwrap();
        *values = state.storage_map.clone().into_iter().collect();
    }
    let group_id = GroupId::from_slice(&state.group_id);
    let group = MlsGroup::load(provider.storage(), &group_id)
        .expect("load group")
        .expect("group exists in storage");
    (group.group_id().clone(), group.epoch())
}

/// Happy path: a mimi-lane group created with `mimi_create_group_with_external_senders` names the
/// hub as its one external sender; the hub signs a Remove for bob; alice (an existing member)
/// accepts it via `mimi_accept_external_remove_proposal` and the resulting commit removes bob.
/// Proven by bob no longer being a member post-commit (checked by attempting mimi_process_commit-shaped
/// epoch sync via encrypt/decrypt would need bob's own state, so instead this proves membership count
/// directly against the reloaded group, the same technique `group_id_and_epoch` above uses).
#[test]
fn hub_signed_remove_is_accepted_and_removes_the_member() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@w3.test".to_string(), now).expect("alice");
    let (_bid, bob_kp, _bob) =
        crate::identity::generate_identity("bob@w3.test".to_string(), now).expect("bob");
    let (_hid, _hkp, hub_bundle) =
        crate::identity::generate_identity("hub@w3.test".to_string(), now).expect("hub");
    let (hub_signer, hub_pubkey) = raw_signer_and_pubkey(&hub_bundle);

    let alice_s = mimi_create_group_with_external_senders(
        "w3_group".to_string(),
        alice.clone(),
        hub_pubkey.as_slice().to_vec(),
        "hub@w3.test".to_string(),
    )
    .expect("create group with external_senders");
    let (alice_s, _welcome_bob) = mimi_add_member(alice_s, alice.clone(), bob_kp).expect("add bob");

    let (group_id, epoch) = group_id_and_epoch(&alice_s);
    let remove_out = ExternalProposal::new_remove::<OpenMlsRustCrypto>(
        LeafNodeIndex::new(1),
        group_id,
        epoch,
        &hub_signer,
        SenderExtensionIndex::new(0),
    )
    .expect("hub constructs a valid external Remove proposal");
    let remove_bytes = remove_out
        .tls_serialize_detached()
        .expect("serialize external proposal");

    let (new_alice_s, commit_bytes) =
        mimi_accept_external_remove_proposal(alice_s, alice, remove_bytes)
            .expect("accept the hub-signed Remove");
    assert!(!commit_bytes.is_empty(), "must produce a real commit");

    let (_gid, _epoch2) = group_id_and_epoch(&new_alice_s);
    let state: GroupState = serde_json::from_slice(&new_alice_s).expect("valid state");
    let provider = OpenMlsRustCrypto::default();
    {
        let mut values = provider.storage().values.write().unwrap();
        *values = state.storage_map.clone().into_iter().collect();
    }
    let group_id2 = GroupId::from_slice(&state.group_id);
    let group = MlsGroup::load(provider.storage(), &group_id2)
        .expect("load")
        .expect("exists");
    assert_eq!(
        group.members().count(),
        1,
        "bob must be removed, only alice remains"
    );
}

/// Happy path: bob joins a hub-mediated group and pins the hub credential he expects. The
/// join must succeed when the expected signature key + identity match the group's real (single)
/// `external_senders` entry.
#[test]
fn mimi_process_welcome_pins_correct_hub_succeeds() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@pin.test".to_string(), now).expect("alice");
    let (_bid, bob_kp, bob) =
        crate::identity::generate_identity("bob@pin.test".to_string(), now).expect("bob");
    let (_hid, _hkp, hub_bundle) =
        crate::identity::generate_identity("hub@pin.test".to_string(), now).expect("hub");
    let (_hub_signer, hub_pubkey) = raw_signer_and_pubkey(&hub_bundle);
    let hub_sig_bytes = hub_pubkey.as_slice().to_vec();

    let alice_s = mimi_create_group_with_external_senders(
        "pin_group".to_string(),
        alice.clone(),
        hub_sig_bytes.clone(),
        "hub@pin.test".to_string(),
    )
    .expect("create group with external_senders");
    let (_alice_s, welcome_bob) = mimi_add_member(alice_s, alice, bob_kp).expect("add bob");

    let joined = mimi_process_welcome_non_atomic(
        welcome_bob,
        bob,
        hub_sig_bytes,
        "hub@pin.test".to_string(),
    );
    assert!(
        joined.is_ok(),
        "join must succeed when the expected hub credential matches: {:?}",
        joined.err()
    );
}

/// The defect being closed: bob expects a DIFFERENT hub than the one actually named in the
/// group's `external_senders` extension (same suite, valid Welcome, valid signature - just the
/// wrong pinned identity). The join must fail closed, not silently succeed with the wrong hub
/// treated as trusted.
#[test]
fn mimi_process_welcome_rejects_wrong_hub_signature_key() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@pinwrong.test".to_string(), now).expect("alice");
    let (_bid, bob_kp, bob) =
        crate::identity::generate_identity("bob@pinwrong.test".to_string(), now).expect("bob");
    let (_hid, _hkp, real_hub_bundle) =
        crate::identity::generate_identity("hub@pinwrong.test".to_string(), now).expect("hub");
    let (_real_hub_signer, real_hub_pubkey) = raw_signer_and_pubkey(&real_hub_bundle);
    // An UNRELATED identity - what bob mistakenly (or is attacker-tricked to) expect.
    let (_wid, _wkp, wrong_hub_bundle) =
        crate::identity::generate_identity("attacker-hub@pinwrong.test".to_string(), now)
            .expect("wrong hub");
    let (_wrong_hub_signer, wrong_hub_pubkey) = raw_signer_and_pubkey(&wrong_hub_bundle);

    let alice_s = mimi_create_group_with_external_senders(
        "pin_wrong_group".to_string(),
        alice.clone(),
        real_hub_pubkey.as_slice().to_vec(),
        "hub@pinwrong.test".to_string(),
    )
    .expect("create group with external_senders");
    let (_alice_s, welcome_bob) = mimi_add_member(alice_s, alice, bob_kp).expect("add bob");

    let joined = mimi_process_welcome_non_atomic(
        welcome_bob,
        bob,
        wrong_hub_pubkey.as_slice().to_vec(),
        "hub@pinwrong.test".to_string(),
    );
    assert!(
        joined.is_err(),
        "join must fail closed when the expected hub signature key does not match the group's real external_senders entry"
    );
}

/// The identity string is part of the pinned entry too - a matching signature key but a
/// DIFFERENT expected credential identity must also fail closed (the whole `ExternalSender`
/// entry, not just the key, is what's pinned).
#[test]
fn mimi_process_welcome_rejects_wrong_hub_credential_identity() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@pinid.test".to_string(), now).expect("alice");
    let (_bid, bob_kp, bob) =
        crate::identity::generate_identity("bob@pinid.test".to_string(), now).expect("bob");
    let (_hid, _hkp, hub_bundle) =
        crate::identity::generate_identity("hub@pinid.test".to_string(), now).expect("hub");
    let (_hub_signer, hub_pubkey) = raw_signer_and_pubkey(&hub_bundle);

    let alice_s = mimi_create_group_with_external_senders(
        "pin_id_group".to_string(),
        alice.clone(),
        hub_pubkey.as_slice().to_vec(),
        "hub@pinid.test".to_string(),
    )
    .expect("create group with external_senders");
    let (_alice_s, welcome_bob) = mimi_add_member(alice_s, alice, bob_kp).expect("add bob");

    let joined = mimi_process_welcome_non_atomic(
        welcome_bob,
        bob,
        hub_pubkey.as_slice().to_vec(),
        "not-the-real-hub@pinid.test".to_string(),
    );
    assert!(
        joined.is_err(),
        "join must fail closed when the expected hub credential identity does not match, even with the right signature key"
    );
}

/// Sanity: the empty-bytes opt-out still joins a HUB-LESS group (the current `mimi_create_group`
/// production path never sets `external_senders`) - the pin check must not regress the common case.
#[test]
fn mimi_process_welcome_skips_pin_check_for_hubless_group() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@nohub.test".to_string(), now).expect("alice");
    let (_bid, bob_kp, bob) =
        crate::identity::generate_identity("bob@nohub.test".to_string(), now).expect("bob");

    let alice_s =
        mimi_create_group("nohub_group".to_string(), alice.clone()).expect("create plain group");
    let (_alice_s, welcome_bob) = mimi_add_member(alice_s, alice, bob_kp).expect("add bob");

    let joined = mimi_process_welcome_non_atomic(welcome_bob, bob, Vec::new(), String::new());
    assert!(
        joined.is_ok(),
        "empty expected-hub bytes must skip the pin check for a hub-less group: {:?}",
        joined.err()
    );
}

/// Violating case: the hub tries to sign an Add instead of Remove. openmls stages it (it's a validly
/// signed external proposal from the allowlisted sender), but `mimi_accept_external_remove_proposal`
/// must refuse it: the allowlist-not-denylist gate (INV-MLS-001b clause 2(c)).
#[test]
fn external_add_proposal_from_the_hub_is_refused_by_type() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@w3b.test".to_string(), now).expect("alice");
    let (_cid, carol_kp, _carol) =
        crate::identity::generate_identity("carol@w3b.test".to_string(), now).expect("carol");
    let (_hid, _hkp, hub_bundle) =
        crate::identity::generate_identity("hub@w3b.test".to_string(), now).expect("hub");
    let (hub_signer, hub_pubkey) = raw_signer_and_pubkey(&hub_bundle);

    let alice_s = mimi_create_group_with_external_senders(
        "w3b_group".to_string(),
        alice.clone(),
        hub_pubkey.as_slice().to_vec(),
        "hub@w3b.test".to_string(),
    )
    .expect("create group with external_senders");

    let mut kp_slice = carol_kp.as_slice();
    let carol_kp_in = KeyPackageIn::tls_deserialize(&mut kp_slice).expect("deserialize carol KP");
    let provider_for_validation = OpenMlsRustCrypto::default();
    let carol_kp_validated = carol_kp_in
        .validate(provider_for_validation.crypto(), ProtocolVersion::Mls10)
        .expect("validate carol KP");

    let (group_id, epoch) = group_id_and_epoch(&alice_s);
    let add_out = ExternalProposal::new_add::<OpenMlsRustCrypto>(
        carol_kp_validated,
        group_id,
        epoch,
        &hub_signer,
        SenderExtensionIndex::new(0),
    )
    .expect("hub constructs a validly-signed external Add proposal");
    let add_bytes = add_out
        .tls_serialize_detached()
        .expect("serialize external proposal");

    let err = mimi_accept_external_remove_proposal(alice_s, alice, add_bytes)
        .expect_err("an external Add must be refused, Remove-only allowlist");
    assert!(
        err.to_string().contains("not allowlisted"),
        "refusal must be the type-allowlist error, got: {err}"
    );
}

/// Violating case: a signer NOT in the extension. openmls itself refuses this at `process_message`
/// (before `mimi_accept_external_remove_proposal`'s own checks ever run), proving the rejection
/// happens at the real trust boundary, not merely inside our wrapper.
#[test]
fn external_remove_from_an_unlisted_sender_is_refused_by_openmls_itself() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@w3c.test".to_string(), now).expect("alice");
    let (_bid, bob_kp, _bob) =
        crate::identity::generate_identity("bob@w3c.test".to_string(), now).expect("bob");
    let (_hid, _hkp, hub_bundle) =
        crate::identity::generate_identity("hub@w3c.test".to_string(), now).expect("hub");
    let (_hub_signer, hub_pubkey) = raw_signer_and_pubkey(&hub_bundle);
    // A rogue identity, NOT named in the group's external_senders extension.
    let (_rid, _rkp, rogue_bundle) =
        crate::identity::generate_identity("rogue@w3c.test".to_string(), now).expect("rogue");
    let (rogue_signer, _rogue_pubkey) = raw_signer_and_pubkey(&rogue_bundle);

    let alice_s = mimi_create_group_with_external_senders(
        "w3c_group".to_string(),
        alice.clone(),
        hub_pubkey.as_slice().to_vec(),
        "hub@w3c.test".to_string(),
    )
    .expect("create group with external_senders");
    let (alice_s, _welcome_bob) = mimi_add_member(alice_s, alice.clone(), bob_kp).expect("add bob");

    let (group_id, epoch) = group_id_and_epoch(&alice_s);
    let rogue_remove_out = ExternalProposal::new_remove::<OpenMlsRustCrypto>(
        LeafNodeIndex::new(1),
        group_id,
        epoch,
        &rogue_signer,
        SenderExtensionIndex::new(0), // rogue claims index 0, but doesn't hold that key
    )
    .expect("rogue constructs a (syntactically valid, wrongly-keyed) external Remove proposal");
    let rogue_bytes = rogue_remove_out
        .tls_serialize_detached()
        .expect("serialize external proposal");

    let err = mimi_accept_external_remove_proposal(alice_s, alice, rogue_bytes)
        .expect_err("a signer not in the extension must be refused by openmls itself");
    assert!(
        err.to_string()
            .contains("Error processing external proposal"),
        "refusal must surface as a process_message failure (openmls's own validation), got: {err}"
    );
}

/// `mimi_accept_external_remove_proposal` is only meant to receive standalone external
/// proposals - but nothing stops a caller from accidentally routing a real application message
/// into it. Before the fix, the catch-all error arm `Debug`-formatted the whole
/// `ProcessedMessageContent`, and `ApplicationMessage`'s `Debug` impl includes its DECRYPTED byte
/// payload - so a caller that logs this error would leak plaintext. Bob sends alice a real
/// application message containing a distinctive marker string; alice mis-routes it into this
/// entry point; the call must fail (wrong message type) AND the error string must NOT contain the
/// marker anywhere.
#[test]
fn mimi_accept_external_remove_proposal_does_not_leak_plaintext_on_wrong_message_type() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@leak.test".to_string(), now).expect("alice");
    let (_bid, bob_kp, bob) =
        crate::identity::generate_identity("bob@leak.test".to_string(), now).expect("bob");

    let alice_s = mimi_create_group("leak_group".to_string(), alice.clone()).expect("create");
    let (alice_s, welcome_bob) = mimi_add_member(alice_s, alice.clone(), bob_kp).expect("add bob");
    let (bob_s, _) =
        mimi_process_welcome_non_atomic(welcome_bob, bob.clone(), Vec::new(), String::new())
            .expect("bob joins");

    const SECRET_MARKER: &str = "SECRET-PLAINTEXT-MARKER-DO-NOT-LEAK";
    let (_bob_s, ct) =
        encrypt_message(bob_s, bob, SECRET_MARKER.as_bytes().to_vec()).expect("bob encrypts");

    let err = mimi_accept_external_remove_proposal(alice_s, alice, ct)
        .expect_err("a real application message must be refused, not treated as a proposal");
    let err_string = err.to_string();
    assert!(
        !err_string.contains(SECRET_MARKER),
        "the error must never contain the decrypted plaintext marker, got: {err_string}"
    );
    assert!(
        err_string.contains("ApplicationMessage"),
        "the error should still name the variant TYPE (just not its content), got: {err_string}"
    );
}

/// Structural regression pin: a NATIVE-lane group (no `ExternalSendersExtension` at all, built via
/// `mimi_create_group`, not `_with_external_senders`) must refuse ANY external proposal, because
/// openmls has no extension to validate the sender against
/// (`NoExternalSendersExtension`/`UnauthorizedExternalSender`). Proves the native lane's protection
/// is structural (extension absence), not a policy check this function could get wrong.
#[test]
fn native_lane_group_refuses_any_external_proposal_structurally() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@w3d.test".to_string(), now).expect("alice");
    let (_bid, bob_kp, _bob) =
        crate::identity::generate_identity("bob@w3d.test".to_string(), now).expect("bob");
    let (_hid, _hkp, hub_bundle) =
        crate::identity::generate_identity("hub@w3d.test".to_string(), now).expect("hub");
    let (hub_signer, _hub_pubkey) = raw_signer_and_pubkey(&hub_bundle);

    // Plain mimi_create_group: NO external_senders extension (this is what protects the native
    // lane; native-lane groups go through crate::mls::groups::create_group, an entirely separate
    // function, but this test proves the *extension-absence* protection generically).
    let alice_s = mimi_create_group("w3d_group".to_string(), alice.clone()).expect("create group");
    let (alice_s, _welcome_bob) = mimi_add_member(alice_s, alice.clone(), bob_kp).expect("add bob");

    let (group_id, epoch) = group_id_and_epoch(&alice_s);
    let remove_out = ExternalProposal::new_remove::<OpenMlsRustCrypto>(
        LeafNodeIndex::new(1),
        group_id,
        epoch,
        &hub_signer,
        SenderExtensionIndex::new(0),
    )
    .expect("hub constructs a syntactically valid external Remove proposal");
    let remove_bytes = remove_out
        .tls_serialize_detached()
        .expect("serialize external proposal");

    let err = mimi_accept_external_remove_proposal(alice_s, alice, remove_bytes)
        .expect_err("a group with no ExternalSendersExtension must refuse any external proposal");
    assert!(
        err.to_string().contains("Error processing external proposal"),
        "refusal must surface as a process_message failure (no extension to validate against), got: {err}"
    );
}

/// Build `(MlsSigner, CredentialWithKey)` from a `generate_identity`-produced bundle, for
/// constructing a real `MlsGroup` directly against openmls's own API (bypassing the `mimi_*`/
/// `crate::mls::groups::*` wrapper functions entirely). Needed here because the wire-format
/// assertion below inspects `MlsMessageOut::body()` on the UN-serialized Commit object (to read
/// the actual `PublicMessage`/`PrivateMessage` wire variant) - every wrapper function returns
/// only TLS-serialized bytes, never the pre-serialization object, so this test drives openmls
/// directly instead, as `spec_capability_proof.rs` (the interop repo's sibling proof
/// module) does for its own tests.
fn signer_and_cwk(bundle_bytes: &[u8]) -> (MlsSigner, CredentialWithKey) {
    let mut identity: IdentityBundle = serde_json::from_slice(bundle_bytes).expect("valid bundle");
    let signer = MlsSigner {
        key: Zeroizing::new(std::mem::take(&mut identity.private_key)),
        scheme: identity.signature_scheme,
    };
    let public_key = SignaturePublicKey::try_from(std::mem::take(&mut identity.public_key_bytes))
        .expect("valid public key bytes");
    let credential = BasicCredential::new(std::mem::take(&mut identity.user_id).into_bytes());
    let cwk = CredentialWithKey {
        credential: credential.into(),
        signature_key: public_key,
    };
    (signer, cwk)
}

/// Build an AppSync-capable group without the optional GroupInfo ratchet-tree extension. This mirrors
/// the persisted/reloaded configuration gap that the AppSync Welcome bundle must tolerate.
fn mimi_group_without_embedded_ratchet_tree(group_id: &str, bundle_bytes: &[u8]) -> Vec<u8> {
    let mut identity: IdentityBundle = serde_json::from_slice(bundle_bytes).expect("valid bundle");
    let provider = OpenMlsRustCrypto::default();
    let signer = MlsSigner {
        key: Zeroizing::new(std::mem::take(&mut identity.private_key)),
        scheme: identity.signature_scheme,
    };
    let public_key = SignaturePublicKey::try_from(std::mem::take(&mut identity.public_key_bytes))
        .expect("valid public key bytes");
    let credential = BasicCredential::new(std::mem::take(&mut identity.user_id).into_bytes());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: public_key,
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(crate::suite_policy::mls_generation_suite())
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .capabilities(mimi_appsync_capabilities())
        .build();
    let group = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &config,
        GroupId::from_slice(group_id.as_bytes()),
        credential_with_key,
    )
    .expect("create group without embedded ratchet tree");
    let storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };
    crate::mls::zeroizing_json(&GroupState {
        group_id: group.group_id().to_vec(),
        storage_map,
    })
    .expect("serialize group state")
    .to_vec()
}

/// An AppSync Welcome still joins when its optional embedded tree is absent: the sender explicitly
/// bundles the post-commit tree and the two-phase receiver supplies it to OpenMLS.
#[test]
fn appsync_welcome_bundle_supplies_missing_ratchet_tree() {
    let now = now_secs();
    let (_a, _akp, alice) =
        mimi_generate_identity("alice@bundle-tree.test".to_string(), now).expect("alice");
    let (_b, bob_kp, bob) =
        mimi_generate_identity("bob@bundle-tree.test".to_string(), now).expect("bob");
    let alice_state = mimi_group_without_embedded_ratchet_tree("bundle-tree", &alice);
    let (alice_state, welcome_payload, _commit) =
        mimi_add_member_commit_appsync(alice_state, alice.clone(), bob_kp, vec![0x81, 0x81, 0x00])
            .expect("add bob");

    let (raw_welcome, ratchet_tree): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&welcome_payload).expect("Welcome payload is a bundle");
    assert!(
        !ratchet_tree.is_empty(),
        "the AppSync Welcome bundle must carry an explicit ratchet tree"
    );

    // The same Welcome cannot join from its optional embedded extension: this group was deliberately
    // created without one. Use a copy of Bob's bundle so this negative control cannot spend the real
    // KeyPackage used by the succeeding crash-atomic path below.
    let identity: IdentityBundle = serde_json::from_slice(&bob).expect("valid bob bundle");
    let provider = OpenMlsRustCrypto::default();
    {
        let mut values = provider.storage().values.write().unwrap();
        *values = identity.storage_map.clone().into_iter().collect();
    }
    let message = MlsMessageIn::tls_deserialize_exact(raw_welcome.as_slice())
        .expect("raw Welcome is TLS framed");
    let welcome = match message.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => panic!("bundle's first element must be a Welcome"),
    };
    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    assert!(
        StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None).is_err(),
        "the missing embedded ratchet tree must reject an unbundled join"
    );

    let prepared =
        prepare_welcome_retirement(welcome_payload, bob.clone(), Vec::new(), String::new())
            .expect("phase 1 accepts the bundled Welcome");
    let (bob_state, _) =
        complete_welcome(prepared).expect("phase 2 joins with bundled ratchet tree");
    let message = b"explicit ratchet tree works".to_vec();
    let (_alice_state, ciphertext) =
        encrypt_message(alice_state, alice, message.clone()).expect("alice encrypts");
    let (_bob_state, plaintext, _sender) =
        decrypt_message(bob_state, bob, ciphertext).expect("bob decrypts");
    assert_eq!(plaintext, message);
}

/// Wire-knob KAT: a Lane::Mimi group's real Commit is PublicMessage-framed on the wire; a
/// Lane::Native group's stays PrivateMessage. Asserts the ACTUAL wire variant (`MlsMessageBodyOut`,
/// read directly off the `MlsMessageOut` - no serialize/deserialize round trip needed), not the
/// config value, per the contract's DONE=(b).
#[test]
fn mimi_lane_commit_is_publicmessage_native_lane_stays_privatemessage() {
    let now = now_secs();

    // Mimi lane.
    let (_aid, _akp, alice_bundle) =
        crate::identity::generate_identity("alice@wire.test".to_string(), now).expect("alice");
    let (alice_signer, alice_cwk) = signer_and_cwk(&alice_bundle);
    let (_bid, bob_kp_bytes, _bob) =
        crate::identity::generate_identity("bob@wire.test".to_string(), now).expect("bob");

    let mimi_provider = OpenMlsRustCrypto::default();
    let mimi_cfg = MlsGroupCreateConfig::builder()
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let mut mimi_group = MlsGroup::new_with_group_id(
        &mimi_provider,
        &alice_signer,
        &mimi_cfg,
        GroupId::from_slice(b"wire_mimi_group"),
        alice_cwk,
    )
    .expect("create mimi group");
    let mut bob_slice = bob_kp_bytes.as_slice();
    let bob_kp = KeyPackageIn::tls_deserialize(&mut bob_slice)
        .expect("deserialize bob kp")
        .validate(mimi_provider.crypto(), ProtocolVersion::Mls10)
        .expect("validate bob kp");
    let (mimi_commit, _welcome, _gi) = mimi_group
        .add_members(&mimi_provider, &alice_signer, &[bob_kp])
        .expect("mimi add commit");
    assert!(
        matches!(mimi_commit.body(), MlsMessageBodyOut::PublicMessage(_)),
        "a Lane::Mimi commit must be wire-framed as PublicMessage (hub-readable)"
    );

    // Native lane: unchanged, still PrivateMessage. The regression pin that the wire-knob change
    // above did not move the native lane's posture.
    let (_aid2, _akp2, alice2_bundle) =
        crate::identity::generate_identity("alice2@wire.test".to_string(), now).expect("alice2");
    let (alice2_signer, alice2_cwk) = signer_and_cwk(&alice2_bundle);
    let (_bid2, bob2_kp_bytes, _bob2) =
        crate::identity::generate_identity("bob2@wire.test".to_string(), now).expect("bob2");

    let native_provider = OpenMlsRustCrypto::default();
    let native_cfg = MlsGroupCreateConfig::builder()
        .wire_format_policy(WireFormatPolicy::default())
        .build();
    let mut native_group = MlsGroup::new_with_group_id(
        &native_provider,
        &alice2_signer,
        &native_cfg,
        GroupId::from_slice(b"wire_native_group"),
        alice2_cwk,
    )
    .expect("create native group");
    let mut bob2_slice = bob2_kp_bytes.as_slice();
    let bob2_kp = KeyPackageIn::tls_deserialize(&mut bob2_slice)
        .expect("deserialize bob2 kp")
        .validate(native_provider.crypto(), ProtocolVersion::Mls10)
        .expect("validate bob2 kp");
    let (native_commit, _welcome2, _gi2) = native_group
        .add_members(&native_provider, &alice2_signer, &[bob2_kp])
        .expect("native add commit");
    assert!(
        matches!(native_commit.body(), MlsMessageBodyOut::PrivateMessage(_)),
        "a native-lane commit must stay wire-framed as PrivateMessage (unchanged posture)"
    );
}

// ── size-bound: mimi-lane wire ingest rejects trailing bytes + oversize input ────────────

/// `mimi_add_member` rejects a real KeyPackage with one trailing byte appended
/// (`tls_deserialize_exact`, not `tls_deserialize`).
#[test]
fn mimi_add_member_rejects_trailing_bytes_key_package() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@trail.test".to_string(), now).expect("alice");
    let (_bid, mut bob_kp, _bob) =
        crate::identity::generate_identity("bob@trail.test".to_string(), now).expect("bob");
    let alice_s = mimi_create_group("trail_group".to_string(), alice.clone()).expect("create");

    bob_kp.push(0xCD);
    let result = mimi_add_member(alice_s, alice, bob_kp);
    assert!(
        result.is_err(),
        "mimi_add_member must reject a KeyPackage with a trailing byte"
    );
}

/// size-bound: `mimi_add_member` rejects an oversize KeyPackage buffer before attempting to
/// deserialize it.
#[test]
fn mimi_add_member_rejects_oversize_key_package() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@oversize.test".to_string(), now).expect("alice");
    let alice_s =
        mimi_create_group("oversize_mimi_group".to_string(), alice.clone()).expect("create");

    let oversized_kp = vec![0u8; crate::mls::MAX_MLS_WIRE_BYTES + 1];
    let result = mimi_add_member(alice_s, alice, oversized_kp);
    assert!(
        result.is_err(),
        "mimi_add_member must reject an oversize KeyPackage buffer"
    );
}

/// The MIMI-lane commit processor surfaces the COMMITTER's verified key alongside the roster
/// payload - the sender an Add's authorization is decided against on the cross-provider lane, and
/// the payload it must keep surfacing. Ground truth for each member's real key comes from
/// `mls_extract_signature_key` over that member's own KeyPackage, an independent route.
///
/// Mutation sensor: returning the added member or the processor instead of the committer reddens
/// the committer assertion; dropping the roster surfacing reddens the payload assertion.
#[test]
fn appsync_commit_surfaces_the_committer_and_still_surfaces_the_roster() {
    use crate::mls::groups::mls_extract_signature_key;
    let now = now_secs();
    let (_a, alice_kp, alice) =
        mimi_generate_identity("alice@as-snd.test".to_string(), now).expect("alice");
    let (_b, bob_kp, bob) =
        mimi_generate_identity("bob@as-snd.test".to_string(), now).expect("bob");
    let (_c, carol_kp, _carol) =
        mimi_generate_identity("carol@as-snd.test".to_string(), now).expect("carol");

    let alice_real = mls_extract_signature_key(alice_kp);
    let bob_real = mls_extract_signature_key(bob_kp.clone());
    let carol_real = mls_extract_signature_key(carol_kp.clone());

    let alice_s = mimi_create_group("as-snd-group".to_string(), alice.clone()).expect("create");
    let (alice_s, welcome_bob) = mimi_add_member(alice_s, alice.clone(), bob_kp).expect("add bob");
    let (bob_s, _) =
        mimi_process_welcome_non_atomic(welcome_bob, bob.clone(), Vec::new(), String::new())
            .expect("bob joins");

    let roster = vec![0x81, 0x83, 0x02];
    let (_alice_s, _welcome_carol, add_commit) =
        mimi_add_member_commit_appsync(alice_s, alice.clone(), carol_kp, roster.clone())
            .expect("add carol with roster");
    let (_bob_s, surfaced, sender) =
        mls_process_commit_appsync(bob_s, bob.clone(), add_commit).expect("bob processes add");

    assert_eq!(
        surfaced, roster,
        "the roster payload must still be surfaced"
    );
    assert_eq!(
        hex::encode_upper(&sender.signature_key),
        alice_real,
        "the surfaced sender must be alice, the committer"
    );
    assert_ne!(
        hex::encode_upper(&sender.signature_key),
        carol_real,
        "the surfaced sender must not be the member being added"
    );
    assert_ne!(
        hex::encode_upper(&sender.signature_key),
        bob_real,
        "the surfaced sender must not be the member processing the commit"
    );
}

/// RFC 9420 §16.8 single-use, on the AppSync Welcome path. A KeyPackage consumed by one AppSync
/// Welcome must not open a second one. `mimi_process_welcome_non_atomic` returns the caller's bundle with the
/// consumed KeyPackage retired, the same way the non-appsync `process_welcome` does, so replaying that
/// KeyPackage into a second Welcome is rejected. Without the retirement the second join would succeed
/// and this test would fail.
#[test]
fn an_appsync_consumed_keypackage_cannot_open_a_second_welcome() {
    let now = now_secs();
    let (_a, _akp, alice) =
        mimi_generate_identity("alice@ku.test".to_string(), now).expect("generate alice");
    let (_b, bob_kp, bob) =
        mimi_generate_identity("bob@ku.test".to_string(), now).expect("generate bob");
    // Opaque roster payload; the KeyPackage retirement, not roster surfacing, is what this asserts.
    let roster = vec![0x81, 0x81, 0x00];

    // Alice creates two AppSync groups and adds Bob to each with the SAME published KeyPackage.
    let g1 = mimi_create_group("ku-as-g1".to_string(), alice.clone()).expect("create g1");
    let (_g1, welcome1, _c1) =
        mimi_add_member_commit_appsync(g1, alice.clone(), bob_kp.clone(), roster.clone())
            .expect("add bob to g1");
    let g2 = mimi_create_group("ku-as-g2".to_string(), alice.clone()).expect("create g2");
    let (_g2, welcome2, _c2) =
        mimi_add_member_commit_appsync(g2, alice, bob_kp, roster).expect("add bob to g2");

    // Bob joins group 1; the returned bundle has the consumed KeyPackage retired.
    let (_state1, bob_after) =
        mimi_process_welcome_non_atomic(welcome1, bob, Vec::new(), String::new())
            .expect("first Welcome joins");

    // The field copy of the consumed KeyPackage's private material must be cleared, not merely retired
    // from storage_map: the second copy in key_package_bundle is otherwise recoverable at rest.
    let parsed: crate::mls::IdentityBundle =
        serde_json::from_slice(&bob_after).expect("deserialize retired bundle");
    assert!(
        parsed.key_package_bundle.is_none(),
        "the consumed KeyPackage's private bundle must be cleared from the AppSync-retired bundle"
    );

    // The consumed KeyPackage must not open the second Welcome (single-use).
    let second = mimi_process_welcome_non_atomic(welcome2, bob_after, Vec::new(), String::new());
    assert!(
        second.is_err(),
        "a KeyPackage consumed by one AppSync Welcome opened a second one - RFC 9420 §16.8 single-use \
         violated"
    );
}

/// A join REJECTED by the hub-pin still spends the KeyPackage. `mimi_process_welcome_non_atomic` retires the
/// consumed KeyPackage before the hub-pin decision and returns `Rejected` carrying the retired bundle,
/// so a second Welcome for that KeyPackage is refused. Without carrying the retirement on the error
/// path, the caller would keep the spent KeyPackage and a second Welcome could reuse it.
#[test]
fn an_appsync_welcome_retires_the_keypackage_even_when_the_hub_pin_rejects_the_join() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@rej.test".to_string(), now).expect("alice");
    let (_bid, bob_kp, bob) =
        crate::identity::generate_identity("bob@rej.test".to_string(), now).expect("bob");
    let (_hid, _hkp, real_hub) =
        crate::identity::generate_identity("hub@rej.test".to_string(), now).expect("hub");
    let (_wid, _wkp, wrong_hub) =
        crate::identity::generate_identity("attacker-hub@rej.test".to_string(), now)
            .expect("wrong hub");
    let (_rs, real_hub_pubkey) = raw_signer_and_pubkey(&real_hub);
    let (_ws, wrong_hub_pubkey) = raw_signer_and_pubkey(&wrong_hub);

    // Group 1 names the real hub; group 2 is where the same KeyPackage would be replayed.
    let g1 = mimi_create_group_with_external_senders(
        "rej-g1".to_string(),
        alice.clone(),
        real_hub_pubkey.as_slice().to_vec(),
        "hub@rej.test".to_string(),
    )
    .expect("create g1 with hub");
    let (_g1, welcome1) =
        mimi_add_member(g1, alice.clone(), bob_kp.clone()).expect("add bob to g1");
    let g2 = mimi_create_group("rej-g2".to_string(), alice.clone()).expect("create g2");
    let (_g2, welcome2) = mimi_add_member(g2, alice, bob_kp).expect("add bob to g2");

    // Bob joins g1 but expects the WRONG hub: the join is rejected, and the KeyPackage is retired anyway.
    let retired_bundle = match mimi_process_welcome_non_atomic(
        welcome1,
        bob,
        wrong_hub_pubkey.as_slice().to_vec(),
        "hub@rej.test".to_string(),
    ) {
        Err(MimiWelcomeError::Spent { retired_bundle, .. }) => retired_bundle,
        Err(MimiWelcomeError::Unspent(e)) => {
            panic!("expected a hub-pin Spent carrying the retired bundle, got Unspent: {e}")
        }
        Ok(_) => panic!("a hub-pin mismatch must reject the join, not return Ok"),
    };
    let parsed: crate::mls::IdentityBundle =
        serde_json::from_slice(&retired_bundle).expect("deserialize retired bundle");
    assert!(
        parsed.key_package_bundle.is_none(),
        "a rejected join must still retire the consumed KeyPackage's private bundle"
    );

    // The retired KeyPackage must not open the second Welcome.
    let second =
        mimi_process_welcome_non_atomic(welcome2, retired_bundle, Vec::new(), String::new());
    assert!(
        second.is_err(),
        "a KeyPackage spent by a rejected join opened a second Welcome - single-use hole on the error \
         path"
    );
}

/// The single-use hole the earlier fix missed: `StagedWelcome::new_from_welcome` deletes the KeyPackage
/// from provider storage BEFORE it finishes validating the Welcome, so a Welcome that opens far enough to
/// spend the KeyPackage but then fails a later decryption step must STILL return the retirement, or the
/// spent KeyPackage stays live and opens a second Welcome. A byte flipped in the tail of the Welcome
/// (inside the encrypted group info) survives TLS framing and the suite gate, is found and deleted by
/// `keys_for_welcome`, then fails to decrypt - the reachable post-spend failure. Mutation guard: routing
/// the post-spend error back through the bundle-less `Unspent` reddens the `Spent` match below.
#[test]
fn a_post_spend_welcome_failure_retires_the_keypackage() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@spend.test".to_string(), now).expect("alice");
    let (_bid, bob_kp, bob) =
        crate::identity::generate_identity("bob@spend.test".to_string(), now).expect("bob");

    // Two groups adding the SAME bob KeyPackage: welcome1 is corrupted to fail post-spend, welcome2 is
    // the valid replay attempt for the same KeyPackage.
    let g1 = mimi_create_group("spend-g1".to_string(), alice.clone()).expect("create g1");
    let (_g1, welcome1) =
        mimi_add_member(g1, alice.clone(), bob_kp.clone()).expect("add bob to g1");
    let g2 = mimi_create_group("spend-g2".to_string(), alice.clone()).expect("create g2");
    let (_g2, welcome2) = mimi_add_member(g2, alice, bob_kp).expect("add bob to g2");

    // Flip a byte in the tail (encrypted group info): the TLS structure and the suite still parse, the
    // KeyPackage is found and deleted, then the group-info AEAD fails - an Err AFTER the spend.
    let mut corrupted = welcome1;
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xff;

    let retired_bundle = match mimi_process_welcome_non_atomic(corrupted, bob, Vec::new(), String::new()) {
        Err(MimiWelcomeError::Spent { retired_bundle, .. }) => retired_bundle,
        Err(MimiWelcomeError::Unspent(e)) => panic!(
            "corruption landed BEFORE the spend (Unspent: {e}); this test needs a post-spend failure"
        ),
        Ok(_) => panic!("a corrupted Welcome must not open a group"),
    };
    let parsed: crate::mls::IdentityBundle =
        serde_json::from_slice(&retired_bundle).expect("deserialize retired bundle");
    assert!(
        parsed.key_package_bundle.is_none(),
        "a post-spend failure must still retire the consumed KeyPackage's private bundle"
    );

    // The retired KeyPackage must not open the second, valid Welcome.
    let second =
        mimi_process_welcome_non_atomic(welcome2, retired_bundle, Vec::new(), String::new());
    assert!(
        second.is_err(),
        "a KeyPackage spent by a failed join opened a second Welcome - single-use hole on the \
         post-spend error path"
    );
}

// ---------------------------------------------------------------------------
// Two-phase persist-before-spend Welcome: crash-atomic single-use (RFC 9420 §16.8).
// Each of these asserts a property a single-call join cannot provide: a single call builds the
// retirement only AFTER opening the Welcome, so obtaining a replay-blocking retirement requires using
// the KeyPackage - which IS the crash window. The two-phase API decouples the two.
// ---------------------------------------------------------------------------

/// The crash-atomicity crux. Run ONLY phase 1, then DROP the `PreparedWelcome` without ever calling
/// `complete_welcome` - a crash between the caller's persist and phase 2. The retirement the caller
/// persisted in phase 1 - built before the KeyPackage's private init key was ever used to open a
/// Welcome - must already block a replay of the same KeyPackage. A single-call join cannot express this:
/// there, a replay-blocking retirement only exists after the open. Mutation guard: a phase 1 that
/// returns the input bundle unretired lets `welcome2` open, reddening the final assert.
#[test]
fn prepared_retirement_blocks_replay_before_any_welcome_is_opened() {
    let now = now_secs();
    let (_a, _akp, alice) =
        mimi_generate_identity("alice@r4.test".to_string(), now).expect("alice");
    let (_b, bob_kp, bob) = mimi_generate_identity("bob@r4.test".to_string(), now).expect("bob");
    let roster = vec![0x81, 0x81, 0x00];

    // Two groups adding the SAME bob KeyPackage: welcome1 drives phase 1, welcome2 is the replay attempt.
    let g1 = mimi_create_group("r4-g1".to_string(), alice.clone()).expect("g1");
    let (_g1, welcome1, _c1) =
        mimi_add_member_commit_appsync(g1, alice.clone(), bob_kp.clone(), roster.clone())
            .expect("add bob to g1");
    let g2 = mimi_create_group("r4-g2".to_string(), alice.clone()).expect("g2");
    let (_g2, welcome2, _c2) =
        mimi_add_member_commit_appsync(g2, alice, bob_kp, roster).expect("add bob to g2");

    // PHASE 1 ONLY. No Welcome is ever opened; the KeyPackage's private init key is never used.
    let prepared = prepare_welcome_retirement(welcome1, bob, Vec::new(), String::new())
        .expect("phase 1 prepares a retirement for a targeting Welcome");
    let retired = prepared.retired_bundle().to_vec();

    // The caller persists `retired`, then the process dies before complete_welcome ever runs.
    drop(prepared);

    // The persisted retirement already cleared the consumed KeyPackage's private bundle...
    let parsed: crate::mls::IdentityBundle =
        serde_json::from_slice(&retired).expect("deserialize retired bundle");
    assert!(
        parsed.key_package_bundle.is_none(),
        "phase 1 must retire the KeyPackage's private bundle before any Welcome is opened"
    );

    // ...and a second Welcome for the same KeyPackage cannot open against it: the retirement is durable
    // BEFORE the spend, so an abort cannot leave a live-and-replayable KeyPackage behind.
    let second = mimi_process_welcome_non_atomic(welcome2, retired, Vec::new(), String::new());
    assert!(
        second.is_err(),
        "a retirement persisted in phase 1 (before any open) failed to block replay - the \
         crash-atomicity window is still open"
    );
}

/// The renamed compatibility entry point remains callable while directing production callers to the
/// two-phase API.
#[test]
fn non_atomic_welcome_processor_remains_callable() {
    let now = now_secs();
    let (_a, _akp, alice) =
        mimi_generate_identity("alice@legacy.test".to_string(), now).expect("generate alice");
    let (_b, bob_kp, bob) =
        mimi_generate_identity("bob@legacy.test".to_string(), now).expect("generate bob");
    let group = mimi_create_group("legacy-group".to_string(), alice.clone()).expect("create group");
    let (_group, welcome) = mimi_add_member(group, alice.clone(), bob_kp).expect("add bob");

    let (state, _) =
        mimi_process_welcome_non_atomic(welcome, bob, Vec::new(), String::new()).expect("join");
    assert!(
        !state.is_empty(),
        "the compatibility entry point must remain callable"
    );
}

/// Phase 1 retires only the public-reference candidate KeyPackage. Other KeyPackages remain available
/// when the caller persists this retirement before phase 2.
#[test]
fn prepared_retirement_keeps_unreferenced_keypackages() {
    let now = now_secs();
    let (_a, _akp, alice) =
        mimi_generate_identity("alice@candidate.test".to_string(), now).expect("generate alice");
    let (_b, bob_kp, bob) =
        mimi_generate_identity("bob@candidate.test".to_string(), now).expect("generate bob");
    let (_id, replacement_kp, replacement_bundle) =
        crate::mls::groups::regenerate_key_package(bob.clone(), now)
            .expect("regenerate bob keypackage");
    let mut two_keypackage_bundle: crate::mls::IdentityBundle =
        serde_json::from_slice(&bob).expect("deserialize bob bundle");
    let replacement: crate::mls::IdentityBundle =
        serde_json::from_slice(&replacement_bundle).expect("deserialize replacement bundle");
    two_keypackage_bundle
        .storage_map
        .extend(replacement.storage_map.clone());
    let two_keypackage_bundle =
        serde_json::to_vec(&two_keypackage_bundle).expect("serialize two-keypackage bundle");

    let group =
        mimi_create_group("candidate-group".to_string(), alice.clone()).expect("create group");
    let (_group, welcome) = mimi_add_member(group, alice.clone(), bob_kp).expect("add bob");
    let replacement_group =
        mimi_create_group("replacement-group".to_string(), alice.clone()).expect("create group");
    let (_replacement_group, replacement_welcome) =
        mimi_add_member(replacement_group, alice, replacement_kp)
            .expect("add replacement keypackage");
    let prepared =
        prepare_welcome_retirement(welcome, two_keypackage_bundle, Vec::new(), String::new())
            .expect("prepare candidate retirement");
    let retired_bytes = prepared.retired_bundle().to_vec();
    let retired: crate::mls::IdentityBundle =
        serde_json::from_slice(prepared.retired_bundle()).expect("deserialize retirement");

    let remaining_keypackages = retired
        .storage_map
        .iter()
        .filter(|(key, _)| key.starts_with(b"KeyPackage"))
        .count();
    assert_eq!(
        remaining_keypackages, 1,
        "phase 1 must retain KeyPackages not named by the Welcome's public references"
    );
    assert!(
        retired.key_package_bundle.is_none(),
        "the field copy of the referenced KeyPackage must be retired"
    );
    assert!(
        mimi_process_welcome_non_atomic(
            replacement_welcome,
            retired_bytes,
            Vec::new(),
            String::new()
        )
        .is_ok(),
        "an unreferenced KeyPackage must remain usable after phase-1 retirement"
    );
}

/// Defensive-invalid phase-2 inputs still return the already-prepared retirement as Spent.
#[test]
fn complete_welcome_invariant_failures_are_spent() {
    let now = now_secs();
    let (_a, _akp, alice) =
        mimi_generate_identity("alice@invariant.test".to_string(), now).expect("generate alice");
    let (_b, bob_kp, bob) =
        mimi_generate_identity("bob@invariant.test".to_string(), now).expect("generate bob");
    let group =
        mimi_create_group("invariant-group".to_string(), alice.clone()).expect("create group");
    let (_group, welcome) = mimi_add_member(group, alice, bob_kp).expect("add bob");

    let mut missing_identity =
        prepare_welcome_retirement(welcome.clone(), bob.clone(), Vec::new(), String::new())
            .expect("prepare welcome");
    let identity_retirement = missing_identity.retired_bundle().to_vec();
    missing_identity.identity = None;
    match complete_welcome(missing_identity) {
        Err(MimiWelcomeError::Spent { retired_bundle, .. }) => {
            assert_eq!(retired_bundle, identity_retirement)
        }
        other => panic!("missing identity must return Spent, got {other:?}"),
    }

    let mut missing_welcome = prepare_welcome_retirement(welcome, bob, Vec::new(), String::new())
        .expect("prepare welcome");
    let welcome_retirement = missing_welcome.retired_bundle().to_vec();
    missing_welcome.welcome = None;
    match complete_welcome(missing_welcome) {
        Err(MimiWelcomeError::Spent { retired_bundle, .. }) => {
            assert_eq!(retired_bundle, welcome_retirement)
        }
        other => panic!("missing Welcome must return Spent, got {other:?}"),
    }
}

/// A non-targeting or hostile Welcome must not be able to force-retire the caller's KeyPackages (a
/// KeyPackage-nuke DoS). `prepare_welcome_retirement` returns `Unspent` for a Welcome that targets a
/// DIFFERENT identity's KeyPackage, leaving the caller's bundle intact. Mutation guard: dropping the
/// "does this Welcome target one of my KeyPackages?" gate makes phase 1 build a conservative retirement
/// and return `Ok`, reddening the `Ok(_) => panic!` arm.
#[test]
fn prepare_welcome_retirement_returns_unspent_for_a_non_targeting_welcome() {
    let now = now_secs();
    let (_a, _akp, alice) =
        mimi_generate_identity("alice@nt.test".to_string(), now).expect("alice");
    let (_b, bob_kp, bob) = mimi_generate_identity("bob@nt.test".to_string(), now).expect("bob");
    let (_c, carol_kp, _carol) =
        mimi_generate_identity("carol@nt.test".to_string(), now).expect("carol");

    // A Welcome that targets CAROL's KeyPackage, not bob's.
    let gc = mimi_create_group("nt-carol".to_string(), alice.clone()).expect("gc");
    let (_gc, welcome_for_carol) = mimi_add_member(gc, alice.clone(), carol_kp).expect("add carol");

    // bob prepares against a Welcome that targets no KeyPackage he holds -> Unspent, no retirement.
    match prepare_welcome_retirement(welcome_for_carol, bob.clone(), Vec::new(), String::new()) {
        Err(MimiWelcomeError::Unspent(_)) => {}
        Err(MimiWelcomeError::Spent { .. }) => {
            panic!("a non-targeting Welcome must be Unspent, not force-retire bob's KeyPackages")
        }
        Ok(_) => panic!("a non-targeting Welcome must not yield a retirement for bob"),
    }

    // bob's KeyPackage is intact: a genuine Welcome for bob still opens against his untouched bundle.
    let gb = mimi_create_group("nt-bob".to_string(), alice.clone()).expect("gb");
    let (_gb, welcome_for_bob) = mimi_add_member(gb, alice, bob_kp).expect("add bob");
    mimi_process_welcome_non_atomic(welcome_for_bob, bob, Vec::new(), String::new())
        .expect("bob's own KeyPackage must still open a genuine Welcome (it was never retired)");
}

/// Positive control for the two-phase path: prepare, (the caller persists), then complete opens the
/// Welcome on the ephemeral copy and returns a usable group state PLUS the precise retirement, which is
/// single-use. Proves phase 2 actually joins and the normal KeyPackage is retired exactly once.
/// Mutation guard: a complete that returns the input bundle unretired lets `welcome2` open, reddening
/// the replay assert.
#[test]
fn two_phase_prepare_then_complete_joins_and_retires_the_keypackage() {
    let now = now_secs();
    let (_a, _akp, alice) =
        mimi_generate_identity("alice@2p.test".to_string(), now).expect("alice");
    let (_b, bob_kp, bob) = mimi_generate_identity("bob@2p.test".to_string(), now).expect("bob");
    let roster = vec![0x81, 0x81, 0x00];

    let g1 = mimi_create_group("2p-g1".to_string(), alice.clone()).expect("g1");
    let (_g1, welcome1, _c1) =
        mimi_add_member_commit_appsync(g1, alice.clone(), bob_kp.clone(), roster.clone())
            .expect("add bob to g1");
    let g2 = mimi_create_group("2p-g2".to_string(), alice.clone()).expect("g2");
    let (_g2, welcome2, _c2) =
        mimi_add_member_commit_appsync(g2, alice, bob_kp, roster).expect("add bob to g2");

    let prepared = prepare_welcome_retirement(welcome1, bob, Vec::new(), String::new())
        .expect("phase 1 prepares");
    // (the caller persists prepared.retired_bundle() here before completing)
    let (state, retired) = complete_welcome(prepared).expect("phase 2 joins");
    assert!(
        !state.is_empty(),
        "phase 2 must return a joined group state"
    );

    let parsed: crate::mls::IdentityBundle =
        serde_json::from_slice(&retired).expect("deserialize precise retirement");
    assert!(
        parsed.key_package_bundle.is_none(),
        "a successful two-phase join must retire the consumed KeyPackage's private bundle"
    );

    let second = mimi_process_welcome_non_atomic(welcome2, retired, Vec::new(), String::new());
    assert!(
        second.is_err(),
        "the two-phase precise retirement failed to block replay - single-use hole"
    );
}

/// A phase-2 hub-pin rejection returns `Spent`, and because the caller persisted the fail-closed
/// retirement in phase 1, a replay is blocked regardless. Proves there is no `Unspent` escape once
/// phase 1 has committed: BOTH the phase-1 retirement (already persisted) and the phase-2-returned
/// retirement block replay. Mutation guard: routing the hub rejection to `Unspent` reddens the `Spent`
/// match; dropping the retirement reddens a replay assert.
#[test]
fn two_phase_hub_pin_rejection_keeps_the_retirement_durable() {
    let now = now_secs();
    let (_aid, _akp, alice) =
        crate::identity::generate_identity("alice@2pr.test".to_string(), now).expect("alice");
    let (_bid, bob_kp, bob) =
        crate::identity::generate_identity("bob@2pr.test".to_string(), now).expect("bob");
    let (_hid, _hkp, real_hub) =
        crate::identity::generate_identity("hub@2pr.test".to_string(), now).expect("hub");
    let (_wid, _wkp, wrong_hub) =
        crate::identity::generate_identity("attacker@2pr.test".to_string(), now)
            .expect("wrong hub");
    let (_rs, real_hub_pubkey) = raw_signer_and_pubkey(&real_hub);
    let (_ws, wrong_hub_pubkey) = raw_signer_and_pubkey(&wrong_hub);

    // g1 names the real hub; g2 is where the same KeyPackage would be replayed.
    let g1 = mimi_create_group_with_external_senders(
        "2pr-g1".to_string(),
        alice.clone(),
        real_hub_pubkey.as_slice().to_vec(),
        "hub@2pr.test".to_string(),
    )
    .expect("create g1 with hub");
    let (_g1, welcome1) =
        mimi_add_member(g1, alice.clone(), bob_kp.clone()).expect("add bob to g1");
    let g2 = mimi_create_group("2pr-g2".to_string(), alice.clone()).expect("create g2");
    let (_g2, welcome2) = mimi_add_member(g2, alice, bob_kp).expect("add bob to g2");

    // Phase 1 prepares the retirement (the caller persists it); phase 2 opens but the WRONG-hub pin
    // rejects the join after the KeyPackage is spent on the ephemeral copy.
    let prepared = prepare_welcome_retirement(
        welcome1,
        bob,
        wrong_hub_pubkey.as_slice().to_vec(),
        "hub@2pr.test".to_string(),
    )
    .expect("phase 1 prepares");
    let phase1_retirement = prepared.retired_bundle().to_vec();

    let retired = match complete_welcome(prepared) {
        Err(MimiWelcomeError::Spent { retired_bundle, .. }) => retired_bundle,
        Err(MimiWelcomeError::Unspent(e)) => {
            panic!("a post-open hub rejection must be Spent, not Unspent: {e}")
        }
        Ok(_) => panic!("a wrong-hub pin must reject the join"),
    };
    let parsed: crate::mls::IdentityBundle =
        serde_json::from_slice(&retired).expect("deserialize retirement");
    assert!(
        parsed.key_package_bundle.is_none(),
        "a rejected phase-2 join must still retire the consumed KeyPackage's private bundle"
    );

    // Both the phase-1 retirement AND the phase-2-returned retirement block replay of the KeyPackage.
    assert!(
        mimi_process_welcome_non_atomic(
            welcome2.clone(),
            phase1_retirement,
            Vec::new(),
            String::new()
        )
        .is_err(),
        "the phase-1 retirement (already persisted) must block replay even though phase 2 rejected"
    );
    assert!(
        mimi_process_welcome_non_atomic(welcome2, retired, Vec::new(), String::new()).is_err(),
        "the phase-2 retirement must block replay after a hub rejection"
    );
}
