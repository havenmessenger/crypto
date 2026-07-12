//! Cross-provider (MIMI) group-flow proofs: epoch sync across add/remove commits, the
//! mimiParticipantList AppSync roster proposal riding atomically with a commit, and the
//! self-contained Welcome (ratchet tree embedded, no out-of-band export) a foreign MIMI
//! implementation would byte-inspect.

use super::*;
use crate::mls::groups::{decrypt_message, encrypt_message, mls_process_commit};

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
    let bob_s = mimi_process_welcome(welcome_bob, bob.clone(), Vec::new(), String::new())
        .expect("bob joins");

    let (alice_s, welcome_carol, add_commit) =
        mimi_add_member_commit(alice_s, alice.clone(), carol_kp).expect("add carol");
    let carol_s = mimi_process_welcome(welcome_carol, carol.clone(), Vec::new(), String::new())
        .expect("carol joins");
    let bob_s = mls_process_commit(bob_s, bob.clone(), add_commit).expect("bob processes add");

    // Proof of epoch sync after ADD: alice encrypts at the new epoch; bob and carol both decrypt.
    let msg = b"after-add message".to_vec();
    let (alice_s, ct) = encrypt_message(alice_s, alice.clone(), msg.clone()).expect("encrypt");
    let (bob_s, pt_bob) = decrypt_message(bob_s, bob.clone(), ct.clone()).expect("bob decrypt");
    let (_carol_s, pt_carol) = decrypt_message(carol_s, carol.clone(), ct).expect("carol decrypt");
    assert_eq!(pt_bob, msg, "bob must decrypt at the post-add epoch");
    assert_eq!(
        pt_carol, msg,
        "carol must decrypt as a freshly-added member"
    );

    // Remove carol; bob must process the commit and stay synced.
    let (alice_s, rm_commit) =
        mimi_remove_member_commit(alice_s, alice.clone(), "carol@mls.test".to_string())
            .expect("remove carol");
    let bob_s = mls_process_commit(bob_s, bob.clone(), rm_commit).expect("bob processes remove");

    let msg2 = b"after-remove message".to_vec();
    let (_alice_s, ct2) = encrypt_message(alice_s, alice.clone(), msg2.clone()).expect("encrypt2");
    let (_bob_s, pt_bob2) = decrypt_message(bob_s, bob, ct2).expect("bob decrypt2");
    assert_eq!(pt_bob2, msg2, "bob must decrypt at the post-remove epoch");
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
    let bob_s = mimi_process_welcome(welcome_bob, bob.clone(), Vec::new(), String::new())
        .expect("bob joins");

    let roster_add = vec![0x81, 0x81, 0x00]; // opaque payload; surfacing correctness is what matters
    let (alice_s, welcome_carol, add_commit) =
        mimi_add_member_commit_appsync(alice_s, alice.clone(), carol_kp, roster_add.clone())
            .expect("add carol with roster");
    let carol_s = mimi_process_welcome(welcome_carol, carol.clone(), Vec::new(), String::new())
        .expect("carol joins");
    let (bob_s, surfaced_add) =
        mls_process_commit_appsync(bob_s, bob.clone(), add_commit).expect("bob processes add");
    assert_eq!(
        surfaced_add, roster_add,
        "bob must surface the roster payload carried in the add commit"
    );

    // Epoch sync after add (the roster rode WITH the Add): alice -> bob+carol decrypt.
    let msg = b"after-appsync-add".to_vec();
    let (alice_s, ct) = encrypt_message(alice_s, alice.clone(), msg.clone()).expect("encrypt");
    let (bob_s, pt_bob) = decrypt_message(bob_s, bob.clone(), ct.clone()).expect("bob decrypt");
    let (_carol_s, pt_carol) = decrypt_message(carol_s, carol.clone(), ct).expect("carol decrypt");
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
    let (bob_s, surfaced_rem) =
        mls_process_commit_appsync(bob_s, bob.clone(), rm_commit).expect("bob processes remove");
    assert_eq!(
        surfaced_rem, roster_rem,
        "bob must surface the roster payload carried in the remove commit"
    );

    let msg2 = b"after-appsync-remove".to_vec();
    let (_alice_s, ct2) = encrypt_message(alice_s, alice, msg2.clone()).expect("encrypt2");
    let (_bob_s, pt_bob2) = decrypt_message(bob_s, bob, ct2).expect("bob decrypt2");
    assert_eq!(
        pt_bob2, msg2,
        "bob stays epoch-synced after the appsync remove"
    );
}

/// The joiner receives ONLY the `MlsMessage(Welcome)` - no out-of-band ratchet tree - and must
/// still join and exchange messages bidirectionally. Proves `use_ratchet_tree_extension(true)`
/// embeds the tree and `mimi_process_welcome` reads it from the Welcome alone. This is the
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

    let rcv_state = mimi_process_welcome(
        welcome_msg.clone(),
        rcv_bundle.clone(),
        Vec::new(),
        String::new(),
    )
    .expect("receiver joins");

    let m1 = b"hello over MIMI (self-contained welcome)".to_vec();
    let (_snd_state_3, ct1) =
        encrypt_message(snd_state_2, snd_bundle, m1.clone()).expect("sender encrypts");
    let (rcv_state_2, p1) =
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
    let identity = IdentityBundle::from_slice(bundle_bytes).expect("valid bundle");
    let signer = MlsSigner {
        key: Zeroizing::new(identity.private_key.clone()),
        scheme: identity.signature_scheme,
    };
    let pubkey = SignaturePublicKey::try_from(identity.public_key_bytes.clone())
        .expect("valid public key bytes");
    (signer, pubkey)
}

/// Load a member's current `(GroupId, epoch)` from their serialized `GroupState` - mirrors exactly
/// the load dance every `mimi_*` function does internally (fresh provider, storage_map restored,
/// `MlsGroup::load`), needed here only to construct a well-formed external proposal in tests (real
/// production code never needs to peek at the epoch from outside `mimi_accept_external_remove_proposal`
/// itself).
fn group_id_and_epoch(state_bytes: &[u8]) -> (GroupId, GroupEpoch) {
    let state = GroupState::from_slice(state_bytes).expect("valid state");
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
    let state = GroupState::from_slice(&new_alice_s).expect("valid state");
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

    let joined = mimi_process_welcome(welcome_bob, bob, hub_sig_bytes, "hub@pin.test".to_string());
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

    let joined = mimi_process_welcome(
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

    let joined = mimi_process_welcome(
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

    let joined = mimi_process_welcome(welcome_bob, bob, Vec::new(), String::new());
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
    let bob_s = mimi_process_welcome(welcome_bob, bob.clone(), Vec::new(), String::new())
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
/// directly instead, exactly as `spec_capability_proof.rs` (the interop repo's sibling proof
/// module) does for its own tests.
fn signer_and_cwk(bundle_bytes: &[u8]) -> (MlsSigner, CredentialWithKey) {
    let mut identity = IdentityBundle::from_slice(bundle_bytes).expect("valid bundle");
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
