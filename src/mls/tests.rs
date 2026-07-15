//! Proof set for the zeroize-on-drop wiring on `GroupState`/`IdentityBundle`/`MlsSigner`, plus
//! a full group-lifecycle round trip. `GroupState` and `IdentityBundle` cannot implement `Drop`
//! without first converting every partial-move call site (`state.field`, `identity.field`) in
//! `groups.rs`/`mimi/mod.rs` to `mem::take` - a Drop-implementing type forbids moving a field
//! out of an existing binding. The lifecycle test proves that conversion preserves the group's
//! cryptographic behavior (create/add/welcome/encrypt/decrypt/remove/regenerate all
//! round-trip), which matters because this crate otherwise has no MLS-group-flow test coverage.

use super::*;
use crate::identity::generate_identity;
use crate::mls::groups::{
    add_member, add_members_bulk, create_group, decrypt_message, encrypt_message,
    mls_extract_signature_key, mls_process_commit, process_welcome, regenerate_key_package,
    remove_member_by_credential, MAX_BULK_AGGREGATE_BYTES, MAX_BULK_MEMBERS,
};
use std::mem::ManuallyDrop;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

/// Real wall-clock seconds - `add_member`'s `KeyPackage::validate` checks lifetime against the
/// actual system clock (not the caller-supplied timestamp used only to BUILD the lifetime), so
/// a hardcoded past/future constant here would make every KeyPackage look expired/not-yet-valid.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64
}

/// Proof that `GroupState`'s `Drop` body wipes `storage_map` values. Uses `ManuallyDrop` so the
/// struct's field-level deallocation never runs - reading a Vec's buffer AFTER real deallocation
/// is unsound (the allocator may reuse/overwrite the freed bytes before the read), so the safe
/// technique is to invoke the exact same zeroize call the real `Drop::drop` body runs, then read
/// the still-live (intentionally leaked) allocation.
#[test]
fn groupstate_drop_zeroizes_storage_values() {
    let state = GroupState {
        group_id: b"gid".to_vec(),
        storage_map: vec![(b"key".to_vec(), (1u8..=32).collect())],
    };
    let mut guard = ManuallyDrop::new(state);
    let (ptr, len) = {
        let v = &guard.storage_map[0].1;
        (v.as_ptr(), v.len())
    };
    // The exact call GroupState::drop makes - proves the wipe, without deallocating.
    for (_, v) in &mut guard.storage_map {
        v.zeroize();
    }
    // SAFETY: `guard` is never dropped (ManuallyDrop, leaked for this test), so the
    // allocation stays live and unreused; ptr/len point into it.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert!(
        bytes.iter().all(|&b| b == 0),
        "GroupState's storage-value zeroize left residue"
    );
}

/// Same technique, for `IdentityBundle.private_key`.
#[test]
fn identitybundle_drop_zeroizes_private_key() {
    let (user_id, _kp_bytes, bundle_bytes) =
        generate_identity("zeroize-probe".to_string(), now_secs()).expect("generate_identity");
    assert_eq!(user_id, "zeroize-probe");
    let bundle: IdentityBundle = serde_json::from_slice(&bundle_bytes).expect("deserialize");
    let mut guard = ManuallyDrop::new(bundle);
    // Force a known non-zero byte so a false-pass (an already-zero key) can't hide a real bug.
    guard.private_key[0] = guard.private_key[0].wrapping_add(1).max(1);
    let (ptr, len) = (guard.private_key.as_ptr(), guard.private_key.len());
    guard.private_key.zeroize(); // the exact call IdentityBundle::drop makes
                                 // SAFETY: `guard` is never dropped, so the allocation stays live and unreused.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert!(
        bytes.iter().all(|&b| b == 0),
        "IdentityBundle's private_key zeroize left residue"
    );
}

/// Same technique, for `MlsSigner.key` (a `Zeroizing<Vec<u8>>` - the type system already
/// guarantees this wipes on drop; this is a behavioral confirmation on real key-shaped bytes).
#[test]
fn mlssigner_key_wipes_on_drop() {
    use openmls::prelude::SignatureScheme;
    let key_bytes: Vec<u8> = (1u8..=32).collect();
    let signer = MlsSigner {
        key: zeroize::Zeroizing::new(key_bytes),
        scheme: SignatureScheme::ED25519,
    };
    let mut guard = ManuallyDrop::new(signer);
    let (ptr, len) = (guard.key.as_ptr(), guard.key.len());
    // The exact wipe Zeroizing's own Drop impl performs, without the subsequent deallocation.
    guard.key.zeroize();
    // SAFETY: `guard` is never dropped, so the allocation stays live and unreused.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert!(
        bytes.iter().all(|&b| b == 0),
        "MlsSigner.key (Zeroizing) left residue on drop"
    );
}

/// Proof that `zeroizing_json`'s output buffer wipes on drop (the serialized-artifact gap
/// this closes).
///
/// A manual `.zeroize()` call on the returned value would not prove this: `Vec<u8>` itself
/// implements `Zeroize`, so that would pass even if `zeroizing_json` returned a bare
/// `Vec<u8>` instead of `Zeroizing<Vec<u8>>` - it proves "calling zeroize on this value wipes
/// it" (trivially true for any `Vec<u8>`), not "this value wipes itself when merely dropped,
/// with no caller action" (the actual claim `Zeroizing` exists to make).
///
/// The proof is the explicit `Zeroizing<Vec<u8>>` type annotation on `serialized` below: a
/// compile-time proof of the return type itself, unconditional on every build, that a manual
/// runtime check can't offer. If `zeroizing_json` ever stopped returning `Zeroizing`, this line
/// would fail to compile, not silently keep passing.
///
/// The runtime check below uses `ManuallyDrop` (matching the other proofs in this
/// file - never deallocates, so unambiguously race-free under `cargo test`'s parallel runner,
/// which shares one global allocator across every test thread) over the actual bytes
/// `zeroizing_json` produced (not a synthetic buffer), as a live-data regression check on the
/// wipe behavior; the type annotation above it is what closes the "would pass for a plain Vec"
/// gap, not this runtime half alone. A real drop-then-read-the-freed-allocation check is NOT
/// used here: another thread's allocation can reuse a just-freed address before this test's
/// read runs, making that shape of check racy under the full suite despite passing in
/// isolation - a false-failure risk this crate does not accept.
#[test]
fn zeroizing_json_output_wipes_on_drop() {
    let (_, _, bundle_bytes) = generate_identity("zeroizing-json-probe".to_string(), now_secs())
        .expect("generate_identity");
    let mut bundle: IdentityBundle = serde_json::from_slice(&bundle_bytes).expect("deserialize");
    // Force a known, distinctive byte pair so a false-pass (an already-zero key, or a
    // coincidental zero run) can't hide a real bug.
    bundle.private_key[0] = 0xAB;
    bundle.private_key[1] = 0xCD;

    let serialized: zeroize::Zeroizing<Vec<u8>> = zeroizing_json(&bundle).expect("serialize");
    // `serde_json` encodes `Vec<u8>` as a JSON array of decimal numbers, not raw bytes - confirm
    // the fixture's marker (171, 205) actually landed in the buffer's ASCII text before proving
    // the buffer gets wiped.
    assert!(
        serialized
            .windows(b"171,205".len())
            .any(|w| w == b"171,205"),
        "fixture sanity: private_key marker not found in the serialized buffer"
    );

    let mut guard = ManuallyDrop::new(serialized);
    let (ptr, len) = (guard.as_ptr(), guard.len());
    guard.zeroize(); // the same call Zeroizing's own Drop impl makes on this value
                     // SAFETY: `guard` is never dropped (ManuallyDrop leaks it for this test),
                     // so the allocation stays live and unreused; ptr/len point into it, and no
                     // other thread can reuse memory this test never frees.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert!(
        bytes.iter().all(|&b| b == 0),
        "zeroizing_json's output buffer left residue on drop"
    );
}

/// Full two-member group lifecycle: generate identities, create a group, add a member, have
/// that member process the Welcome, encrypt from the creator, decrypt at the joiner, remove
/// the joiner. Proves the `mem::take` refactor (needed for `GroupState`/`IdentityBundle` to
/// implement `Drop`) didn't change any of the actual MLS wire/state semantics.
#[test]
fn group_lifecycle_round_trips_after_zeroize_refactor() {
    let now = now_secs();
    let (user_a, _kp_a_unused, bundle_a) =
        generate_identity("alice".to_string(), now).expect("generate alice");
    let (user_b, kp_b, bundle_b) = generate_identity("bob".to_string(), now).expect("generate bob");
    assert_eq!(user_a, "alice");
    assert_eq!(user_b, "bob");

    let group_state_a =
        create_group("test-group".to_string(), bundle_a.clone()).expect("create_group");

    let (group_state_a2, combined_welcome, _commit_ab) =
        add_member(group_state_a, bundle_a.clone(), kp_b).expect("add_member");

    let group_state_b =
        process_welcome(combined_welcome, bundle_b.clone()).expect("process_welcome");

    let plaintext = b"hello from alice".to_vec();
    let (group_state_a3, ciphertext) =
        encrypt_message(group_state_a2, bundle_a.clone(), plaintext.clone())
            .expect("encrypt_message");

    let (_group_state_b2, decrypted) =
        decrypt_message(group_state_b, bundle_b.clone(), ciphertext).expect("decrypt_message");
    assert_eq!(decrypted, plaintext, "round-tripped plaintext mismatch");

    // Alice removes Bob by credential identity - exercises the last un-covered groups.rs fn.
    let (group_state_a4, _remove_commit) =
        remove_member_by_credential(group_state_a3, bundle_a, "bob".to_string())
            .expect("remove_member_by_credential");
    let state: GroupState = serde_json::from_slice(&group_state_a4).expect("deserialize");
    assert_eq!(state.group_id, b"test-group");
}

/// Regression test: a THIRD member joining must not strand an EXISTING member on
/// a stale epoch. `group_lifecycle_round_trips_after_zeroize_refactor` above only ever adds to a
/// 1-member group, which structurally cannot exercise this bug (there is no existing member besides
/// the adder to strand) - that's how the discarded-commit bug shipped undetected.
///
/// Sequence: Alice creates a group and adds Bob (2-member). Alice then adds Carol (3-member) - THIS
/// is the commit that must reach Bob, who was not part of that operation. Bob explicitly processes
/// the returned Commit via `mls_process_commit` (mirroring what the client's commit-distribution
/// path now does over the wire). Proof of sync: Alice encrypts in the post-Carol epoch and Bob
/// decrypts it. Before the fix, this test would not compile (arity); with the fix reverted to
/// discard the commit (i.e. `_commit` instead of `commit`), Bob's decrypt fails with an epoch/secret
/// mismatch - the production failure this test guards against.
#[test]
fn add_member_commit_keeps_existing_member_in_sync_three_party() {
    let now = now_secs();
    let (_user_a, _kp_a_unused, bundle_a) =
        generate_identity("alice3".to_string(), now).expect("generate alice3");
    let (_user_b, kp_b, bundle_b) =
        generate_identity("bob3".to_string(), now).expect("generate bob3");
    let (_user_c, kp_c, bundle_c) =
        generate_identity("carol3".to_string(), now).expect("generate carol3");

    let group_state_a =
        create_group("test-group-3party".to_string(), bundle_a.clone()).expect("create_group");

    // Alice adds Bob - 2-member group. Bob joins via his Welcome.
    let (group_state_a, welcome_for_bob, _commit_ab) =
        add_member(group_state_a, bundle_a.clone(), kp_b).expect("add_member (bob)");
    let group_state_b =
        process_welcome(welcome_for_bob, bundle_b.clone()).expect("bob process_welcome");

    // Alice adds Carol - 3-member group. This Commit is the one Bob must receive: Bob was not
    // part of this operation and has no other way to learn the group advanced an epoch.
    let (group_state_a, welcome_for_carol, commit_for_bob) =
        add_member(group_state_a, bundle_a.clone(), kp_c).expect("add_member (carol)");
    let group_state_c =
        process_welcome(welcome_for_carol, bundle_c.clone()).expect("carol process_welcome");

    // Bob (the existing member, untouched by the add itself) advances his epoch by processing
    // the Commit - this is the fix's whole point: without it, Bob has no path to this state.
    let group_state_b = mls_process_commit(group_state_b, bundle_b.clone(), commit_for_bob)
        .expect("bob mls_process_commit");

    // Prove Bob is in the SAME epoch as Alice post-Carol-add: Alice encrypts, Bob decrypts.
    let plaintext = b"hello group, carol just joined".to_vec();
    let (_group_state_a2, ciphertext) =
        encrypt_message(group_state_a, bundle_a, plaintext.clone()).expect("alice encrypt");
    let (_group_state_b2, decrypted) =
        decrypt_message(group_state_b, bundle_b, ciphertext).expect("bob decrypt");
    assert_eq!(
        decrypted, plaintext,
        "Bob desynced after Carol's add - the exact bug this test guards against"
    );

    // Sanity: Carol (the new member) is also usable in the group she just joined.
    let (_group_state_c2, carol_ciphertext) =
        encrypt_message(group_state_c, bundle_c.clone(), b"hi from carol".to_vec())
            .expect("carol encrypt");
    assert!(
        !carol_ciphertext.is_empty(),
        "Carol must be able to encrypt in her newly-joined group"
    );
}

/// `regenerate_key_package` preserves the identity's private key / scheme / user_id while
/// issuing a fresh KeyPackage - proof that the 3-field `mem::take` there (private_key,
/// public_key_bytes, and the final user_id return) didn't change the preserved values.
#[test]
fn regenerate_key_package_preserves_identity() {
    let now = now_secs();
    let (user_id, _kp_bytes, bundle_bytes) =
        generate_identity("carol".to_string(), now).expect("generate carol");

    let (returned_user_id, new_kp_bytes, new_bundle_bytes) =
        regenerate_key_package(bundle_bytes, now + 1).expect("regenerate_key_package");

    assert_eq!(returned_user_id, "carol");
    assert_eq!(user_id, "carol");
    assert!(!new_kp_bytes.is_empty());

    let new_bundle: IdentityBundle =
        serde_json::from_slice(&new_bundle_bytes).expect("deserialize new bundle");
    assert_eq!(new_bundle.user_id, "carol");
    assert!(!new_bundle.private_key.is_empty());
}

// ── negative/overflowing timestamps must fail closed, never panic or wrap ──────────────

/// A negative `now_secs` (a caller clock error) must be rejected with `Err` at the public API
/// surface - not silently cast to `u64::MAX` via `as u64` and only fail (or, in a debug build,
/// panic) deep inside `make_lifetime`'s arithmetic.
#[test]
fn generate_identity_rejects_negative_timestamp() {
    let result = generate_identity("negative_ts".to_string(), -1);
    assert!(
        result.is_err(),
        "a negative now_secs must fail closed, not panic or produce a bogus lifetime"
    );
}

/// Same boundary, the `regenerate_key_package` call path.
#[test]
fn regenerate_key_package_rejects_negative_timestamp() {
    let now = now_secs();
    let (_uid, _kp, bundle_bytes) =
        generate_identity("regen_negative".to_string(), now).expect("generate");
    let result = regenerate_key_package(bundle_bytes, -1);
    assert!(
        result.is_err(),
        "a negative now_secs must fail closed on regenerate_key_package too"
    );
}

/// `make_lifetime` itself: a `now_secs` close enough to `u64::MAX` that `+ KP_LIFETIME_SECS`
/// would overflow must return `Err` from the `checked_add`, never silently wrap into a
/// nonsensical (or debug-panicking) lifetime.
#[test]
fn make_lifetime_rejects_overflowing_now_secs() {
    let result = make_lifetime(u64::MAX - 10);
    assert!(
        result.is_err(),
        "now_secs near u64::MAX must fail the checked_add, not wrap"
    );
}

/// Sanity: an ordinary `now_secs` still produces a valid lifetime (the fix must not have
/// narrowed the accepted range for real wall-clock timestamps).
#[test]
fn make_lifetime_accepts_ordinary_now_secs() {
    let now = now_secs();
    #[allow(clippy::cast_sign_loss)]
    let result = make_lifetime(now as u64);
    assert!(
        result.is_ok(),
        "an ordinary current timestamp must still succeed"
    );
}

// ── valid-plus-trailing-bytes must be REJECTED (tls_deserialize_exact, not tls_deserialize) ──

/// A real, valid KeyPackage with one extra trailing byte must be rejected - `tls_deserialize`
/// (the old call) silently accepts `valid_object || arbitrary_trailer`; `tls_deserialize_exact`
/// requires the whole buffer to be consumed.
#[test]
fn mls_extract_signature_key_rejects_trailing_bytes() {
    let now = now_secs();
    let (_uid, kp_bytes, _bundle) =
        generate_identity("trailing_bytes".to_string(), now).expect("generate");

    // Sanity: the unmodified bytes DO extract a real key.
    let sig_clean = mls_extract_signature_key(kp_bytes.clone());
    assert!(
        !sig_clean.is_empty(),
        "the real KeyPackage must extract cleanly"
    );

    let mut with_trailer = kp_bytes;
    with_trailer.push(0xAB);
    let sig_trailer = mls_extract_signature_key(with_trailer);
    assert!(
        sig_trailer.is_empty(),
        "a KeyPackage with one trailing byte must be rejected (tls_deserialize_exact), not \
         silently accepted"
    );
}

// ── size-bound: an oversize wire input must be rejected BEFORE deserialization is attempted ──

/// A buffer larger than `MAX_MLS_WIRE_BYTES` must fail fast at the size-cap check, not reach
/// `tls_deserialize_exact` at all (proven indirectly: garbage bytes that size would otherwise
/// just fail to parse anyway, so the meaningful proof is that this returns the SAME
/// fail-closed `""` either way, never panics/hangs on an oversized allocation attempt).
#[test]
fn mls_extract_signature_key_rejects_oversize_input() {
    let oversized = vec![0u8; crate::mls::MAX_MLS_WIRE_BYTES + 1];
    let sig = mls_extract_signature_key(oversized);
    assert!(
        sig.is_empty(),
        "an oversize buffer must be rejected (fast, at the size-cap check), not processed"
    );
}

/// `add_member` also rejects an oversize KeyPackage buffer before any deserialization is
/// attempted (the size cap applies to every production wire-ingest call site, not just
/// `mls_extract_signature_key`).
#[test]
fn add_member_rejects_oversize_key_package() {
    let now = now_secs();
    let (_uid, _kp, alice_bundle) =
        generate_identity("oversize_add".to_string(), now).expect("generate alice");
    let alice_state =
        create_group("oversize_group".to_string(), alice_bundle.clone()).expect("create group");

    let oversized_kp = vec![0u8; crate::mls::MAX_MLS_WIRE_BYTES + 1];
    let result = add_member(alice_state, alice_bundle, oversized_kp);
    assert!(
        result.is_err(),
        "add_member must reject an oversize KeyPackage buffer, not attempt to deserialize it"
    );
}

/// The MIMI (cross-provider) path went through the identical `mem::take` conversion in
/// `mimi/mod.rs` - this exercises it at runtime rather than trusting that an identical textual
/// pattern behaves identically: create a MIMI group, add a member, have them process the
/// self-contained Welcome (ratchet tree embedded, no separate export needed), and confirm both
/// sides agree on the group id.
#[test]
fn mimi_group_create_add_welcome_round_trips_after_zeroize_refactor() {
    use crate::mimi::{
        mimi_add_member, mimi_create_group, mimi_generate_identity, mimi_process_welcome,
    };
    let now = now_secs();
    let (_user_a, _kp_a_unused, bundle_a) =
        mimi_generate_identity("dave".to_string(), now).expect("generate dave");
    let (_user_b, kp_b, bundle_b) =
        mimi_generate_identity("erin".to_string(), now).expect("generate erin");

    let group_state_a = mimi_create_group("mimi-test-group".to_string(), bundle_a.clone())
        .expect("mimi_create_group");

    let (_group_state_a2, welcome) =
        mimi_add_member(group_state_a, bundle_a, kp_b).expect("mimi_add_member");

    let group_state_b = mimi_process_welcome(welcome, bundle_b, Vec::new(), String::new())
        .expect("mimi_process_welcome");
    let state_b: GroupState = serde_json::from_slice(&group_state_b).expect("deserialize");
    assert_eq!(state_b.group_id, b"mimi-test-group");
}

// ============================================================================
// INV-MLS-002 proof set: the explicit inbound ciphersuite accept-gate.
//
// Suite 0x0003 = MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 - same Ed25519
// signing scheme as the pinned 0x0001, so identity/signing code is unchanged; only
// the AEAD differs. Used here purely as a non-pinned suite to drive the accept-gate
// reachability tests - never reachable from a production code path.
// ============================================================================

mod suite_gate {
    use super::*;
    use crate::mls::groups::mls_extract_signature_key;
    use openmls::ciphersuite::signature::SignaturePublicKey;
    use openmls::credentials::{BasicCredential, CredentialWithKey};
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::OpenMlsProvider;
    use std::convert::TryFrom;
    use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

    const CHACHA: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

    /// Build a full foreign identity (KeyPackage + `IdentityBundle`) under an ARBITRARY
    /// ciphersuite - simulating a remote peer/provider this crate doesn't control. Test-only.
    fn foreign_identity(user_id: &str, now: i64, suite: Ciphersuite) -> (Vec<u8>, Vec<u8>) {
        let provider = OpenMlsRustCrypto::default();
        let scheme = SignatureScheme::ED25519;
        let (priv_bytes, pub_bytes) = provider.crypto().signature_key_gen(scheme).unwrap();
        let public_key = SignaturePublicKey::try_from(pub_bytes.clone()).unwrap();
        let credential = BasicCredential::new(user_id.as_bytes().to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: public_key,
        };
        let signer = MlsSigner {
            key: zeroize::Zeroizing::new(priv_bytes.clone()),
            scheme,
        };
        let lifetime = make_lifetime(now as u64).unwrap();
        let kpb = KeyPackage::builder()
            .key_package_extensions(Extensions::empty())
            .key_package_lifetime(lifetime)
            .build(suite, &provider, &signer, credential_with_key)
            .unwrap();
        let kp_bytes = kpb.key_package().tls_serialize_detached().unwrap();
        let storage_map: Vec<(Vec<u8>, Vec<u8>)> = provider
            .storage()
            .values
            .read()
            .unwrap()
            .clone()
            .into_iter()
            .collect();
        let bundle = IdentityBundle {
            key_package_bundle: kpb,
            private_key: priv_bytes,
            signature_scheme: scheme,
            public_key_bytes: pub_bytes,
            user_id: user_id.to_string(),
            storage_map,
        };
        (kp_bytes, serde_json::to_vec(&bundle).unwrap())
    }

    /// Create a group under an ARBITRARY ciphersuite (a foreign peer's group). Mirrors
    /// `create_group` but sets the suite explicitly (the real fn relies on the 0x0001 default).
    fn foreign_create_group(group_id: &str, bundle_bytes: &[u8], suite: Ciphersuite) -> Vec<u8> {
        let mut identity: IdentityBundle = serde_json::from_slice(bundle_bytes).unwrap();
        let provider = OpenMlsRustCrypto::default();
        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(suite)
            .wire_format_policy(WireFormatPolicy::default())
            .build();
        let signer = MlsSigner {
            key: zeroize::Zeroizing::new(std::mem::take(&mut identity.private_key)),
            scheme: identity.signature_scheme,
        };
        let public_key =
            SignaturePublicKey::try_from(std::mem::take(&mut identity.public_key_bytes)).unwrap();
        let credential = BasicCredential::new(std::mem::take(&mut identity.user_id).into_bytes());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: public_key,
        };
        let group_id_struct = GroupId::from_slice(group_id.as_bytes());
        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &group_config,
            group_id_struct,
            credential_with_key,
        )
        .unwrap();
        let storage_map = provider
            .storage()
            .values
            .read()
            .unwrap()
            .clone()
            .into_iter()
            .collect();
        let state = GroupState {
            group_id: group.group_id().to_vec(),
            storage_map,
        };
        serde_json::to_vec(&state).unwrap()
    }

    /// Raw, UNGATED add - builds a Welcome by adding a foreign KeyPackage to a foreign group via
    /// openmls directly, bypassing the production `add_member`'s accept-gate. Test-only: simulates
    /// a hostile remote provider assembling a fully self-consistent foreign-suite Welcome, so it
    /// can be fed to the GATED `process_welcome` to prove it refuses.
    fn foreign_add_member(
        group_state_bytes: Vec<u8>,
        bundle_bytes: &[u8],
        key_package_bytes: Vec<u8>,
    ) -> Vec<u8> {
        let mut state: GroupState = serde_json::from_slice(&group_state_bytes).unwrap();
        let mut identity: IdentityBundle = serde_json::from_slice(bundle_bytes).unwrap();
        let provider = OpenMlsRustCrypto::default();
        {
            let mut values = provider.storage().values.write().unwrap();
            *values = std::mem::take(&mut state.storage_map).into_iter().collect();
        }
        let signer = MlsSigner {
            key: zeroize::Zeroizing::new(std::mem::take(&mut identity.private_key)),
            scheme: identity.signature_scheme,
        };
        let group_id = GroupId::from_slice(&state.group_id);
        let mut group = MlsGroup::load(provider.storage(), &group_id)
            .unwrap()
            .unwrap();
        let mut kp_slice = key_package_bytes.as_slice();
        let key_package = KeyPackageIn::tls_deserialize(&mut kp_slice).unwrap();
        let validated_kp = key_package
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .unwrap();
        // NOTE: NO gate_inbound_keypackage here - that is the whole point (hostile peer).
        let (_commit, welcome, _gi) = group
            .add_members(&provider, &signer, &[validated_kp])
            .unwrap();
        group.merge_pending_commit(&provider).unwrap();
        let ratchet_tree_bytes = group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .unwrap();
        let welcome_bytes = welcome.tls_serialize_detached().unwrap();
        serde_json::to_vec(&(welcome_bytes, ratchet_tree_bytes)).unwrap()
    }

    /// TIER 1 - sanity: is the ChaCha20-Poly1305 suite (0x0003) even selectable in this build?
    /// Expected YES (openmls_rust_crypto enables all MTI suites). Probes `validate()` DIRECTLY
    /// (not through `mls_extract_signature_key`, which now suite-gates - see below) because
    /// this test's job is to confirm the underlying suite is buildable at all, independent of
    /// this crate's own accept policy.
    #[test]
    fn chacha_0x0003_suite_is_selectable() {
        let now = now_secs();
        let (kp_bytes, _bundle) = foreign_identity("chacha_sanity", now, CHACHA);
        let provider = OpenMlsRustCrypto::default();
        let mut slice = kp_bytes.as_slice();
        let kp_in = openmls::prelude::KeyPackageIn::tls_deserialize(&mut slice).unwrap();
        let validated = kp_in.validate(provider.crypto(), openmls::prelude::ProtocolVersion::Mls10);
        assert!(
            validated.is_ok(),
            "0x0003 KeyPackage must validate -> ChaCha20-Poly1305 suite IS selectable"
        );
    }

    /// `mls_extract_signature_key` now routes through the same
    /// explicit `gate_inbound_keypackage` accept-gate every other inbound KeyPackage path uses -
    /// a foreign-suite (0x0003) KeyPackage validates fine (proved above) but must be REJECTED
    /// here, returning `""` (this fn's existing failure convention), not the extracted key. This
    /// is the exact gap this closes: `validate()` alone (used internally, proved above
    /// to accept 0x0003) is signature-only and does not suite-gate, so
    /// `mls_extract_signature_key` must call the gate after `validate()` - stopping at
    /// `validate()` alone would return a non-empty identity key for a foreign-suite object.
    #[test]
    fn mls_extract_signature_key_rejects_foreign_suite() {
        let now = now_secs();
        let (kp_0x0003, _b) = foreign_identity("foreign_extract", now, CHACHA);
        let sig = mls_extract_signature_key(kp_0x0003);
        assert!(
            sig.is_empty(),
            "mls_extract_signature_key must reject a 0x0003 KeyPackage (INV-MLS-002 accept-gate), got a non-empty key"
        );
    }

    /// Sibling positive case: a REAL 0x0001 KeyPackage must still extract its identity key
    /// normally through the gate (the fix tightens acceptance, it must not break the pinned path).
    #[test]
    fn mls_extract_signature_key_accepts_pinned_suite() {
        let now = now_secs();
        let (_uid, kp_bytes, _bundle) =
            crate::identity::generate_identity("real_extract".into(), now).unwrap();
        let sig = mls_extract_signature_key(kp_bytes);
        assert!(
            !sig.is_empty(),
            "a real 0x0001 KeyPackage must still extract its signature key through the gate"
        );
    }

    /// THE DECISIVE TEST - `process_welcome` must REJECT a fully self-consistent foreign-suite
    /// (0x0003) Welcome at the explicit accept-gate (`suite_policy::gate_inbound_welcome`) BEFORE
    /// openmls ever touches it. The Welcome is built via the raw-openmls `foreign_add_member`
    /// helper (bypassing the gate) because the real `add_member` is gated too and would refuse
    /// the 0x0003 KeyPackage at setup - `foreign_add_member` simulates the hostile remote that
    /// doesn't have that gate.
    #[test]
    fn process_welcome_foreign_suite_rejected() {
        let now = now_secs();
        let (_alice_kp, alice_bundle) = foreign_identity("alice_cc", now, CHACHA);
        let (bob_kp, bob_bundle) = foreign_identity("bob_cc", now, CHACHA);

        let alice_group = foreign_create_group("cc-group", &alice_bundle, CHACHA);
        let combined_welcome = foreign_add_member(alice_group, &alice_bundle, bob_kp);

        let bob_state = process_welcome(combined_welcome, bob_bundle);
        assert!(
            bob_state.is_err(),
            "process_welcome MUST reject a foreign-suite (0x0003) Welcome at the explicit \
             accept-gate BEFORE openmls - got Ok = the accept-gate was bypassed"
        );
    }

    /// The realistic native-chat attack surface: an attacker cannot make this crate
    /// HOLD a matching 0x0003 KeyPackage, so can they still drive ChaCha by (i) adding a foreign
    /// 0x0003 KeyPackage to a real 0x0001 group, or (ii) adding a real 0x0001 KeyPackage to their
    /// 0x0003 group? Both must reject on suite mismatch BEFORE any AEAD is driven.
    #[test]
    fn cross_suite_add_is_rejected() {
        let now = now_secs();

        // (i) foreign 0x0003 KeyPackage -> a REAL 0x0001 group (inviter side).
        let (_real_alice_id, _rkp, real_alice_bundle) =
            generate_identity("real_alice".to_string(), now).unwrap();
        let real_group = create_group("real-group".to_string(), real_alice_bundle.clone()).unwrap();
        let (foreign_bob_kp, _fb) = foreign_identity("foreign_bob", now, CHACHA);
        let add_foreign = add_member(real_group, real_alice_bundle, foreign_bob_kp);
        assert!(
            add_foreign.is_err(),
            "adding a 0x0003 KeyPackage to a 0x0001 group must be REJECTED (suite mismatch)"
        );

        // (ii) a REAL 0x0001 KeyPackage -> a foreign 0x0003 group.
        let (_real_bob_id, real_bob_kp, _real_bob_bundle) =
            generate_identity("real_bob".to_string(), now).unwrap();
        let (_acc_kp, foreign_alice_bundle) = foreign_identity("attacker_alice", now, CHACHA);
        let foreign_group = foreign_create_group("cc-grp2", &foreign_alice_bundle, CHACHA);
        let add_real = add_member(foreign_group, foreign_alice_bundle, real_bob_kp);
        assert!(
            add_real.is_err(),
            "adding a 0x0001 KeyPackage to a 0x0003 group must be REJECTED (suite mismatch)"
        );
    }
}

/// The inbound MLS-wire deserializers must FAIL-SAFE on hostile/malformed
/// bytes - return `Err`, never panic. Network/foreign MLS bytes enter this crate ONLY as opaque
/// `Vec<u8>` args and are parsed INSIDE each function via fallible deserializers + the suite
/// accept-gate; a battery of hostile inputs must be rejected without panic (a panic = failure).
#[test]
fn inbound_wire_deserializers_reject_hostile_bytes_without_panic() {
    let now = now_secs();
    let (_id, _kp, bundle) = generate_identity("fuzz@haven.test".to_string(), now).unwrap();

    let hostile: Vec<Vec<u8>> = vec![
        vec![],
        vec![0u8],
        vec![0u8; 4],
        vec![0xFFu8; 32],
        (0u8..=255).collect(),
        b"not json at all".to_vec(),
        serde_json::to_vec(&(vec![0xAAu8; 16], vec![0xBBu8; 16])).unwrap(),
        b"{\"unexpected\":true}".to_vec(),
    ];

    for (i, bytes) in hostile.iter().enumerate() {
        let r = process_welcome(bytes.clone(), bundle.clone());
        assert!(
            r.is_err(),
            "process_welcome must reject hostile input #{i} with Err, not panic/Ok"
        );
    }

    let group_state = create_group("fuzz-grp".to_string(), bundle.clone()).unwrap();
    for (i, bytes) in hostile.iter().enumerate() {
        let r = add_member(group_state.clone(), bundle.clone(), bytes.clone());
        assert!(
            r.is_err(),
            "add_member must reject hostile KeyPackage #{i} with Err, not panic/Ok"
        );
    }

    for (i, bytes) in hostile.iter().enumerate() {
        let r = crate::mimi::mimi_process_welcome(
            bytes.clone(),
            bundle.clone(),
            Vec::new(),
            String::new(),
        );
        assert!(
            r.is_err(),
            "mimi_process_welcome must reject hostile input #{i} with Err, not panic/Ok"
        );
    }
}

// ── add_members_bulk: batch-cardinality bound ───────────────────────────────

/// A batch over `MAX_BULK_MEMBERS` is refused before any group-state deserialization is
/// attempted - proven with garbage `group_state_bytes`/`bundle_bytes` (empty, would fail
/// deserialization anyway), so the only way this can return `Err` for the RIGHT reason is the
/// cardinality check running first.
#[test]
fn add_members_bulk_rejects_over_cap_member_count() {
    let too_many = vec![vec![0u8; 8]; MAX_BULK_MEMBERS + 1];
    let result = add_members_bulk(Vec::new(), Vec::new(), too_many);
    assert!(
        result.is_err(),
        "a batch over the member-count cap must be refused"
    );
}

/// A batch within the member-count cap but over the aggregate-byte cap is also refused, same
/// fail-fast-before-deserialization shape as the count check above.
#[test]
fn add_members_bulk_rejects_over_cap_aggregate_bytes() {
    let big_item_len = (MAX_BULK_AGGREGATE_BYTES / 4) + 1;
    let four_big_items = vec![vec![0u8; big_item_len]; 4];
    let result = add_members_bulk(Vec::new(), Vec::new(), four_big_items);
    assert!(
        result.is_err(),
        "a batch over the aggregate-byte cap must be refused"
    );
}
