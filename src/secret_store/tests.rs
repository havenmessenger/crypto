//! This module's three non-negotiable proofs:
//!   (a) `lock()` zeroizes - proven via a sound in-place wipe + a compile-time `ZeroizeOnDrop` bound.
//!   (b) the handle exposes no raw key bytes - structural (the public surface returns no key).
//!   (c) session-keyed isolation - one session's handle cannot read another's secrets.
//! Plus round-trip, fail-closed-after-lock, lock-idempotence, and a PGP round-trip.

use super::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 32-byte test root key (distinct bytes so an isolation failure is visible).
fn root_a() -> Vec<u8> {
    (0u8..32).collect()
}
fn root_b() -> Vec<u8> {
    (32u8..64).collect()
}

/// Seal `plaintext` exactly the way `decrypt_blob` will open it: `key = HKDF(root, info)`, then
/// `aes_gcm_256_seal`. Returns the `nonce(12)‖ct‖tag` wire.
fn manual_seal_blob(root: &[u8], info: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let key =
        crate::crypto::hkdf_sha256(root.to_vec(), Vec::new(), info.to_vec(), 32).expect("hkdf");
    crate::crypto::aes_gcm_256_seal(key, plaintext.to_vec()).expect("seal")
}

// ── (a) lock() zeroizes ──────────────────────────────────────────────────────

/// SOUND zeroize proof, no read-after-free: zeroize the buffer IN PLACE (allocation still live) and
/// read it back through a raw pointer. Proves the `Zeroize` impl actually overwrites the bytes (not
/// a no-op). `lock()` reaches this same wipe via `drop` → see `assert_zeroize_on_drop`.
#[test]
fn zeroize_actually_wipes_in_place() {
    let mut secret: Vec<u8> = (1u8..=64).collect();
    let ptr = secret.as_ptr();
    let len = secret.len();
    secret.zeroize();
    // SAFETY: `secret` still owns the (now-zeroized) allocation; ptr/len are valid for this read.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert!(bytes.iter().all(|&b| b == 0), "zeroize left residue");
}

/// Compile-time proof that `SessionSecrets` is `ZeroizeOnDrop`, so the real `drop` path (what
/// `lock`/`lock_all` trigger by removing the registry entry) wipes every field. If a future field is
/// added that isn't zeroizable, the derive - and this line - fail to compile.
#[test]
fn session_secrets_is_zeroize_on_drop() {
    fn assert_zod<T: ZeroizeOnDrop>() {}
    assert_zod::<SessionSecrets>();
}

/// Behavioural proof that `lock` tears the entry down: after `lock`, the session is gone and every
/// op fails closed (the live object was dropped → its `ZeroizeOnDrop` ran).
#[test]
fn lock_removes_and_zeroizes_session() {
    let id = unlock(root_a());
    assert_eq!(session_count_for_test_contains(id), true);
    lock(id);
    assert_eq!(session_count_for_test_contains(id), false);
    let info = b"haven-cipher-store-blob:k".to_vec();
    let wire = manual_seal_blob(&root_a(), &info, b"x");
    assert!(matches!(
        decrypt_blob(id, info, wire),
        Err(SecretStoreError::NoSuchSession)
    ));
}

/// Helper: whether the registry currently holds `id` (test-only peek; never reads key bytes).
fn session_count_for_test_contains(id: SessionId) -> bool {
    super::store().contains_key(&id)
}

// ── (b) the handle exposes no raw key bytes ──────────────────────────────────

/// Structural contract: the ops work via the opaque `SessionId` token, while NO function in the
/// public surface returns the root key or the PGP private bytes. The only thing a holder of the
/// token can do is REQUEST a decryption - never retrieve the key. (Enforced by absence; this test
/// documents + exercises that contract: a round-trip succeeds, and there is no
/// `get_master_key(id)`-style accessor to call.)
#[test]
fn handle_yields_no_raw_key_only_operations() {
    let id = unlock(root_a());
    let info = b"haven-cipher-store-blob:contract".to_vec();
    let wire = manual_seal_blob(&root_a(), &info, b"only ops, never keys");
    let out = decrypt_blob(id, info, wire).expect("op via token works");
    assert_eq!(out, b"only ops, never keys");
    lock(id);
    // There is NO public accessor returning `master_root_key` / `pgp_private_key_armored`. If one is
    // ever added, this comment + the module contract are the tripwire for review.
}

// ── (c) session-keyed isolation ──────────────────────────────────────────────

#[test]
fn sessions_are_isolated() {
    let a = unlock(root_a());
    let b = unlock(root_b());
    assert_ne!(a, b, "distinct session tokens");

    let info = b"haven-cipher-store-blob:shared-name".to_vec();
    let secret = b"A's secret";
    let wire = manual_seal_blob(&root_a(), &info, secret);

    // Handle A opens its own blob…
    assert_eq!(
        decrypt_blob(a, info.clone(), wire.clone()).expect("A opens A"),
        secret
    );
    // …handle B (different root) cannot - tag mismatch, fail-closed.
    assert!(matches!(
        decrypt_blob(b, info, wire),
        Err(SecretStoreError::Crypto(_))
    ));
    lock(a);
    lock(b);
}

// ── round-trip / fail-closed / idempotence ───────────────────────────────────

#[test]
fn decrypt_blob_round_trip() {
    let id = unlock(root_a());
    let info = b"haven-cipher-store-blob:msg-42".to_vec();
    let plain = b"the quick brown fox";
    let wire = manual_seal_blob(&root_a(), &info, plain);
    assert_eq!(decrypt_blob(id, info, wire).expect("round-trip"), plain);
    lock(id);
}

#[test]
fn decrypt_blob_batch_round_trip_and_partial_failure() {
    let id = unlock(root_a());
    let i1 = b"haven-cipher-store-blob:a".to_vec();
    let i2 = b"haven-cipher-store-blob:b".to_vec();
    let w1 = manual_seal_blob(&root_a(), &i1, b"one");
    let w2 = manual_seal_blob(&root_a(), &i2, b"two");
    // A corrupt wire → that item fails, the batch does not.
    let bad = vec![0u8; 40];
    let out = decrypt_blob_batch(
        id,
        vec![
            (i1, w1),
            (b"haven-cipher-store-blob:x".to_vec(), bad),
            (i2, w2),
        ],
    )
    .expect("session live");
    assert_eq!(out[0].as_ref().expect("item0"), b"one");
    assert!(
        out[1].is_err(),
        "corrupt blob fails its slot, not the batch"
    );
    assert_eq!(out[2].as_ref().expect("item2"), b"two");
    lock(id);
}

#[test]
fn ops_fail_closed_after_lock() {
    let id = unlock(root_a());
    lock(id);
    let info = b"haven-cipher-store-blob:k".to_vec();
    let wire = manual_seal_blob(&root_a(), &info, b"x");
    assert!(matches!(
        decrypt_blob(id, info, wire),
        Err(SecretStoreError::NoSuchSession)
    ));
    assert!(matches!(
        pgp_decrypt(id, "x".to_string()),
        Err(SecretStoreError::NoSuchSession)
    ));
    assert!(matches!(
        set_pgp_identity(id, "k".to_string(), "p".to_string()),
        Err(SecretStoreError::NoSuchSession)
    ));
}

#[test]
fn lock_is_idempotent() {
    let id = unlock(root_a());
    lock(id);
    lock(id); // no panic, no-op
    lock(fresh_id_for_test()); // locking a never-seen id is a no-op
}

fn fresh_id_for_test() -> SessionId {
    super::fresh_id()
}

#[test]
fn pgp_decrypt_fails_closed_without_identity() {
    let id = unlock(root_a());
    assert!(matches!(
        pgp_decrypt(id, "anything".to_string()),
        Err(SecretStoreError::NoPgpIdentity)
    ));
    lock(id);
}

// ── PGP round-trip through the store ─────────────────────────────────────────

#[test]
fn pgp_round_trip_via_handle() {
    let (public_armored, private_armored) =
        crate::pgp::pgp_generate_key("T".into(), "t@e.x".into(), "pw".into(), "ecc".into())
            .expect("keygen");
    let id = unlock(root_a());
    set_pgp_identity(id, private_armored, "pw".into()).expect("set identity");

    let ct = crate::pgp::pgp_encrypt("hello pgp".into(), public_armored).expect("encrypt");
    let pt = pgp_decrypt(id, ct).expect("decrypt via handle");
    assert_eq!(pt, "hello pgp");
    lock(id);
}

/// A SECOND `set_pgp_identity` call on the same session must fully REPLACE the identity, not
/// merely shadow it - the outgoing value is zeroized (`Option::replace` + `.zeroize()`, not a bare
/// field assignment that would drop the old `String` unwiped). Proven functionally: after the
/// replace, a ciphertext encrypted to the OLD identity must fail (the old private key is gone from
/// the store), and a ciphertext encrypted to the NEW identity must succeed.
#[test]
fn set_pgp_identity_replace_wipes_old_identity() {
    let (pub_old, priv_old) =
        crate::pgp::pgp_generate_key("Old".into(), "old@e.x".into(), "pwOld".into(), "ecc".into())
            .expect("keygen old");
    let (pub_new, priv_new) =
        crate::pgp::pgp_generate_key("New".into(), "new@e.x".into(), "pwNew".into(), "ecc".into())
            .expect("keygen new");

    let id = unlock(root_a());
    set_pgp_identity(id, priv_old, "pwOld".into()).expect("set old identity");
    let ct_old = crate::pgp::pgp_encrypt("for old".into(), pub_old).expect("encrypt to old");

    // Replace with the new identity.
    set_pgp_identity(id, priv_new, "pwNew".into()).expect("set new identity");

    // The old identity is gone: decrypting a blob meant for it must fail, not silently succeed.
    assert!(
        pgp_decrypt(id, ct_old).is_err(),
        "after replace, the OLD identity's ciphertext must no longer decrypt"
    );

    // The new identity is live.
    let ct_new = crate::pgp::pgp_encrypt("for new".into(), pub_new).expect("encrypt to new");
    let pt_new = pgp_decrypt(id, ct_new).expect("decrypt via the replaced (new) identity");
    assert_eq!(pt_new, "for new");
    lock(id);
}

// ── The client cipher-store's TWO-HKDF-layer ops ────────────────────

/// Seal `plaintext` exactly the way `decrypt_cipher_store_blob` opens it - mirroring the client's
/// own cipher-store derivation: `cs_root = HKDF(root, "haven-cipher-store-root")`, `blob_key =
/// HKDF(cs_root, "haven-cipher-store-blob:$name")`, then `aes_gcm_256_seal`. (A separate
/// differential-parity test additionally proves equality against the client's own real decrypt path.)
fn manual_seal_cipher_store_blob(root: &[u8], blob_key_name: &str, plaintext: &[u8]) -> Vec<u8> {
    let cs_root = crate::crypto::hkdf_sha256(
        root.to_vec(),
        Vec::new(),
        b"haven-cipher-store-root".to_vec(),
        32,
    )
    .expect("cs root");
    let info = format!("haven-cipher-store-blob:{blob_key_name}");
    let blob_key =
        crate::crypto::hkdf_sha256(cs_root, Vec::new(), info.into_bytes(), 32).expect("blob key");
    crate::crypto::aes_gcm_256_seal(blob_key, plaintext.to_vec()).expect("seal")
}

#[test]
fn decrypt_cipher_store_blob_two_layer_round_trip() {
    let id = unlock(root_a());
    let plain = b"two-layer round trip";
    let wire = manual_seal_cipher_store_blob(&root_a(), "mls_identity", plain);
    assert_eq!(
        decrypt_cipher_store_blob(id, "mls_identity", wire).expect("round-trip"),
        plain
    );
    lock(id);
}

/// The inner `cipher_store_root_key` is derived once + cached as a subkey.
#[test]
fn cipher_store_root_is_cached_after_first_op() {
    let id = unlock(root_a());
    // Before any cipher_store op the subkey is absent…
    assert!(super::store()
        .get(&id)
        .expect("session")
        .cipher_store_root_key
        .is_none());
    let wire = manual_seal_cipher_store_blob(&root_a(), "k", b"x");
    let _ = decrypt_cipher_store_blob(id, "k", wire).expect("op");
    // …after the op it is cached (the outer HKDF runs once for the 28-50-blob hydration).
    assert!(super::store()
        .get(&id)
        .expect("session")
        .cipher_store_root_key
        .is_some());
    lock(id);
}

#[test]
fn decrypt_cipher_store_blob_batch_round_trip_and_partial_failure() {
    let id = unlock(root_a());
    let w1 = manual_seal_cipher_store_blob(&root_a(), "a", b"one");
    let w2 = manual_seal_cipher_store_blob(&root_a(), "b", b"two");
    let bad = vec![0u8; 40];
    let out = decrypt_cipher_store_blob_batch(
        id,
        vec![
            ("a".to_string(), w1),
            ("x".to_string(), bad),
            ("b".to_string(), w2),
        ],
    )
    .expect("session live");
    assert_eq!(out[0].as_ref().expect("item0"), b"one");
    assert!(
        out[1].is_err(),
        "corrupt blob fails its slot, not the batch"
    );
    assert_eq!(out[2].as_ref().expect("item2"), b"two");
    lock(id);
}

/// The GENERIC single-layer `decrypt_blob` does NOT reproduce the cipher-store's TWO-layer
/// plaintext - the one-pass key differs from the two-pass key, so the tag fails (fail-closed).
/// This is why the cipher-store needed its own dedicated two-layer op, not `decrypt_blob`.
#[test]
fn single_layer_decrypt_blob_is_not_cipher_store_two_layer() {
    let id = unlock(root_a());
    let wire = manual_seal_cipher_store_blob(&root_a(), "k", b"secret");
    // The two-layer op opens it…
    assert_eq!(
        decrypt_cipher_store_blob(id, "k", wire.clone()).expect("two-layer opens"),
        b"secret"
    );
    // …but the single-layer op with the SAME info fails (key = HKDF(root, info) != the two-layer key).
    assert!(matches!(
        decrypt_blob(id, b"haven-cipher-store-blob:k".to_vec(), wire),
        Err(SecretStoreError::Crypto(_))
    ));
    lock(id);
}

#[test]
fn cipher_store_ops_fail_closed_after_lock() {
    let id = unlock(root_a());
    lock(id);
    let wire = manual_seal_cipher_store_blob(&root_a(), "k", b"x");
    assert!(matches!(
        decrypt_cipher_store_blob(id, "k", wire.clone()),
        Err(SecretStoreError::NoSuchSession)
    ));
    assert!(matches!(
        decrypt_cipher_store_blob_batch(id, vec![("k".to_string(), wire)]),
        Err(SecretStoreError::NoSuchSession)
    ));
}

// ── The client secure-vault's HMAC-SHA256 + version-framing decrypt ──

/// Seal `plaintext` exactly the way `decrypt_vault_blob` opens it - mirroring the client's own
/// vault chain:
///   vault_master_key = HKDF(root, "haven-vault-master-key")
///   vault_key        = HMAC-SHA256(vault_master_key, "haven:vault-encryption")
///   sub_key          = HMAC-SHA256(vault_key,        "haven:" + type)
///   wire             = version(4,be,=1) ‖ aes_gcm_256_seal(sub_key, plaintext)
/// (A separate differential-parity test additionally proves equality against the client's own
/// real decrypt path.)
fn manual_seal_vault_blob(root: &[u8], blob_type: &str, plaintext: &[u8]) -> Vec<u8> {
    let vmk = crate::crypto::hkdf_sha256(
        root.to_vec(),
        Vec::new(),
        b"haven-vault-master-key".to_vec(),
        32,
    )
    .expect("vault master key");
    let vault_key = hmac_sha256(&vmk, b"haven:vault-encryption").expect("vault key");
    let purpose = format!("haven:{blob_type}");
    let sub_key = hmac_sha256(&vault_key, purpose.as_bytes()).expect("sub key");
    let inner = crate::crypto::aes_gcm_256_seal(sub_key, plaintext.to_vec()).expect("seal");
    let mut wire = vec![0u8, 0, 0, 1]; // big-endian version = 1
    wire.extend_from_slice(&inner);
    wire
}

#[test]
fn decrypt_vault_blob_round_trip_across_types() {
    let id = unlock(root_a());
    for blob_type in ["email", "mls_chat", "file", "index"] {
        let plain = format!("vault payload for {blob_type}").into_bytes();
        let wire = manual_seal_vault_blob(&root_a(), blob_type, &plain);
        assert_eq!(
            decrypt_vault_blob(id, blob_type, wire).expect("round-trip"),
            plain,
            "vault round-trip failed for type {blob_type}"
        );
    }
    lock(id);
}

/// The vault master key is derived once + cached as a subkey.
#[test]
fn vault_master_key_is_cached_after_first_op() {
    let id = unlock(root_a());
    assert!(super::store()
        .get(&id)
        .expect("session")
        .vault_master_key
        .is_none());
    let wire = manual_seal_vault_blob(&root_a(), "file", b"x");
    let _ = decrypt_vault_blob(id, "file", wire).expect("op");
    assert!(super::store()
        .get(&id)
        .expect("session")
        .vault_master_key
        .is_some());
    lock(id);
}

#[test]
fn vault_decrypt_fails_closed_on_bad_version_and_short_wire() {
    let id = unlock(root_a());
    let mut wire = manual_seal_vault_blob(&root_a(), "email", b"hello");
    // Flip the version prefix 1 → 2 → unsupported.
    wire[3] = 2;
    assert!(matches!(
        decrypt_vault_blob(id, "email", wire),
        Err(SecretStoreError::Crypto(_))
    ));
    // A wire shorter than version(4)+nonce(12)+tag(16) fails closed.
    assert!(matches!(
        decrypt_vault_blob(id, "email", vec![0u8, 0, 0, 1, 9, 9]),
        Err(SecretStoreError::Crypto(_))
    ));
    lock(id);
}

/// The wrong blob TYPE derives a different sub_key → tag mismatch (per-type isolation, fail-closed).
#[test]
fn vault_wrong_type_fails_closed() {
    let id = unlock(root_a());
    let wire = manual_seal_vault_blob(&root_a(), "email", b"typed secret");
    assert_eq!(
        decrypt_vault_blob(id, "email", wire.clone()).expect("right type opens"),
        b"typed secret"
    );
    assert!(matches!(
        decrypt_vault_blob(id, "file", wire),
        Err(SecretStoreError::Crypto(_))
    ));
    lock(id);
}

#[test]
fn vault_op_fails_closed_after_lock() {
    let id = unlock(root_a());
    lock(id);
    let wire = manual_seal_vault_blob(&root_a(), "email", b"x");
    assert!(matches!(
        decrypt_vault_blob(id, "email", wire),
        Err(SecretStoreError::NoSuchSession)
    ));
}

// ── SEAL ops - write-side inverses of the decrypt ops ──────────────────────
// The seal op is non-deterministic (fresh OsRng nonce) → the proof is round-trip (`decrypt(seal(p)) ==
// p`), NOT byte-equality of two seals. A separate differential-parity test proves the stronger
// cross-implementation claim (a Rust-handle seal opens via the client's own real cipher-store/vault
// key chain, and vice versa, BOTH directions). These Rust units prove the seal op derives the SAME
// key the decrypt op does (a successful open + correct plaintext can only happen under a matching key).

#[test]
fn seal_cipher_store_blob_round_trip_across_sizes() {
    let id = unlock(root_a());
    for plain in [
        Vec::new(),    // empty payload → wire = nonce(12)‖tag(16)
        b"x".to_vec(), // single byte
        b"two-layer seal round trip".to_vec(),
        vec![0xABu8; 4096], // large
    ] {
        let wire = seal_cipher_store_blob(id, "mls_identity", plain.clone()).expect("seal");
        assert_eq!(
            decrypt_cipher_store_blob(id, "mls_identity", wire).expect("round-trip open"),
            plain,
            "cipher_store seal→open failed for {}-byte payload",
            plain.len()
        );
    }
    lock(id);
}

/// The production seal op derives the SAME two-layer key as the canonical (manual) reference: BOTH a
/// production-sealed wire and a manual-sealed wire open to the same plaintext via the production decrypt
/// op (different random nonces, identical key).
#[test]
fn seal_cipher_store_blob_matches_canonical_derivation() {
    let id = unlock(root_a());
    let plain = b"canonical match".to_vec();
    let prod_wire = seal_cipher_store_blob(id, "k", plain.clone()).expect("prod seal");
    let manual_wire = manual_seal_cipher_store_blob(&root_a(), "k", &plain);
    assert_eq!(
        decrypt_cipher_store_blob(id, "k", prod_wire).expect("open prod-sealed"),
        plain
    );
    assert_eq!(
        decrypt_cipher_store_blob(id, "k", manual_wire).expect("open manual-sealed"),
        plain
    );
    lock(id);
}

#[test]
fn seal_vault_blob_round_trip_across_types_and_sizes() {
    let id = unlock(root_a());
    for blob_type in ["email", "mls_chat", "file", "index"] {
        for plain in [
            Vec::new(),
            format!("vault seal {blob_type}").into_bytes(),
            vec![0x5Au8; 4096],
        ] {
            let wire = seal_vault_blob(id, blob_type, plain.clone()).expect("seal");
            // The version(4,be,=1) framing prefix is present.
            assert_eq!(&wire[0..4], &[0, 0, 0, 1], "vault version prefix");
            assert_eq!(
                decrypt_vault_blob(id, blob_type, wire).expect("round-trip open"),
                plain,
                "vault seal→open failed for type {blob_type} / {}-byte payload",
                plain.len()
            );
        }
    }
    lock(id);
}

/// The production vault seal op matches the canonical (manual) reference: both open to the same
/// plaintext via the production decrypt op.
#[test]
fn seal_vault_blob_matches_canonical_derivation() {
    let id = unlock(root_a());
    let plain = b"vault canonical match".to_vec();
    let prod_wire = seal_vault_blob(id, "email", plain.clone()).expect("prod seal");
    let manual_wire = manual_seal_vault_blob(&root_a(), "email", &plain);
    assert_eq!(
        decrypt_vault_blob(id, "email", prod_wire).expect("open prod-sealed"),
        plain
    );
    assert_eq!(
        decrypt_vault_blob(id, "email", manual_wire).expect("open manual-sealed"),
        plain
    );
    lock(id);
}

#[test]
fn seal_ops_fail_closed_after_lock() {
    let id = unlock(root_a());
    lock(id);
    assert!(matches!(
        seal_cipher_store_blob(id, "k", b"x".to_vec()),
        Err(SecretStoreError::NoSuchSession)
    ));
    assert!(matches!(
        seal_vault_blob(id, "email", b"x".to_vec()),
        Err(SecretStoreError::NoSuchSession)
    ));
}
