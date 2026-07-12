//! Tier-1 session secret-store - the stateful, handle-based custodian of a session's long-lived
//! secret material.
//!
//! # Why this module exists (the custody hole it closes)
//! Haven's long-lived secrets were previously custodied in the client's managed-language layer:
//! the master key lived in a garbage-collected string type (immutable + GC'd → un-zeroizable),
//! and on web the master key / PGP passphrase / auth password sat in PLAINTEXT browser storage -
//! JS-readable, XSS-reachable, and one CSP-bypass from theft. This module makes RUST the
//! custodian instead: the client hands the already-derived root key in ONCE (`unlock`), receives
//! an OPAQUE handle (a token, never the key), and thereafter calls handle-based ops
//! (`decrypt_blob`, `pgp_decrypt`) - the client never holds raw key bytes again. `lock` drops +
//! ZEROIZES the entry, replacing the prior "set the reference to null" pattern (which only drops
//! a GC reference and never wipes the underlying memory).
//!
//! # Limitations
//! This closes the un-wipeable managed-string in-memory window and, once fully wired on web, the
//! plaintext-browser-storage window - the web secret then lives in WASM linear memory, NOT
//! plaintext-JS-readable and NOT reload-persisted. But WASM linear memory is NOT a secure enclave
//! (better than plaintext browser storage, NOT equivalent to a mobile OS keychain/keystore). And
//! the passphrase still transits the client layer ONCE at unlock (the user types it there) - this
//! design minimizes RESIDENCE of the secret, it cannot eliminate the initial TRANSIT.
//!
//! # Scope (infrastructure only, at this module's introduction)
//! This module builds the store + handle + ops and unit-tests them; introducing it did not, by
//! itself, cut over any production caller - the client's existing key paths kept running
//! unchanged for a period, gaining a dormant handle-based path alongside the live one, with the
//! actual switchover (and removal of key-passing entirely) as separate, later, irreversible work.
//!
//! # Layer count
//! `decrypt_blob(handle, info, wire)` is the GENERIC SINGLE-HKDF-layer op (`HKDF(root, info) →
//! open`). The client's cipher-store abstraction derives keys in TWO HKDF passes - `HKDF(master_root,
//! "haven-cipher-store-root")` then `HKDF(that, "haven-cipher-store-blob:$name")` - so its
//! byte-identical op is `decrypt_cipher_store_blob`, NOT `decrypt_blob`. The single-layer op is
//! kept for its own test coverage and any future single-layer consumer.
//!
//! # Zeroize posture (house pattern - `zeroize`, NOT `secrecy`)
//! The secret struct derives `ZeroizeOnDrop`; its fields are write-once + never grown (no
//! realloc-copy orphan can survive un-wiped). We deliberately do NOT add the `secrecy` crate (a
//! new auditor-visible dependency on the public crypto repo) - `zeroize` delivers the drop→wipe
//! property the design requires.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// An opaque, process-internal session token. NOT a secret (it is a lookup index, never a key);
/// random only as defense-in-depth against a fabricated/guessed token reaching the registry.
pub type SessionId = u128;

// The Dart-exposed FRB batch-item structs live in the consuming application, not here -
// crypto-core must not depend on the crate that wraps it (the same reasoning as the
// `PgpSignatureInfo` split documented in `crate::pgp`). The batch fns below take plain
// `(Vec<u8>, Vec<u8>)` / `(String, Vec<u8>)` tuples instead; thin wrappers on the application
// side do the struct→tuple conversion.

/// Typed, fail-closed errors; the FRB boundary maps them to `anyhow::Error`.
#[derive(thiserror::Error, Debug)]
pub enum SecretStoreError {
    /// No live session for this handle - locked, never unlocked, or already torn down.
    #[error("no such session (locked, never unlocked, or already torn down)")]
    NoSuchSession,
    /// The session holds no PGP identity yet - call `set_pgp_identity` first.
    #[error("session holds no PGP identity (call set_pgp_identity first)")]
    NoPgpIdentity,
    /// The underlying HKDF / AES-GCM / PGP op failed (bad tag, malformed wire, wrong passphrase…).
    #[error("crypto operation failed: {0}")]
    Crypto(String),
}

/// The custodied secret material for ONE session. Every field is a heap secret; the derived
/// `ZeroizeOnDrop` impl wipes them all when the struct is dropped (i.e. when `lock` / `lock_all`
/// removes the registry entry, or the process tears the registry down).
///
/// Realloc-copy safety: `master_root_key` is written ONCE at `unlock` (moved in from the
/// caller's `Vec<u8>`) and NEVER grown / pushed → its backing allocation never reallocates → no
/// orphaned pre-realloc copy can survive un-wiped.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SessionSecrets {
    /// The session root key the handle ops derive per-blob subkeys from (the value the client's
    /// managed-language layer held un-wipeably before this store existed).
    master_root_key: Vec<u8>,
    /// Lazily-derived + cached `cipher_store_root_key = HKDF(master_root_key,
    /// "haven-cipher-store-root")` - the INNER root of the client's cipher-store two-HKDF-layer
    /// chain. Cached so a multi-blob login hydration runs the OUTER HKDF once. `None` until the
    /// first cipher-store op; wiped with the struct (`ZeroizeOnDrop`).
    /// Realloc-copy safe: written once (set when `None`), never grown.
    cipher_store_root_key: Option<Vec<u8>>,
    /// Lazily-derived + cached `vault_master_key = HKDF(master_root_key, "haven-vault-master-key")` -
    /// the raw bytes the client's secure-vault layer holds under its own (legacy-misnamed) field.
    /// The client passes a distinct vault master key, not the database key, so the vault is not
    /// entangled with a separate, unrelated custody question. The two HMAC-SHA256 sublayers
    /// (vault key / per-type sub-key) are recomputed per blob (HMAC is ~µs). `None` until
    /// the first vault op; wiped with the struct. Realloc-copy safe: written once, never grown.
    vault_master_key: Option<Vec<u8>>,
    /// The PGP private key (ASCII-armored), set lazily via `set_pgp_identity` (the identity key is
    /// loaded after unlock in the real flow). `None` until set; `pgp_decrypt` fails closed until set.
    pgp_private_key_armored: Option<String>,
    /// The PGP key's at-rest passphrase (INV-KEY-001). `None` until `set_pgp_identity`.
    pgp_passphrase: Option<String>,
}

/// Process-global session registry. The OPAQUE handle Dart holds carries only a `SessionId` token
/// INTO this map - never an `Arc<SessionSecrets>` - so `lock` deterministically wipes (removing the
/// entry drops the only owner → `ZeroizeOnDrop` runs NOW, not whenever Dart GC happens to release an
/// Arc).
///
/// The first process-global mutable state in this crate - deliberate: this module is exactly the
/// move from stateless-per-op crypto to a stateful custodian. Single `Mutex`, no `.await` held
/// across the lock, ops are sub-millisecond → no contention concern.
static STORE: LazyLock<Mutex<HashMap<SessionId, SessionSecrets>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn store() -> MutexGuard<'static, HashMap<SessionId, SessionSecrets>> {
    // A panicked holder would only have been mid-insert/remove of opaque entries; recover the guard
    // rather than poison the whole custody surface for the rest of the session.
    STORE.lock().unwrap_or_else(PoisonError::into_inner)
}

fn fresh_id() -> SessionId {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    u128::from_le_bytes(b)
}

/// Custody the already-derived session root key; return its opaque token. This module owns
/// custody of the already-derived key, not the passphrase→key derivation itself; the caller
/// derives the key and hands it in once. The input `Vec<u8>` is MOVED into the store (no copy).
#[must_use]
pub fn unlock(master_root_key: Vec<u8>) -> SessionId {
    let id = fresh_id();
    store().insert(
        id,
        SessionSecrets {
            master_root_key,
            cipher_store_root_key: None,
            vault_master_key: None,
            pgp_private_key_armored: None,
            pgp_passphrase: None,
        },
    );
    id
}

/// Populate this session's PGP identity (armored private key + at-rest passphrase). Fails closed if
/// the session does not exist. A SECOND call (re-set) zeroizes the outgoing OLD value before it
/// drops - `Option::replace` returns the previous value instead of letting the assignment silently
/// drop it unwiped, which is what plain `entry.field = Some(new)` would do.
pub fn set_pgp_identity(
    id: SessionId,
    private_key_armored: String,
    passphrase: String,
) -> Result<(), SecretStoreError> {
    let mut s = store();
    let entry = s.get_mut(&id).ok_or(SecretStoreError::NoSuchSession)?;
    if let Some(mut old) = entry.pgp_private_key_armored.replace(private_key_armored) {
        old.zeroize();
    }
    if let Some(mut old) = entry.pgp_passphrase.replace(passphrase) {
        old.zeroize();
    }
    drop(s);
    Ok(())
}

/// Drop + zeroize one session. Idempotent (locking an absent / already-locked session is a no-op).
/// Replaces the client's prior "set the key reference to null" pattern, which only drops a GC
/// reference and never wipes memory. MUST be called by the session-scope teardown on logout /
/// account-switch (INV-SESSION-SCOPE-001).
pub fn lock(id: SessionId) {
    // remove() returns the entry, dropped here → ZeroizeOnDrop wipes it.
    drop(store().remove(&id));
}

/// Drop + zeroize ALL sessions (teardown panic-button for the session-scope teardown).
pub fn lock_all() {
    store().clear();
}

/// Diagnostic only - NEVER exposes key bytes. Count of live sessions.
#[must_use]
pub fn session_count() -> usize {
    store().len()
}

/// GENERIC single-HKDF-layer op: derive `subkey = HKDF(root, info)` and AES-GCM-256 open the wire,
/// ALL inside Rust - the caller passes the HKDF `info` + the `nonce(12)‖ct‖tag` wire and receives
/// plaintext; it never sees the key. Reuses the already-KAT'd `crypto::hkdf_sha256` +
/// `crypto::aes_gcm_256_open` primitives. Fails closed on unknown session / bad tag.
///
/// 🔴 This is NOT the client's cipher-store path - that derives keys in TWO HKDF passes; its
/// byte-identical op is [`decrypt_cipher_store_blob`]. This single-layer op is kept for its own
/// test coverage and any future single-layer custody consumer.
pub fn decrypt_blob(
    id: SessionId,
    hkdf_info: Vec<u8>,
    wire: Vec<u8>,
) -> Result<Vec<u8>, SecretStoreError> {
    // Clone the root into a zeroizing buffer and DROP the registry lock before the crypto - the
    // global mutex is never held across HKDF/AES work (sub-ms, but the global custody lock should
    // not gate it). The clone wipes on drop.
    let root = clone_root(id)?;
    open_with_root(&root, hkdf_info, wire)
}

/// Batch sibling of `decrypt_blob` - the `cipher_store` login-hydration hot path opens 28-50 blobs
/// (one lock acquisition, one session lookup). Per-item `Result` so one bad blob does not fail the
/// batch.
pub fn decrypt_blob_batch(
    id: SessionId,
    items: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Vec<Result<Vec<u8>, String>>, SecretStoreError> {
    let root = clone_root(id)?;
    Ok(items
        .into_iter()
        .map(|(hkdf_info, wire)| open_with_root(&root, hkdf_info, wire).map_err(|e| e.to_string()))
        .collect())
}

/// Look up the session and return a zeroizing clone of its root key, releasing the registry lock
/// before returning (so the lock is not held across the caller's crypto). Fails closed on unknown
/// session.
fn clone_root(id: SessionId) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
    let s = store();
    let root = s
        .get(&id)
        .ok_or(SecretStoreError::NoSuchSession)?
        .master_root_key
        .clone();
    drop(s);
    Ok(Zeroizing::new(root))
}

/// `HKDF-SHA256(ikm=root, salt=empty, info=hkdf_info, 32)` → `aes_gcm_256_open`. `hkdf_info` and
/// `wire` are consumed by the (owned-arg) primitives; `root` is borrowed from the registry entry.
fn open_with_root(
    root: &[u8],
    hkdf_info: Vec<u8>,
    wire: Vec<u8>,
) -> Result<Vec<u8>, SecretStoreError> {
    let subkey = Zeroizing::new(
        crate::crypto::hkdf_sha256(root.to_vec(), Vec::new(), hkdf_info, 32)
            .map_err(|e| SecretStoreError::Crypto(e.to_string()))?,
    );
    crate::crypto::aes_gcm_256_open((*subkey).clone(), wire)
        .map_err(|e| SecretStoreError::Crypto(e.to_string()))
}

/// Write-side inverse of [`open_with_root`]: derive `subkey = HKDF(root, info)`
/// and `aes_gcm_256_seal` the plaintext (fresh `OsRng` nonce), returning the `nonce(12)‖ct‖tag` wire -
/// ALL inside Rust. `info` + `plaintext` are consumed by the (owned-arg) primitives; `root` is borrowed.
/// The subkey wipes on drop (`Zeroizing`). Seal is non-deterministic (random nonce) → the proof is
/// round-trip (`open_with_root(seal_with_root(p)) == p`), NOT byte-equality of two seals.
fn seal_with_root(
    root: &[u8],
    info: Vec<u8>,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, SecretStoreError> {
    let subkey = Zeroizing::new(
        crate::crypto::hkdf_sha256(root.to_vec(), Vec::new(), info, 32)
            .map_err(|e| SecretStoreError::Crypto(e.to_string()))?,
    );
    crate::crypto::aes_gcm_256_seal((*subkey).clone(), plaintext)
        .map_err(|e| SecretStoreError::Crypto(e.to_string()))
}

// ── The client's cipher-store TWO-HKDF-layer decrypt ────────────────────────────────────
// The client's cipher-store abstraction derives keys in TWO HKDF passes:
//   cipher_store_root_key = HKDF(master_root_key,        "haven-cipher-store-root")
//   blob_key              = HKDF(cipher_store_root_key,  "haven-cipher-store-blob:$name")
// `decrypt_blob` above does ONE pass, so it is NOT a drop-in for this chain. These ops
// do BOTH passes inside Rust - the inner `cipher_store_root_key` is cached as a derived subkey
// so the caller passes only the blob key NAME and the root never crosses the FRB boundary.
// Proven byte-identical to the client's own decrypt path by differential-parity tests.

/// The cipher-store's two-HKDF-layer info labels. ASCII → `as_bytes()` matches the client's own
/// code-unit encoding of the same label (the client's blob keys are canonical ASCII, so the two
/// encodings coincide).
const CIPHER_STORE_ROOT_INFO: &[u8] = b"haven-cipher-store-root";
const CIPHER_STORE_BLOB_INFO_PREFIX: &str = "haven-cipher-store-blob:";

/// The cipher-store's two-layer decrypt for ONE blob. The caller passes the blob key NAME (e.g.
/// `"mls_identity"`); Rust derives the cipher-store root (cached) + the per-blob key, then
/// AES-GCM-256-opens - byte-identical to the client's own decrypt path. Fails closed on unknown
/// session / bad tag.
pub fn decrypt_cipher_store_blob(
    id: SessionId,
    blob_key_name: &str,
    wire: Vec<u8>,
) -> Result<Vec<u8>, SecretStoreError> {
    let cs_root = cipher_store_root_clone(id)?;
    open_with_root(&cs_root, cipher_store_blob_info(blob_key_name), wire)
}

/// The cipher-store's two-layer SEAL for ONE blob - the write-side inverse of
/// [`decrypt_cipher_store_blob`]. The caller passes the blob key NAME + plaintext; Rust derives
/// the cipher-store root (cached) + the per-blob key, then `aes_gcm_256_seal`s - returning a
/// `nonce(12)‖ct‖tag` wire byte-openable by the client's own decrypt path (proven BOTH directions
/// by the round-trip parity test). The root never crosses the FRB boundary. Fails closed on
/// unknown session. Wired alongside the live encrypt path at this stage; the write-cutover +
/// key-path removal is separate, later, gated work.
pub fn seal_cipher_store_blob(
    id: SessionId,
    blob_key_name: &str,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, SecretStoreError> {
    let cs_root = cipher_store_root_clone(id)?;
    seal_with_root(&cs_root, cipher_store_blob_info(blob_key_name), plaintext)
}

/// Batch sibling - the `cipher_store` login-hydration hot path (28-50 blobs): derive the
/// `cipher_store` root ONCE, then open each blob. Per-item `Result` so one bad blob does not fail the
/// batch.
pub fn decrypt_cipher_store_blob_batch(
    id: SessionId,
    items: Vec<(String, Vec<u8>)>,
) -> Result<Vec<Result<Vec<u8>, String>>, SecretStoreError> {
    let cs_root = cipher_store_root_clone(id)?;
    Ok(items
        .into_iter()
        .map(|(blob_key_name, wire)| {
            open_with_root(&cs_root, cipher_store_blob_info(&blob_key_name), wire)
                .map_err(|e| e.to_string())
        })
        .collect())
}

/// Build the per-blob HKDF `info` = `"haven-cipher-store-blob:" + name`.
fn cipher_store_blob_info(blob_key_name: &str) -> Vec<u8> {
    let mut info = Vec::with_capacity(CIPHER_STORE_BLOB_INFO_PREFIX.len() + blob_key_name.len());
    info.extend_from_slice(CIPHER_STORE_BLOB_INFO_PREFIX.as_bytes());
    info.extend_from_slice(blob_key_name.as_bytes());
    info
}

/// Get-or-derive-and-cache this session's `cipher_store_root_key` (the INNER root of the two-layer
/// chain), returning a zeroizing clone with the registry lock released before any crypto (the global
/// custody mutex is never held across HKDF). Fails closed on unknown session.
fn cipher_store_root_clone(id: SessionId) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
    // Fast path: already cached → clone + release the lock (no crypto under the global mutex).
    {
        let s = store();
        let entry = s.get(&id).ok_or(SecretStoreError::NoSuchSession)?;
        if let Some(csr) = entry.cipher_store_root_key.as_ref() {
            let out = Zeroizing::new(csr.clone());
            drop(s);
            return Ok(out);
        }
    }
    // Slow path: clone the master root out (lock released by `clone_root`), derive the cipher_store
    // root OUTSIDE the lock, then cache it (idempotent - a racing thread derives identical bytes; if
    // the session was torn down mid-derive the cache write is skipped and the next op fails closed).
    let master = clone_root(id)?;
    let csr = crate::crypto::hkdf_sha256(
        master.to_vec(),
        Vec::new(),
        CIPHER_STORE_ROOT_INFO.to_vec(),
        32,
    )
    .map_err(|e| SecretStoreError::Crypto(e.to_string()))?;
    {
        let mut s = store();
        if let Some(entry) = s.get_mut(&id) {
            entry
                .cipher_store_root_key
                .get_or_insert_with(|| csr.clone());
        }
    }
    Ok(Zeroizing::new(csr))
}

// ── The client's secure-vault HMAC-SHA256 chain + version framing ───────────────────────
// The vault chain is HMAC-based, not HKDF-based, and roots off `vault_master_key` (a clean HKDF
// subkey of master_root_key - kept as its own key, distinct from any database key, so the vault
// is not entangled with an unrelated custody question):
//   vault_master_key = HKDF(master_root_key, "haven-vault-master-key")   [32 raw bytes]
//   vault_key        = HMAC-SHA256(vault_master_key, "haven:vault-encryption")
//   sub_key          = HMAC-SHA256(vault_key,        "haven:" + blob_type)
//   plaintext        = aes_gcm_256_open(sub_key, wire[4..])   where wire = version(4,be,==1)‖nonce‖ct‖tag
// Reproduced entirely inside Rust so master_root_key never crosses the FRB boundary. Proven
// byte-identical to the client's own vault decrypt path by a differential-parity test.

const VAULT_MASTER_KEY_INFO: &[u8] = b"haven-vault-master-key";
/// The client vault's on-disk framing prefix: a 4-byte big-endian version (== 1).
const VAULT_VERSION_BYTES: usize = 4;

/// The client vault's two-layer HMAC decrypt for ONE blob. The caller passes the blob TYPE (e.g.
/// `"email"`, `"file"`); Rust derives the vault master key (cached) → `vault_key` → per-type
/// `sub_key`, then validates + strips the version prefix and AES-GCM-256-opens - byte-identical
/// to the client's own decrypt path. Fails closed on unknown session / bad version / short wire /
/// bad tag.
pub fn decrypt_vault_blob(
    id: SessionId,
    blob_type: &str,
    mut wire: Vec<u8>,
) -> Result<Vec<u8>, SecretStoreError> {
    // version(4)‖nonce(12)‖ct‖tag - mirrors the client's own decrypt guards (fail-closed; the
    // client returns null on failure, this custody op returns a typed error so a caller can
    // distinguish absence from corruption).
    if wire.len() < VAULT_VERSION_BYTES + 12 + 16 {
        return Err(SecretStoreError::Crypto("vault blob too short".to_string()));
    }
    let version = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]);
    if version != 1 {
        return Err(SecretStoreError::Crypto(format!(
            "unsupported vault blob version {version}"
        )));
    }
    let vault_master = vault_master_key_clone(id)?;
    let vault_key = Zeroizing::new(hmac_sha256(&vault_master, b"haven:vault-encryption")?);
    let purpose = format!("haven:{blob_type}");
    let sub_key = Zeroizing::new(hmac_sha256(&vault_key, purpose.as_bytes())?);
    // Consume `wire` by splitting off the `nonce‖ct‖tag` tail (drops the 4-byte version prefix).
    let inner = wire.split_off(VAULT_VERSION_BYTES);
    crate::crypto::aes_gcm_256_open((*sub_key).clone(), inner)
        .map_err(|e| SecretStoreError::Crypto(e.to_string()))
}

/// The client vault's HMAC-chain SEAL for ONE blob - the write-side inverse of
/// [`decrypt_vault_blob`]. The caller passes the blob TYPE + plaintext; Rust derives the vault
/// master key (cached) → `vault_key` → per-type `sub_key`, `aes_gcm_256_seal`s, and PREPENDS the
/// `version(4,be,=1)` framing - returning a `version(4)‖nonce(12)‖ct‖tag` wire byte-openable by
/// the client's own decrypt path (proven BOTH directions by the round-trip parity test). The
/// root never crosses the FRB boundary. Fails closed on unknown session. Wired alongside the
/// live encrypt path at this stage; the write-cutover is separate, later work.
pub fn seal_vault_blob(
    id: SessionId,
    blob_type: &str,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, SecretStoreError> {
    let vault_master = vault_master_key_clone(id)?;
    let vault_key = Zeroizing::new(hmac_sha256(&vault_master, b"haven:vault-encryption")?);
    let purpose = format!("haven:{blob_type}");
    let sub_key = Zeroizing::new(hmac_sha256(&vault_key, purpose.as_bytes())?);
    let inner = crate::crypto::aes_gcm_256_seal((*sub_key).clone(), plaintext)
        .map_err(|e| SecretStoreError::Crypto(e.to_string()))?;
    // Prepend the 4-byte big-endian version (== 1) → mirrors the client's own encrypt framing.
    let mut wire = Vec::with_capacity(VAULT_VERSION_BYTES + inner.len());
    wire.extend_from_slice(&[0, 0, 0, 1]);
    wire.extend_from_slice(&inner);
    Ok(wire)
}

/// Get-or-derive-and-cache this session's `vault_master_key` (an HKDF subkey of the master root
/// key), returning a zeroizing clone with the registry lock released before any crypto. Fails
/// closed on unknown session.
fn vault_master_key_clone(id: SessionId) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
    {
        let s = store();
        let entry = s.get(&id).ok_or(SecretStoreError::NoSuchSession)?;
        if let Some(vmk) = entry.vault_master_key.as_ref() {
            let out = Zeroizing::new(vmk.clone());
            drop(s);
            return Ok(out);
        }
    }
    let master = clone_root(id)?;
    let vmk = crate::crypto::hkdf_sha256(
        master.to_vec(),
        Vec::new(),
        VAULT_MASTER_KEY_INFO.to_vec(),
        32,
    )
    .map_err(|e| SecretStoreError::Crypto(e.to_string()))?;
    {
        let mut s = store();
        if let Some(entry) = s.get_mut(&id) {
            entry.vault_master_key.get_or_insert_with(|| vmk.clone());
        }
    }
    Ok(Zeroizing::new(vmk))
}

/// `HMAC-SHA256(key, msg)` → 32-byte tag. Mirrors the client's own sub-key derivation function.
/// HMAC accepts any key length, so `new_from_slice` never actually fails here; the error is mapped
/// rather than unwrapped to satisfy the no-panic clippy gate.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|e| SecretStoreError::Crypto(format!("hmac key: {e}")))?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Decrypt an armored PGP message with the session's custodied PGP identity. Fails closed if no
/// identity was set. Delegates to the proven `pgp_decrypt_impl` (the privkey + passphrase never
/// leave Rust).
pub fn pgp_decrypt(id: SessionId, encrypted_armored: String) -> Result<String, SecretStoreError> {
    // Extract the PGP identity and DROP the registry lock before the (slower) PGP decrypt - the
    // global custody mutex must not be held across rPGP work. `pgp_decrypt_impl` re-wraps the
    // passphrase in `Zeroizing`, so the moved clone wipes there.
    let (priv_armored, passphrase) = {
        let s = store();
        let entry = s.get(&id).ok_or(SecretStoreError::NoSuchSession)?;
        let priv_armored = entry
            .pgp_private_key_armored
            .as_ref()
            .ok_or(SecretStoreError::NoPgpIdentity)?
            .clone();
        let passphrase = entry
            .pgp_passphrase
            .as_ref()
            .ok_or(SecretStoreError::NoPgpIdentity)?
            .clone();
        drop(s); // release the registry lock before rPGP work (entry's borrow has ended)
        (priv_armored, passphrase)
    };
    crate::pgp::pgp_decrypt_impl(encrypted_armored, priv_armored, passphrase)
        .map_err(|e| SecretStoreError::Crypto(e.to_string()))
}
