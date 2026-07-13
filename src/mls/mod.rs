//! Shared MLS primitive types + helpers. Used by the native domain modules in this crate
//! (`crate::mls::groups`, `crate::mimi`, `crate::identity`).
//!
//! `GroupState`/`IdentityBundle` are `pub` types with `pub(crate)` fields: a consuming
//! application reuses them as opaque handles passed between this crate's own functions, never
//! by reading a field directly - the secret-bearing fields being crate-private (not just
//! undocumented) is what makes that a compiler-enforced property rather than a convention.
//! Serialization is an inherent API (`to_zeroizing_json`/`from_slice`) over a module-private
//! wire DTO, returning [`SerializedSecret`] rather than a bare `Zeroizing<Vec<u8>>` - see that
//! type's own doc for why a `Zeroizing` return alone does not close the escape.

pub mod groups;

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// The group's ratchet-tree secrets, as exported from openmls's in-memory storage. This
/// crate's own copy is wiped on drop (`storage_map` values); the copy openmls itself holds
/// inside the per-op `OpenMlsRustCrypto` provider is out of this crate's control - it is a
/// fresh, single-op provider (see groups.rs/mimi/mod.rs module docs), not a long-lived
/// process, but openmls does not zeroize its own `MemoryStorage` internally.
///
/// Carries no `Serialize`/`Deserialize` impl of its own - the wire form is reached only
/// through [`GroupState::to_zeroizing_json`]/[`GroupState::from_slice`], so every serialize
/// of this type's plaintext fields is wrapped in `Zeroizing` by construction, not by the
/// caller remembering to route through it.
pub struct GroupState {
    pub(crate) group_id: Vec<u8>,
    pub(crate) storage_map: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Drop for GroupState {
    fn drop(&mut self) {
        for (_, v) in &mut self.storage_map {
            v.zeroize();
        }
    }
}

/// Borrowed wire shape for [`GroupState::to_zeroizing_json`] - serializes by reference so
/// encoding never clones the plaintext `storage_map` bytes into a second, unwiped buffer.
#[derive(Serialize)]
struct GroupStateSerDto<'a> {
    group_id: &'a [u8],
    storage_map: &'a [(Vec<u8>, Vec<u8>)],
}

/// Owned wire shape for [`GroupState::from_slice`] - the only place this crate ever
/// deserializes a `GroupState` from bytes.
#[derive(Deserialize)]
struct GroupStateDeDto {
    group_id: Vec<u8>,
    storage_map: Vec<(Vec<u8>, Vec<u8>)>,
}

impl GroupState {
    /// Serialize into a self-wiping buffer. See [`zeroizing_json`] for the residuals this
    /// still carries.
    pub fn to_zeroizing_json(&self) -> anyhow::Result<SerializedSecret> {
        zeroizing_json(&GroupStateSerDto {
            group_id: &self.group_id,
            storage_map: &self.storage_map,
        })
    }

    /// Deserialize from the wire form `to_zeroizing_json` produces.
    pub fn from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        let dto: GroupStateDeDto = serde_json::from_slice(bytes)?;
        Ok(Self {
            group_id: dto.group_id,
            storage_map: dto.storage_map,
        })
    }
}

/// Internal value type (never a Dart type). Carries opaque openmls fields
/// (`KeyPackageBundle`, `SignatureScheme`) - FRB would auto-opaque these into unresolved
/// bare type refs, which is why it never crosses the boundary.
///
/// `private_key` is the Ed25519 MLS signing key; `storage_map` may carry the same
/// ratchet-tree secrets as `GroupState` (populated on `process_welcome`). Both are
/// wiped on drop - the same openmls-internal-copy bound noted on `GroupState` applies.
///
/// Carries no `Serialize`/`Deserialize` impl of its own - see [`GroupState`]'s doc for why.
pub struct IdentityBundle {
    pub(crate) key_package_bundle: KeyPackageBundle,
    pub(crate) private_key: Vec<u8>,
    pub(crate) signature_scheme: SignatureScheme,
    pub(crate) public_key_bytes: Vec<u8>,
    pub(crate) user_id: String,
    // Storage map from provider - needed for process_welcome to find KeyPackage
    pub(crate) storage_map: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Drop for IdentityBundle {
    fn drop(&mut self) {
        self.private_key.zeroize();
        for (_, v) in &mut self.storage_map {
            v.zeroize();
        }
    }
}

/// Borrowed wire shape for [`IdentityBundle::to_zeroizing_json`] - `key_package_bundle`
/// and `signature_scheme` serialize by reference via serde's blanket `&T: Serialize`, so
/// only the two plaintext-bearing fields need an explicit borrow.
#[derive(Serialize)]
struct IdentityBundleSerDto<'a> {
    key_package_bundle: &'a KeyPackageBundle,
    private_key: &'a [u8],
    signature_scheme: &'a SignatureScheme,
    public_key_bytes: &'a [u8],
    user_id: &'a str,
    storage_map: &'a [(Vec<u8>, Vec<u8>)],
}

/// Owned wire shape for [`IdentityBundle::from_slice`].
#[derive(Deserialize)]
struct IdentityBundleDeDto {
    key_package_bundle: KeyPackageBundle,
    private_key: Vec<u8>,
    signature_scheme: SignatureScheme,
    public_key_bytes: Vec<u8>,
    user_id: String,
    storage_map: Vec<(Vec<u8>, Vec<u8>)>,
}

impl IdentityBundle {
    /// Serialize into a self-wiping buffer. See [`zeroizing_json`] for the residuals this
    /// still carries.
    pub fn to_zeroizing_json(&self) -> anyhow::Result<SerializedSecret> {
        zeroizing_json(&IdentityBundleSerDto {
            key_package_bundle: &self.key_package_bundle,
            private_key: &self.private_key,
            signature_scheme: &self.signature_scheme,
            public_key_bytes: &self.public_key_bytes,
            user_id: &self.user_id,
            storage_map: &self.storage_map,
        })
    }

    /// Deserialize from the wire form `to_zeroizing_json` produces.
    pub fn from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        let dto: IdentityBundleDeDto = serde_json::from_slice(bytes)?;
        Ok(Self {
            key_package_bundle: dto.key_package_bundle,
            private_key: dto.private_key,
            signature_scheme: dto.signature_scheme,
            public_key_bytes: dto.public_key_bytes,
            user_id: dto.user_id,
            storage_map: dto.storage_map,
        })
    }
}

/// Serde-only internal value type (never a Dart type) - carries an opaque openmls
/// `SignatureScheme`. `key` is the Ed25519 MLS signing key, held for the duration of
/// a group operation (sign/add/remove/commit) - `Zeroizing` wipes it on drop,
/// covering every exit path (including an early `?`-return or a panic unwind).
pub struct MlsSigner {
    pub key: Zeroizing<Vec<u8>>,
    pub scheme: SignatureScheme,
}

impl Signer for MlsSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        let provider = OpenMlsRustCrypto::default();
        let crypto = provider.crypto();
        crypto
            .sign(self.scheme, payload, &self.key)
            .map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

// OpenMLS default KeyPackage lifetime: 84 days validity + 1h not_before margin.
// These match MAX_LEAF_NODE_LIFETIME_RANGE_SECONDS in OpenMLS so validation passes.
pub const KP_LIFETIME_SECS: u64 = 60 * 60 * 24 * 84; // 84 days
pub const KP_NOT_BEFORE_MARGIN_SECS: u64 = 60 * 60; // 1 hour back

/// Size-bound: a hard cap on the size of any single network-derived
/// MLS/MIMI wire object (`KeyPackage`, `Welcome`, ratchet tree, application ciphertext, Commit,
/// external proposal) BEFORE it reaches `tls_codec`'s length-prefixed deserializer. `tls_codec`
/// allocates based on the length prefix it reads, ahead of `read_exact` - a crafted length prefix
/// on a short buffer can therefore request a disproportionate allocation. This crate cannot patch
/// `tls_codec`'s internal allocator behavior without violating INV-CRYPTO-001 (never hand-roll/
/// patch vetted crypto/wire-format deps); the practical, in-scope mitigation is bounding the
/// TOP-LEVEL input size this crate actually owns, checked before every production
/// `tls_deserialize_exact` call. 1 MiB is generous for any real KeyPackage/Welcome/Commit/
/// application-ciphertext Haven produces (MLS objects are small relative to MIME).
pub const MAX_MLS_WIRE_BYTES: usize = 1024 * 1024;

/// Self-wiping serialized-secret bytes returned by [`GroupState::to_zeroizing_json`] and
/// [`IdentityBundle::to_zeroizing_json`]. Deliberately does not implement `Deref`/`AsRef<[u8]>` -
/// those would let a caller reach a plain `&[u8]`/`Vec<u8>` through the same ergonomic path
/// (`.to_vec()`, `.clone()`) that made the previous bare `Zeroizing<Vec<u8>>` return type
/// trivially copyable into a non-wiping buffer with no visible indication a secret was involved.
/// The two accessors below are the only ways out, and both are named so a reviewer can grep
/// every place this type's bytes leave the wiping wrapper: [`SerializedSecret::as_bytes`] for a
/// one-shot borrow, [`SerializedSecret::into_zeroizing`] to hand ownership to another wiping
/// owner. Neither can stop a caller from copying the borrowed slice into a plain `Vec` if it
/// chooses to - no safe-Rust API can - but both require a deliberate, auditable call instead of
/// an inherited standard-library method.
pub struct SerializedSecret(Zeroizing<Vec<u8>>);

impl SerializedSecret {
    /// Borrow the serialized bytes. The caller must not copy this into a non-zeroizing buffer.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Take ownership of the underlying zeroizing buffer.
    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }

    /// The serialized length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the serialized form is empty (never true for a real `GroupState`/`IdentityBundle`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Growth-aware `Write` sink backed by a [`Zeroizing`] buffer that is wiping from the FIRST byte
/// written, not just wrapped around the final successful allocation. When a write needs more room
/// than the current backing allocation, this grows by copying into a fresh `Zeroizing` buffer and
/// replacing the old one - the replaced value's `Drop` (zeroize, then deallocate) runs at that
/// point, so the freed backing allocation from the previous size never carries plaintext. Bounded
/// by [`MAX_MLS_WIRE_BYTES`] (the same ceiling this crate already applies to inbound MLS/MIMI wire
/// objects): a write that would exceed it fails closed instead of growing further.
struct ZeroizingSink(Zeroizing<Vec<u8>>);

impl std::io::Write for ZeroizingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let needed = self.0.len().saturating_add(buf.len());
        if needed > MAX_MLS_WIRE_BYTES {
            return Err(std::io::Error::other(format!(
                "serialized secret would exceed the {MAX_MLS_WIRE_BYTES}-byte bound ({needed} bytes)"
            )));
        }
        if needed > self.0.capacity() {
            let new_cap = needed
                .max(self.0.capacity().saturating_mul(2))
                .clamp(64, MAX_MLS_WIRE_BYTES);
            let mut grown = Zeroizing::new(Vec::with_capacity(new_cap));
            grown.extend_from_slice(&self.0);
            self.0 = grown; // old backing buffer zeroized-then-freed via Drop here
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Serialize a key-bearing value (`GroupState`, `IdentityBundle`) into a self-wiping
/// [`SerializedSecret`]. Every exit path wipes: a successful encode wraps the final buffer as
/// before; a `serde_json` serialization error drops the in-progress [`ZeroizingSink`] (a
/// `Zeroizing`-backed local from its first byte, not a bare `Vec` wrapped only on success); a
/// panic unwinding through this call drops it the same way (`[profile.release]` in `Cargo.toml`
/// carries no `panic = "abort"` override, so `Drop` runs on unwind); and a growth event zeroizes
/// the superseded backing buffer before freeing it (see [`ZeroizingSink`]) rather than leaving it
/// for the allocator to reuse untouched.
pub fn zeroizing_json<T: Serialize>(value: &T) -> anyhow::Result<SerializedSecret> {
    let mut sink = ZeroizingSink(Zeroizing::new(Vec::new()));
    serde_json::to_writer(&mut sink, value)?;
    Ok(SerializedSecret(sink.0))
}

/// Shared pre-deserialize guard: `bytes.len() <= MAX_MLS_WIRE_BYTES`, checked BEFORE any
/// `tls_deserialize_exact` call on network-derived MLS/MIMI wire input.
pub fn check_wire_size(bytes: &[u8], what: &str) -> anyhow::Result<()> {
    if bytes.len() > MAX_MLS_WIRE_BYTES {
        anyhow::bail!(
            "{what}: {} bytes exceeds the {MAX_MLS_WIRE_BYTES}-byte MLS wire-input cap",
            bytes.len()
        );
    }
    Ok(())
}

/// Build a `Lifetime` from an explicit Unix timestamp (seconds).
/// Bypasses `SystemTime::now()` in Rust - avoids any platform-specific
/// timer dependency. Caller supplies Dart's `DateTime.now()` converted to seconds.
pub fn make_lifetime(now_secs: u64) -> anyhow::Result<Lifetime> {
    let not_before = now_secs.saturating_sub(KP_NOT_BEFORE_MARGIN_SECS);
    // Checked, not a bare `+` - an attacker/caller-supplied `now_secs` near `u64::MAX`
    // (e.g. from an upstream unchecked cast of a negative timestamp) must fail closed, not
    // silently wrap into a nonsensical (or, in debug builds, panicking) lifetime.
    let not_after = now_secs
        .checked_add(KP_LIFETIME_SECS)
        .ok_or_else(|| anyhow::anyhow!("now_secs {now_secs} + KP_LIFETIME_SECS overflows u64"))?;
    // Construct via serde to avoid SystemTime::now() inside Lifetime::new().
    serde_json::from_value(serde_json::json!({
        "not_before": not_before,
        "not_after": not_after,
    }))
    .map_err(|e| anyhow::anyhow!("Failed to construct Lifetime: {e}"))
}

#[cfg(test)]
mod tests;
