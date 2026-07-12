//! Shared MLS primitive types + helpers. Used by the native domain modules in this crate
//! (`crate::mls::groups`, `crate::mimi`, `crate::identity`).
//!
//! These types are `pub` (not `pub(crate)`) because a consuming application reuses them
//! directly - as opaque handles passed between this crate's own functions, not as bare
//! serde types. Serialization is an inherent API (`to_zeroizing_json`/`from_slice`) over a
//! module-private wire DTO, so a consumer cannot reach the plaintext bytes through any
//! `Serialize`-based encoder except the one that wipes its own output on drop.

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
    pub group_id: Vec<u8>,
    pub storage_map: Vec<(Vec<u8>, Vec<u8>)>,
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
    /// still carries (reallocation during encode, the error-path gap).
    pub fn to_zeroizing_json(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
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
    pub key_package_bundle: KeyPackageBundle,
    pub private_key: Vec<u8>,
    pub signature_scheme: SignatureScheme,
    pub public_key_bytes: Vec<u8>,
    pub user_id: String,
    // Storage map from provider - needed for process_welcome to find KeyPackage
    pub storage_map: Vec<(Vec<u8>, Vec<u8>)>,
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
    /// still carries (reallocation during encode, the error-path gap).
    pub fn to_zeroizing_json(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
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

/// Serialize a key-bearing value (`GroupState`, `IdentityBundle`) into a self-wiping buffer.
/// `serde_json::to_vec` alone returns a bare `Vec<u8>` holding the plaintext MLS ratchet
/// secrets or Ed25519 private key. Wrapping the returned buffer in `Zeroizing` protects it: it
/// wipes on drop along every exit path after this function returns, including a fallible step a
/// caller adds later between this call and the point it takes ownership of the bytes.
///
/// Residual (`docs/THREAT_MODEL.md` has the full treatment): this wraps only the last buffer
/// `serde_json::to_vec` hands back. Building that buffer reallocates as it grows, freeing each
/// earlier, smaller backing buffer unwiped, and a serialization error drops the partially-
/// written internal buffer before it ever reaches `Zeroizing::new`. Both happen inside
/// `serde_json::to_vec`'s own call frame, outside this function's reach to close.
pub fn zeroizing_json<T: Serialize>(value: &T) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(serde_json::to_vec(value)?))
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
