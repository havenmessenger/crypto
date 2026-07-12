//! MLS identity generation (`generate_identity`, `generate_identity_from_seed`,
//! `mls_derive_signing_key`). The Dart-exposed entry points a consuming application defines are
//! thin delegators over the functions here.
//!
//! Lint posture: this module allows several pedantic/style lints with justification rather than
//! fixing them, because fixing some of them would be a logic edit on a KAT-pinned crypto path
//! (see per-lint comments below); `unwrap_used` is kept per-site (not module-wide) so the gate
//! stays tight.
#![allow(
    clippy::uninlined_format_args, // format-arg style only, not a correctness concern
    clippy::missing_panics_doc, // no panic-doc convention adopted in this crate
    clippy::unnecessary_fallible_conversions, // try_from kept - it is the error-handling path
    clippy::needless_pass_by_value // owned params so zeroize can wipe the caller's buffer on drop
)]

use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::OpenMlsProvider;
use std::convert::TryFrom;
use tls_codec::Serialize as TlsSerialize;
use zeroize::Zeroizing;

use crate::mls::{make_lifetime, IdentityBundle, MlsSigner};

pub fn generate_identity(
    user_id: String,
    now_secs: i64,
) -> anyhow::Result<(String, Vec<u8>, Vec<u8>)> {
    let provider = OpenMlsRustCrypto::default();
    let crypto = provider.crypto();

    let signature_scheme = SignatureScheme::ED25519;
    let (priv_bytes, pub_bytes) = crypto
        .signature_key_gen(signature_scheme)
        .map_err(|e| anyhow::anyhow!("Crypto error: {:?}", e))?;

    build_identity_from_keypair(user_id, now_secs, priv_bytes, pub_bytes, false)
}

pub fn generate_identity_from_seed(
    user_id: String,
    now_secs: i64,
    mls_seed_hex: String,
) -> anyhow::Result<(String, Vec<u8>, Vec<u8>)> {
    let (priv_hex, pub_hex) = mls_derive_signing_key(mls_seed_hex);
    if priv_hex.is_empty() || pub_hex.is_empty() {
        return Err(anyhow::anyhow!(
            "mls_seed_hex must be exactly 32 bytes of hex"
        ));
    }
    let priv_bytes =
        hex::decode(&priv_hex).map_err(|e| anyhow::anyhow!("derived priv not hex: {e}"))?;
    let pub_bytes =
        hex::decode(&pub_hex).map_err(|e| anyhow::anyhow!("derived pub not hex: {e}"))?;
    build_identity_from_keypair(user_id, now_secs, priv_bytes, pub_bytes, false)
}

/// Shared identity-construction core for `generate_identity` (random key) and
/// `generate_identity_from_seed` (HD key). Everything downstream of the signing
/// keypair - credential, signer, `KeyPackage` build, storage-map export, bundle
/// serialization - is identical, so it lives here ONCE to prevent the random
/// and HD paths from drifting.
///
/// `pub` (not `pub(crate)`): another consumer's `mimi_generate_identity` calls this with
/// `appsync_caps=true`, kept distinct from the production surface; a consuming application
/// re-exports it so that path still resolves for existing callers.
pub fn build_identity_from_keypair(
    user_id: String,
    now_secs: i64,
    priv_bytes: Vec<u8>,
    pub_bytes: Vec<u8>,
    // When true, the leaf node advertises the mimiParticipantList AppSync custom proposal type
    // (demo / MIMI path only - see `mimi_generate_identity`). When false the KeyPackage is built
    // EXACTLY as the production path always has (no `.leaf_node_capabilities()` call) - byte-identical,
    // so production identities are unaffected (INV-MLS-002 + trinity untouched).
    appsync_caps: bool,
) -> anyhow::Result<(String, Vec<u8>, Vec<u8>)> {
    let provider = OpenMlsRustCrypto::default();

    let signature_scheme = SignatureScheme::ED25519;

    let public_key = SignaturePublicKey::try_from(pub_bytes.clone())
        .map_err(|_| anyhow::anyhow!("Invalid public key bytes"))?;

    let credential = BasicCredential::new(user_id.clone().into_bytes());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: public_key,
    };

    let signer = MlsSigner {
        key: Zeroizing::new(priv_bytes.clone()),
        scheme: signature_scheme,
    };

    // Checked conversion, not `as u64` - a negative `now_secs` (a caller clock error, not an
    // expected input) must fail closed here, not silently become `u64::MAX` and panic/wrap deep
    // inside `make_lifetime`'s arithmetic.
    let now_secs_u64 = u64::try_from(now_secs)
        .map_err(|_| anyhow::anyhow!("now_secs must be non-negative, got {now_secs}"))?;
    let lifetime = make_lifetime(now_secs_u64)?;

    let kp_builder = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .key_package_lifetime(lifetime);
    // The `false` branch is the UNCHANGED production path (no leaf capabilities call). The `true`
    // branch (MIMI demo) advertises the mimiParticipantList custom proposal so AppSync commits validate.
    let key_package_bundle = if appsync_caps {
        kp_builder
            // `mimi_appsync_capabilities` lives in `crate::mimi`; a consuming application
            // re-exports it, and another in-repo consumer reuses it directly.
            .leaf_node_capabilities(crate::mimi::mimi_appsync_capabilities())
            .build(
                crate::suite_policy::mls_generation_suite(),
                &provider,
                &signer,
                credential_with_key,
            )?
    } else {
        kp_builder.build(
            crate::suite_policy::mls_generation_suite(),
            &provider,
            &signer,
            credential_with_key,
        )?
    };

    let key_package = key_package_bundle.key_package();
    let key_package_bytes = key_package.tls_serialize_detached()?;

    // Export storage map - contains the KeyPackage in OpenMLS's internal format
    let storage_map: Vec<(Vec<u8>, Vec<u8>)> = {
        // In-memory RwLock read on the single-threaded provider; poison is unreachable (no
        // panic is held across this lock).
        #[allow(clippy::unwrap_used)]
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };

    #[cfg(test)]
    {
        eprintln!(
            "DEBUG generate_identity: storage_map has {} entries",
            storage_map.len()
        );
        for (k, _v) in storage_map.iter() {
            eprintln!(
                "DEBUG generate: key (len={}): {:?}",
                k.len(),
                &k[..k.len().min(50)]
            );
        }
    }

    let identity_bundle = IdentityBundle {
        key_package_bundle,
        private_key: priv_bytes,
        signature_scheme,
        public_key_bytes: pub_bytes,
        user_id: user_id.clone(),
        storage_map,
    };

    let bundle_bytes = crate::mls::zeroizing_json(&identity_bundle)?;

    Ok((user_id, key_package_bytes, bundle_bytes.to_vec()))
}

#[must_use]
pub fn mls_derive_signing_key(seed_hex: String) -> (String, String) {
    // Tier-0: the Ed25519 signing seed regenerates the identity's private key - wipe
    // every retained copy of it on drop. The returned priv_hex String is the unavoidable secret-crossing
    // (consumed by generate_identity_from_seed → build_identity_from_keypair); it stays a String, like an
    // FRB return. ed25519_dalek's own SigningKey already zeroizes its internal copy on drop.
    let seed_hex = Zeroizing::new(seed_hex);
    let seed = match hex::decode(seed_hex.trim()) {
        Ok(b) if b.len() == 32 => Zeroizing::new(b),
        _ => return (String::new(), String::new()),
    };
    let mut seed_arr = Zeroizing::new([0u8; 32]);
    seed_arr.copy_from_slice(&seed);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
    let priv_bytes = Zeroizing::new(signing_key.to_bytes()); // == seed_arr, the 32-byte seed
    let pub_bytes = signing_key.verifying_key().to_bytes();
    (
        hex::encode_upper(priv_bytes.as_slice()),
        hex::encode_upper(pub_bytes),
    )
}

#[cfg(test)]
mod tests;
