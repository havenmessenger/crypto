//! Native MLS group operations - the Haven-to-Haven messaging path. The Dart-exposed entry
//! points a consuming application defines are thin delegators over the functions here.
//!
//! The MLS wire format and the INV-MLS-002 / INV-CRYPTO-AGILITY-001 inbound
//! accept-gate calls (`suite_policy::gate_inbound_*`) are proven by a client/server conformance
//! test suite plus this crate's own KATs.
//!
//! Lint posture: this module allows several pedantic/style lints with justification rather than
//! fixing them, because fixing some of them would be a logic edit on a KAT-pinned crypto path
//! (see per-lint comments below). `unwrap_used` is allowed module-wide ONLY because every
//! `.unwrap()` here is the SAME pattern - acquiring an in-memory `RwLock` guard on a
//! freshly-created, single-threaded `OpenMlsRustCrypto` provider's storage, where
//! lock poisoning is unreachable (no panic is ever held across these guards). This
//! does not relax the gate on any fallible operation (those all use
//! `?`/`map_err`).
#![allow(
    clippy::unwrap_used, // in-memory provider RwLock guards only (see module doc)
    clippy::uninlined_format_args, // format-arg style only, not a correctness concern
    clippy::missing_panics_doc, // no panic-doc convention adopted in this crate
    clippy::needless_pass_by_value, // owned params so zeroize can wipe the caller's buffer on drop
    clippy::doc_markdown, // doc comments cite OpenMLS/KeyPackage/etc. type names verbatim
    clippy::unnecessary_fallible_conversions, // try_from kept - it is the error-handling path
    // The two below are genuine idiom-cleanup candidates, allowed rather than fixed here because
    // fixing them is a logic edit on a KAT-pinned crypto path, deferred to a later pass:
    clippy::manual_let_else, // remove_member_by_credential closure
    clippy::useless_conversion // process_welcome `ratchet_tree.into()`
)]

use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use std::convert::TryFrom;
use std::mem;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use zeroize::Zeroizing;

use crate::mls::{make_lifetime, GroupState, IdentityBundle, MlsSigner};

pub fn regenerate_key_package(
    bundle_bytes: Vec<u8>,
    now_secs: i64,
) -> anyhow::Result<(String, Vec<u8>, Vec<u8>)> {
    // The owned JSON-serialized bundle bytes carry the same plaintext private
    // key the deserialized IdentityBundle wipes on drop - wrap on entry so the raw input
    // buffer is wiped too, not just the typed struct it decodes into.
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    // 1. Deserialize the existing bundle. All five private fields
    //    (key_package_bundle, private_key, signature_scheme,
    //    public_key_bytes, user_id) are preserved.
    let mut old: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;

    // 2. Reconstruct the signer + credential from the existing
    //    bytes - same private key, same scheme, same user_id.
    let provider = OpenMlsRustCrypto::default();

    let public_key = SignaturePublicKey::try_from(old.public_key_bytes.clone())
        .map_err(|_| anyhow::anyhow!("Invalid public key bytes in stored bundle"))?;

    let credential = BasicCredential::new(old.user_id.clone().into_bytes());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: public_key,
    };

    let signer = MlsSigner {
        key: Zeroizing::new(old.private_key.clone()),
        scheme: old.signature_scheme,
    };

    // 3. Build a fresh KeyPackage. Same scheme + same credential +
    //    same signing key → identical authenticated identity from
    //    OpenMLS's perspective. Only the lifetime + the per-package
    //    encryption key (which OpenMLS auto-generates inside build)
    //    are fresh.
    // Checked conversion, not `as u64` - a negative `now_secs` must fail closed, not
    // silently become `u64::MAX` and panic/wrap inside `make_lifetime`'s arithmetic.
    let now_secs_u64 = u64::try_from(now_secs)
        .map_err(|_| anyhow::anyhow!("now_secs must be non-negative, got {now_secs}"))?;
    let lifetime = make_lifetime(now_secs_u64)?;

    let new_key_package_bundle = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .key_package_lifetime(lifetime)
        .build(
            crate::suite_policy::mls_generation_suite(),
            &provider,
            &signer,
            credential_with_key,
        )?;

    let new_key_package = new_key_package_bundle.key_package();
    let new_key_package_bytes = new_key_package.tls_serialize_detached()?;

    // 4. Storage map - the fresh provider used to build the new
    //    KeyPackage has its own storage map. Per generate_identity's
    //    contract, this is exported so process_welcome on receivers
    //    can find the KeyPackage.
    let storage_map: Vec<(Vec<u8>, Vec<u8>)> = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };

    // 5. Rebuild the IdentityBundle with the new KeyPackage portion
    //    + new storage_map, but PRESERVING private_key,
    //    signature_scheme, public_key_bytes, and user_id.
    let new_bundle = IdentityBundle {
        key_package_bundle: new_key_package_bundle,
        private_key: mem::take(&mut old.private_key),
        signature_scheme: old.signature_scheme,
        public_key_bytes: mem::take(&mut old.public_key_bytes),
        user_id: old.user_id.clone(),
        storage_map,
    };

    let new_bundle_bytes = crate::mls::zeroizing_json(&new_bundle)?;

    // `old` drops here (its private_key/public_key_bytes were taken above, leaving empty
    // placeholders; Drop still zeroizes whatever remains, e.g. old.storage_map, harmlessly).
    Ok((
        mem::take(&mut old.user_id),
        new_key_package_bytes,
        new_bundle_bytes.to_vec(),
    ))
}

pub fn create_group(group_id: String, bundle_bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    // Wrap the owned input on entry (see regenerate_key_package's comment).
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;

    let provider = OpenMlsRustCrypto::default();

    // Explicit generation-suite call, not openmls's default.
    // Today's default already resolves to 0x0001 (this is a strengthening, not a behavior
    // change) - see suite_policy.rs's module doc for WHY the seam exists.
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(crate::suite_policy::mls_generation_suite())
        .wire_format_policy(WireFormatPolicy::default())
        .build();

    let signer = MlsSigner {
        key: Zeroizing::new(mem::take(&mut identity.private_key)),
        scheme: identity.signature_scheme,
    };

    let public_key = SignaturePublicKey::try_from(mem::take(&mut identity.public_key_bytes))
        .map_err(|_| anyhow::anyhow!("Invalid public key bytes"))?;

    let credential = BasicCredential::new(mem::take(&mut identity.user_id).into_bytes());
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
    .map_err(|e| anyhow::anyhow!("Error creating group: {:?}", e))?;

    // Export storage
    // provider.storage() returns &MemoryStorage
    // MemoryStorage has pub values: RwLock<HashMap<...>>
    let storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };

    let state = GroupState {
        group_id: group.group_id().to_vec(),
        storage_map,
    };

    let state_bytes = crate::mls::zeroizing_json(&state)?;

    Ok(state_bytes.to_vec())
}

pub fn encrypt_message(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    message_bytes: Vec<u8>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    // Wrap both owned secret-bearing inputs on entry (see
    // regenerate_key_package's comment). message_bytes is the application plaintext being
    // encrypted, not MLS key material.
    let group_state_bytes = Zeroizing::new(group_state_bytes);
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut state: GroupState = serde_json::from_slice(&group_state_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid group state: {:?}", e))?;

    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;

    let provider = OpenMlsRustCrypto::default();

    // Inject storage
    {
        let mut values = provider.storage().values.write().unwrap();
        *values = mem::take(&mut state.storage_map).into_iter().collect();
    }

    let signer = MlsSigner {
        key: Zeroizing::new(mem::take(&mut identity.private_key)),
        scheme: identity.signature_scheme,
    };

    let group_id = GroupId::from_slice(&state.group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|e| anyhow::anyhow!("Error loading group: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Group not found in storage"))?;

    let message = group
        .create_message(&provider, &signer, &message_bytes)
        .map_err(|e| anyhow::anyhow!("Encryption error: {:?}", e))?;

    // Export updated storage
    let new_storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };

    let new_state = GroupState {
        group_id: mem::take(&mut state.group_id),
        storage_map: new_storage_map,
    };
    let new_group_state = crate::mls::zeroizing_json(&new_state)?;

    let ciphertext = message.tls_serialize_detached()?;

    Ok((new_group_state.to_vec(), ciphertext))
}

pub fn decrypt_message(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    ciphertext_bytes: Vec<u8>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    // Wrap on entry (see regenerate_key_package's comment). bundle_bytes carries no
    // information this function's body reads - a caller may still pass the real bundle bytes,
    // so it's wrapped and held (never read) purely for its wipe-on-drop side effect.
    let group_state_bytes = Zeroizing::new(group_state_bytes);
    let _bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut state: GroupState = serde_json::from_slice(&group_state_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid group state: {:?}", e))?;

    let provider = OpenMlsRustCrypto::default();

    // Inject storage
    {
        let mut values = provider.storage().values.write().unwrap();
        *values = mem::take(&mut state.storage_map).into_iter().collect();
    }

    let group_id = GroupId::from_slice(&state.group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|e| anyhow::anyhow!("Error loading group: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Group not found in storage"))?;

    crate::mls::check_wire_size(&ciphertext_bytes, "decrypt_message ciphertext")?;
    let message_in = MlsMessageIn::tls_deserialize_exact(ciphertext_bytes.as_slice())?;
    let message = ProtocolMessage::try_from(message_in)
        .map_err(|e| anyhow::anyhow!("Invalid protocol message: {:?}", e))?;

    let processed_message = group
        .process_message(&provider, message)
        .map_err(|e| anyhow::anyhow!("Processing error: {:?}", e))?;

    let content = match processed_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => app_msg.into_bytes(),
        _ => return Err(anyhow::anyhow!("Not an application message")),
    };

    // Export updated storage
    let new_storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };

    let new_state = GroupState {
        group_id: mem::take(&mut state.group_id),
        storage_map: new_storage_map,
    };
    let new_group_state = crate::mls::zeroizing_json(&new_state)?;

    Ok((new_group_state.to_vec(), content))
}

/// Add a member to the MLS group using their KeyPackage.
/// Returns (newGroupState, welcomeBytes, commitBytes). The Commit is additive: a caller adding
/// to a 2-member group may ignore it (there is no third existing member to notify), but a caller
/// adding to a group with other existing members MUST distribute commitBytes to every one of
/// them (excluding the member just added) via `mls_process_commit`, or those members permanently
/// desync onto a stale epoch.
pub fn add_member(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    key_package_bytes: Vec<u8>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Wrap both owned secret-bearing inputs on entry (see
    // regenerate_key_package's comment). key_package_bytes is a public KeyPackage - not
    // secret.
    let group_state_bytes = Zeroizing::new(group_state_bytes);
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut state: GroupState = serde_json::from_slice(&group_state_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid group state: {:?}", e))?;

    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;

    let provider = OpenMlsRustCrypto::default();

    // Inject storage
    {
        let mut values = provider.storage().values.write().unwrap();
        *values = mem::take(&mut state.storage_map).into_iter().collect();
    }

    let signer = MlsSigner {
        key: Zeroizing::new(mem::take(&mut identity.private_key)),
        scheme: identity.signature_scheme,
    };

    let group_id = GroupId::from_slice(&state.group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|e| anyhow::anyhow!("Error loading group: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Group not found in storage"))?;

    // Deserialize the KeyPackage
    crate::mls::check_wire_size(&key_package_bytes, "add_member KeyPackage")?;
    let key_package = KeyPackageIn::tls_deserialize_exact(key_package_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Invalid KeyPackage: {:?}", e))?;

    let validated_kp = key_package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| anyhow::anyhow!("KeyPackage validation failed: {:?}", e))?;

    // INV-MLS-002 explicit accept-gate: refuse a foreign-suite KeyPackage before openmls HPKE-seals
    // the Welcome to it. validate() above is signature-only (no AEAD); this gates the suite.
    crate::suite_policy::gate_inbound_keypackage(&validated_kp)?;

    // Add member
    let (commit, welcome, _group_info) = group
        .add_members(&provider, &signer, &[validated_kp])
        .map_err(|e| anyhow::anyhow!("Error adding member: {:?}", e))?;

    // Merge pending commit
    group
        .merge_pending_commit(&provider)
        .map_err(|e| anyhow::anyhow!("Error merging commit: {:?}", e))?;

    // Export ratchet tree for Welcome processing
    let ratchet_tree = group.export_ratchet_tree();
    let ratchet_tree_bytes = ratchet_tree.tls_serialize_detached()?;

    // Export updated storage
    let new_storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };

    let new_state = GroupState {
        group_id: mem::take(&mut state.group_id),
        storage_map: new_storage_map,
    };
    let new_group_state = crate::mls::zeroizing_json(&new_state)?;

    // Serialize Welcome as MlsMessageOut (wrapper)
    let welcome_bytes = welcome.tls_serialize_detached()?;

    // Return: (new_group_state, welcome_bytes, ratchet_tree_bytes)
    // Note: We combine welcome and ratchet_tree into a single payload for simplicity
    let combined_welcome = serde_json::to_vec(&(welcome_bytes, ratchet_tree_bytes))?;
    let commit_bytes = commit.tls_serialize_detached()?;

    Ok((new_group_state.to_vec(), combined_welcome, commit_bytes))
}

/// Upper bounds on `add_members_bulk`'s batch, generous for any real single-commit add and small
/// enough to bound the aggregate KeyPackage-validation + HPKE-seal work one call can force.
/// `check_wire_size` already caps each individual KeyPackage (`MAX_MLS_WIRE_BYTES`); that per-item
/// check does not bound the batch as a whole, which is what these two constants are for.
pub(crate) const MAX_BULK_MEMBERS: usize = 256;
pub(crate) const MAX_BULK_AGGREGATE_BYTES: usize = 4 * 1024 * 1024;

/// Add multiple members to the MLS group in a single commit using their KeyPackages.
/// Returns (newGroupState, combinedWelcomeBytes, commitBytes) - same Welcome is valid for all
/// added members. The Commit is additive (see `add_member`'s doc for the distribution
/// obligation to any OTHER existing member of the group).
pub fn add_members_bulk(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    key_packages_bytes: Vec<Vec<u8>>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if key_packages_bytes.len() > MAX_BULK_MEMBERS {
        anyhow::bail!(
            "add_members_bulk: {} KeyPackages exceeds the {MAX_BULK_MEMBERS}-member batch cap",
            key_packages_bytes.len()
        );
    }
    let aggregate_bytes: usize = key_packages_bytes.iter().map(Vec::len).sum();
    if aggregate_bytes > MAX_BULK_AGGREGATE_BYTES {
        anyhow::bail!(
            "add_members_bulk: {aggregate_bytes} aggregate bytes exceeds the \
             {MAX_BULK_AGGREGATE_BYTES}-byte batch cap"
        );
    }

    // Wrap both owned secret-bearing inputs on entry (see
    // regenerate_key_package's comment). key_packages_bytes are public KeyPackages - not
    // secret.
    let group_state_bytes = Zeroizing::new(group_state_bytes);
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut state: GroupState = serde_json::from_slice(&group_state_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid group state: {:?}", e))?;

    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;

    let provider = OpenMlsRustCrypto::default();

    {
        let mut values = provider.storage().values.write().unwrap();
        *values = mem::take(&mut state.storage_map).into_iter().collect();
    }

    let signer = MlsSigner {
        key: Zeroizing::new(mem::take(&mut identity.private_key)),
        scheme: identity.signature_scheme,
    };

    let group_id = GroupId::from_slice(&state.group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|e| anyhow::anyhow!("Error loading group: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Group not found in storage"))?;

    let mut validated_kps = Vec::with_capacity(key_packages_bytes.len());
    for kp_bytes in &key_packages_bytes {
        crate::mls::check_wire_size(kp_bytes, "add_members_bulk KeyPackage")?;
        let key_package = KeyPackageIn::tls_deserialize_exact(kp_bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("Invalid KeyPackage: {:?}", e))?;
        let validated_kp = key_package
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| anyhow::anyhow!("KeyPackage validation failed: {:?}", e))?;
        // INV-MLS-002 explicit accept-gate: refuse any foreign-suite KeyPackage in the batch
        // before openmls HPKE-seals to it.
        crate::suite_policy::gate_inbound_keypackage(&validated_kp)?;
        validated_kps.push(validated_kp);
    }

    let (commit, welcome, _group_info) = group
        .add_members(&provider, &signer, &validated_kps)
        .map_err(|e| anyhow::anyhow!("Error adding members: {:?}", e))?;

    group
        .merge_pending_commit(&provider)
        .map_err(|e| anyhow::anyhow!("Error merging commit: {:?}", e))?;

    let ratchet_tree = group.export_ratchet_tree();
    let ratchet_tree_bytes = ratchet_tree.tls_serialize_detached()?;

    let new_storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };

    let new_state = GroupState {
        group_id: mem::take(&mut state.group_id),
        storage_map: new_storage_map,
    };
    let new_group_state = crate::mls::zeroizing_json(&new_state)?;

    let welcome_bytes = welcome.tls_serialize_detached()?;
    let combined_welcome = serde_json::to_vec(&(welcome_bytes, ratchet_tree_bytes))?;
    let commit_bytes = commit.tls_serialize_detached()?;

    Ok((new_group_state.to_vec(), combined_welcome, commit_bytes))
}

/// Remove a member from the MLS group by their credential identity (user_id string).
/// Used when re-enrolling a member whose credential is already in the group (DuplicateSignatureKey),
/// and by the admin "Remove Person" flow.
/// Returns (newGroupState, commitBytes). The Commit MUST be distributed to every remaining member
/// (the removed member cannot process it, by construction) via `mls_process_commit`, or they
/// permanently desync onto a stale epoch.
pub fn remove_member_by_credential(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    credential_identity: String,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    // Wrap both owned secret-bearing inputs on entry (see
    // regenerate_key_package's comment).
    let group_state_bytes = Zeroizing::new(group_state_bytes);
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut state: GroupState = serde_json::from_slice(&group_state_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid group state: {:?}", e))?;

    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;

    let provider = OpenMlsRustCrypto::default();

    {
        let mut values = provider.storage().values.write().unwrap();
        *values = mem::take(&mut state.storage_map).into_iter().collect();
    }

    let signer = MlsSigner {
        key: Zeroizing::new(mem::take(&mut identity.private_key)),
        scheme: identity.signature_scheme,
    };

    let group_id = GroupId::from_slice(&state.group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|e| anyhow::anyhow!("Error loading group: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Group not found in storage"))?;

    // Find the leaf index of the member with matching credential identity
    let target_index = group
        .members()
        .find(|m| {
            BasicCredential::try_from(m.credential.clone())
                .is_ok_and(|basic| basic.identity() == credential_identity.as_bytes())
        })
        .map(|m| m.index)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Member with credential '{}' not found in group",
                credential_identity
            )
        })?;

    let (commit, _welcome, _group_info) = group
        .remove_members(&provider, &signer, &[target_index])
        .map_err(|e| anyhow::anyhow!("Error removing member: {:?}", e))?;

    group
        .merge_pending_commit(&provider)
        .map_err(|e| anyhow::anyhow!("Error merging remove commit: {:?}", e))?;

    let new_storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };

    let new_state = GroupState {
        group_id: mem::take(&mut state.group_id),
        storage_map: new_storage_map,
    };

    let commit_bytes = commit.tls_serialize_detached()?;
    Ok((
        crate::mls::zeroizing_json(&new_state)?.to_vec(),
        commit_bytes,
    ))
}

/// Process a Welcome message to join a group.
/// Returns the new group state bytes.
pub fn process_welcome(
    welcome_bytes: Vec<u8>, // This is actually combined (welcome_bytes, ratchet_tree_bytes)
    bundle_bytes: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    // Wrap the owned bundle input on entry (see regenerate_key_package's
    // comment). welcome_bytes is an MLS Welcome (HPKE-sealed wire form), not the plaintext
    // key bundle.
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    // Parse combined payload: (welcome_bytes, ratchet_tree_bytes)
    let (raw_welcome_bytes, ratchet_tree_bytes): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&welcome_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid combined welcome payload: {:?}", e))?;

    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;

    let provider = OpenMlsRustCrypto::default();

    #[cfg(test)]
    eprintln!(
        "DEBUG process_welcome: identity.storage_map has {} entries",
        identity.storage_map.len()
    );

    // Inject the full storage from identity generation
    // This contains the KeyPackage in OpenMLS's expected format
    {
        let mut values = provider.storage().values.write().unwrap();
        *values = mem::take(&mut identity.storage_map).into_iter().collect();

        #[cfg(test)]
        for (k, _v) in values.iter() {
            eprintln!(
                "DEBUG: storage key (len={}): {:?}",
                k.len(),
                &k[..k.len().min(30)]
            );
        }
    }

    // Deserialize Welcome (wrapped in MlsMessageIn)
    crate::mls::check_wire_size(&raw_welcome_bytes, "process_welcome Welcome")?;
    let mls_message = MlsMessageIn::tls_deserialize_exact(raw_welcome_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Invalid MlsMessage: {:?}", e))?;

    // Extract Welcome from the wrapper using extract() and matching
    let welcome = match mls_message.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => return Err(anyhow::anyhow!("Message is not a Welcome")),
    };

    // INV-MLS-002 explicit accept-gate: refuse a foreign-suite Welcome BEFORE StagedWelcome
    // drives the HPKE-open. Without this gate, receive-side (attacker-influenced) input can
    // reach OpenMlsRustCrypto's ChaCha implementation on an unvalidated suite.
    crate::suite_policy::gate_inbound_welcome(&welcome)?;

    // Deserialize ratchet tree
    crate::mls::check_wire_size(&ratchet_tree_bytes, "process_welcome ratchet tree")?;
    let ratchet_tree = RatchetTreeIn::tls_deserialize_exact(ratchet_tree_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Invalid ratchet tree: {:?}", e))?;

    #[cfg(test)]
    {
        // Debug: Print what hash_refs the Welcome is looking for
        eprintln!("DEBUG: About to iterate welcome.secrets()");
        let secrets = welcome.secrets();
        eprintln!("DEBUG: Welcome has {} secrets", secrets.len());
        for egs in secrets.iter() {
            let hash_ref = egs.new_member().clone();
            let key = serde_json::to_vec(&hash_ref).unwrap();
            let label = b"KeyPackage";
            let mut storage_key = label.to_vec();
            storage_key.extend_from_slice(&key);
            storage_key.extend_from_slice(&1u16.to_be_bytes()); // VERSION = 1
            eprintln!(
                "DEBUG: Welcome looking for key (len={}): {:?}",
                storage_key.len(),
                &storage_key[..storage_key.len().min(50)]
            );
        }
    }

    let mls_group_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(WireFormatPolicy::default())
        .build();

    // Create staged join from Welcome with ratchet tree
    let staged_join = StagedWelcome::new_from_welcome(
        &provider,
        &mls_group_config,
        welcome,
        Some(ratchet_tree.into()),
    )
    .map_err(|e| anyhow::anyhow!("Error processing Welcome: {:?}", e))?;

    // Complete the join
    let group = staged_join
        .into_group(&provider)
        .map_err(|e| anyhow::anyhow!("Error joining group: {:?}", e))?;

    // Export storage
    let storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };

    let state = GroupState {
        group_id: group.group_id().to_vec(),
        storage_map,
    };

    let state_bytes = crate::mls::zeroizing_json(&state)?;

    Ok(state_bytes.to_vec())
}

/// Process an incoming Commit: an existing member advances its epoch after another member
/// committed an Add/Remove. `process_message` → `StagedCommitMessage` → `merge_staged_commit`.
pub fn mls_process_commit(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    commit_bytes: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    // Wrap on entry (see decrypt_message's comment on the unused-but-still-owned
    // bundle_bytes pattern).
    let group_state_bytes = Zeroizing::new(group_state_bytes);
    let _bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut state: GroupState = serde_json::from_slice(&group_state_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid group state: {:?}", e))?;
    let provider = OpenMlsRustCrypto::default();
    {
        let mut values = provider.storage().values.write().unwrap();
        *values = mem::take(&mut state.storage_map).into_iter().collect();
    }
    let group_id = GroupId::from_slice(&state.group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|e| anyhow::anyhow!("Error loading group: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Group not found in storage"))?;

    crate::mls::check_wire_size(&commit_bytes, "mls_process_commit Commit")?;
    let message_in = MlsMessageIn::tls_deserialize_exact(commit_bytes.as_slice())?;
    let message = ProtocolMessage::try_from(message_in)
        .map_err(|e| anyhow::anyhow!("Invalid protocol message: {:?}", e))?;
    let processed = group
        .process_message(&provider, message)
        .map_err(|e| anyhow::anyhow!("Processing error: {:?}", e))?;
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            group
                .merge_staged_commit(&provider, *staged)
                .map_err(|e| anyhow::anyhow!("Error merging staged commit: {:?}", e))?;
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Expected a Commit, got a different message type"
            ))
        }
    }

    let new_storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };
    let new_state = GroupState {
        group_id: mem::take(&mut state.group_id),
        storage_map: new_storage_map,
    };
    Ok(crate::mls::zeroizing_json(&new_state)?.to_vec())
}

/// Extract a peer's MLS signature public key from their KeyPackage bytes, as
/// uppercase hex. This is the MLS analogue of a PGP key fingerprint: the stable,
/// per-USER identity anchor - a user's client identifier and signing keys are
/// immutable for the account's lifetime. Pinning it lets the client detect when
/// a peer's MLS identity key changes (the chat-side tripwire).
///
/// The KeyPackage is VALIDATED first, so the returned key is the one that
/// actually signed the leaf (a tampered signature key fails validation). Returns
/// "" on any parse/validation failure - never panics.
#[must_use]
pub fn mls_extract_signature_key(key_package_bytes: Vec<u8>) -> String {
    if crate::mls::check_wire_size(&key_package_bytes, "mls_extract_signature_key KeyPackage")
        .is_err()
    {
        return String::new();
    }
    let provider = OpenMlsRustCrypto::default();
    let kp_in = match KeyPackageIn::tls_deserialize_exact(key_package_bytes.as_slice()) {
        Ok(kp) => kp,
        Err(_) => return String::new(),
    };
    let validated = match kp_in.validate(provider.crypto(), ProtocolVersion::Mls10) {
        Ok(kp) => kp,
        Err(_) => return String::new(),
    };
    // `validate()` above is signature-only, not a suite check - a
    // foreign-suite KeyPackage validates fine and, before this gate, would have its identity key
    // extracted and returned same as a real 0x0001 one. Route through the same explicit
    // INV-MLS-002 accept-gate every other inbound KeyPackage path already uses.
    if crate::suite_policy::gate_inbound_keypackage(&validated).is_err() {
        return String::new();
    }
    let sig_key = validated.leaf_node().signature_key().as_slice();
    hex::encode_upper(sig_key)
}
