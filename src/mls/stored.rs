//! MLS operations that keep a group's state in an [`MlsStore`].
//!
//! Each function here is the store-backed form of one in [`crate::mls::groups`] or [`crate::mimi`]: it
//! takes the store and the group id where the byte-in/byte-out form takes the group's state, and returns
//! what that form returns without the new state. The operation reads the group's entries from the store,
//! runs, and writes back only the entries it changed or removed, after its last fallible step; an
//! operation that fails writes nothing. See [`crate::mls::store`] for the contract.
//!
//! The identity bundle (the signing key and key-package material) stays a byte value the caller holds.

#![allow(
    clippy::unwrap_used // in-memory provider RwLock guards only (see crate::mls::groups module doc)
)]

use std::collections::BTreeMap;

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use zeroize::{Zeroize, Zeroizing};

use crate::mimi::{self, MimiWelcomeError, PreparedWelcome};
use crate::mls::groups::{self, IndexedMlsMember};
use crate::mls::inspection::{self, GroupStateMetadata};
use crate::mls::store::{apply_change, decode_state, read_entries, state_v1, EntryMap, MlsStore};
use crate::mls::AuthenticatedSender;

fn store_error(error: crate::mls::store::MlsStoreError) -> anyhow::Error {
    anyhow::anyhow!(error)
}

/// The group's entries and its `serde_json` snapshot, which the byte-in/byte-out operations take.
fn load(store: &dyn MlsStore, group: &[u8]) -> anyhow::Result<(EntryMap, Zeroizing<Vec<u8>>)> {
    let entries = read_entries(store, group).map_err(store_error)?;
    if entries.is_empty() {
        anyhow::bail!("the store holds no state for this group");
    }
    let state = state_v1(group, &entries).map_err(store_error)?;
    Ok((entries, state))
}

/// Write what `new_state` changed relative to `before` into the store, for the group it names.
fn commit(store: &dyn MlsStore, before: &EntryMap, new_state: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let new_state = Zeroizing::new(new_state);
    let (group, after) = decode_state(&new_state).map_err(store_error)?;
    apply_change(store, &group, before, &after).map_err(store_error)?;
    Ok(group)
}

/// Run an operation that reads the group and changes nothing.
fn read_op<T>(
    store: &dyn MlsStore,
    group: &[u8],
    operation: impl FnOnce(Vec<u8>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let (_, state) = load(store, group)?;
    operation(state.to_vec())
}

/// Run an operation that returns the group's new state and a result, and store what changed.
fn write_op<T>(
    store: &dyn MlsStore,
    group: &[u8],
    operation: impl FnOnce(Vec<u8>) -> anyhow::Result<(Vec<u8>, T)>,
) -> anyhow::Result<T> {
    let (before, state) = load(store, group)?;
    let (new_state, output) = operation(state.to_vec())?;
    commit(store, &before, new_state)?;
    Ok(output)
}

/// An openmls provider whose storage holds `entries`.
fn load_provider(entries: &EntryMap) -> OpenMlsRustCrypto {
    let provider = OpenMlsRustCrypto::default();
    let loaded = entries
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    *provider.storage().values.write().unwrap() = loaded;
    provider
}

/// The entries in `provider`'s storage, wiping the provider's own copy.
fn take_entries(provider: &OpenMlsRustCrypto) -> EntryMap {
    let entries: EntryMap = provider
        .storage()
        .values
        .read()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for value in provider.storage().values.write().unwrap().values_mut() {
        value.zeroize();
    }
    entries
}

/// Run an operation directly on an in-memory openmls provider holding the group's entries, with no
/// whole-state serialization in between, and store what it changed.
fn direct_op<T>(
    store: &dyn MlsStore,
    group: &[u8],
    operation: impl FnOnce(&OpenMlsRustCrypto) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let before = read_entries(store, group).map_err(store_error)?;
    if before.is_empty() {
        anyhow::bail!("the store holds no state for this group");
    }
    let provider = load_provider(&before);
    let output = operation(&provider);
    let after = take_entries(&provider);
    let output = output?;
    apply_change(store, group, &before, &after).map_err(store_error)?;
    Ok(output)
}

/// Run an operation that makes a group, and store its entries. Returns the new group's id.
fn create_op(
    store: &dyn MlsStore,
    operation: impl FnOnce() -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<Vec<u8>> {
    let state = operation()?;
    commit(store, &BTreeMap::new(), state)
}

// ---- mls ----

/// Make a group named `group_id` with this device as its only member.
pub fn create_group(store: &dyn MlsStore, group_id: &str, bundle: &[u8]) -> anyhow::Result<()> {
    create_op(store, || {
        groups::create_group(group_id.to_owned(), bundle.to_vec())
    })
    .map(drop)
}

/// Encrypt `message` to the group. Returns the ciphertext.
pub fn encrypt_message(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    message: &[u8],
) -> anyhow::Result<Vec<u8>> {
    direct_op(store, group, |provider| {
        groups::encrypt_in(provider, group, bundle, message)
    })
}

/// Decrypt `ciphertext`. Returns the plaintext and the member the group authenticated as its sender.
pub fn decrypt_message(
    store: &dyn MlsStore,
    group: &[u8],
    _bundle: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<(Vec<u8>, AuthenticatedSender)> {
    direct_op(store, group, |provider| {
        groups::decrypt_in(provider, group, ciphertext)
    })
}

/// Add the member holding `key_package`. Returns the Welcome and the Commit.
pub fn add_member(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    key_package: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    write_op(store, group, |state| {
        let (state, welcome, commit) =
            groups::add_member(state, bundle.to_vec(), key_package.to_vec())?;
        Ok((state, (welcome, commit)))
    })
}

/// Add every member holding one of `key_packages` in one commit. Returns the Welcome and the Commit.
pub fn add_members_bulk(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    key_packages: &[Vec<u8>],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    write_op(store, group, |state| {
        let (state, welcome, commit) =
            groups::add_members_bulk(state, bundle.to_vec(), key_packages.to_vec())?;
        Ok((state, (welcome, commit)))
    })
}

/// Remove the member whose credential is `credential_identity`. Returns the Commit.
pub fn remove_member_by_credential(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    credential_identity: &str,
) -> anyhow::Result<Vec<u8>> {
    write_op(store, group, |state| {
        groups::remove_member_by_credential(state, bundle.to_vec(), credential_identity.to_owned())
    })
}

/// Remove the member at `leaf_index`, if it holds `expected_signature_key`. Returns the Commit.
pub fn remove_member_by_leaf_index(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    leaf_index: u32,
    expected_signature_key: &str,
) -> anyhow::Result<Vec<u8>> {
    write_op(store, group, |state| {
        groups::remove_member_by_leaf_index(
            state,
            bundle.to_vec(),
            leaf_index,
            expected_signature_key.to_owned(),
        )
    })
}

/// The group's members.
pub fn list_members(store: &dyn MlsStore, group: &[u8]) -> anyhow::Result<Vec<String>> {
    read_op(store, group, groups::list_members)
}

/// The group's members with the leaf each occupies.
pub fn list_members_with_indices(
    store: &dyn MlsStore,
    group: &[u8],
) -> anyhow::Result<Vec<IndexedMlsMember>> {
    read_op(store, group, groups::list_members_with_indices)
}

/// Join the group a Welcome is for. Returns the group id and the updated identity bundle (the key
/// package the Welcome used is spent).
pub fn process_welcome(
    store: &dyn MlsStore,
    welcome: &[u8],
    bundle: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let (state, bundle) = groups::process_welcome(welcome.to_vec(), bundle.to_vec())?;
    let group = commit(store, &BTreeMap::new(), state)?;
    Ok((group, bundle))
}

/// Apply a Commit another member made. Returns the member the group authenticated as its sender.
pub fn mls_process_commit(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    commit: &[u8],
) -> anyhow::Result<AuthenticatedSender> {
    write_op(store, group, |state| {
        groups::mls_process_commit(state, bundle.to_vec(), commit.to_vec())
    })
}

/// The group's epoch and retention settings.
pub fn inspect_group(store: &dyn MlsStore, group: &[u8]) -> anyhow::Result<GroupStateMetadata> {
    let (_, state) = load(store, group)?;
    inspection::inspect_group_state(&state)
}

// ---- mimi ----

/// Make a MIMI group named `group_id` with this device as its only member.
pub fn mimi_create_group(
    store: &dyn MlsStore,
    group_id: &str,
    bundle: &[u8],
) -> anyhow::Result<()> {
    create_op(store, || {
        mimi::mimi_create_group(group_id.to_owned(), bundle.to_vec())
    })
    .map(drop)
}

/// Make a MIMI group that accepts removal proposals from the hub's external sender.
pub fn mimi_create_group_with_external_senders(
    store: &dyn MlsStore,
    group_id: &str,
    bundle: &[u8],
    hub_signature_key: &[u8],
    hub_credential_identity: &str,
) -> anyhow::Result<()> {
    create_op(store, || {
        mimi::mimi_create_group_with_external_senders(
            group_id.to_owned(),
            bundle.to_vec(),
            hub_signature_key.to_vec(),
            hub_credential_identity.to_owned(),
        )
    })
    .map(drop)
}

/// Add a member and return the Welcome.
pub fn mimi_add_member(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    key_package: &[u8],
) -> anyhow::Result<Vec<u8>> {
    write_op(store, group, |state| {
        mimi::mimi_add_member(state, bundle.to_vec(), key_package.to_vec())
    })
}

/// Add a member. Returns the Welcome and the Commit.
pub fn mimi_add_member_commit(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    key_package: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    write_op(store, group, |state| {
        let (state, welcome, commit) =
            mimi::mimi_add_member_commit(state, bundle.to_vec(), key_package.to_vec())?;
        Ok((state, (welcome, commit)))
    })
}

/// Remove the member whose credential is `credential_identity`. Returns the Commit.
pub fn mimi_remove_member_commit(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    credential_identity: &str,
) -> anyhow::Result<Vec<u8>> {
    write_op(store, group, |state| {
        mimi::mimi_remove_member_commit(state, bundle.to_vec(), credential_identity.to_owned())
    })
}

/// Remove the member at `leaf_index`, if it holds `expected_signature_key`. Returns the Commit.
pub fn mimi_remove_member_commit_by_leaf_index(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    leaf_index: u32,
    expected_signature_key: &str,
) -> anyhow::Result<Vec<u8>> {
    write_op(store, group, |state| {
        mimi::mimi_remove_member_commit_by_leaf_index(
            state,
            bundle.to_vec(),
            leaf_index,
            expected_signature_key.to_owned(),
        )
    })
}

/// Commit the removal an external sender proposed. Returns the Commit.
pub fn mimi_accept_external_remove_proposal(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    external_proposal: &[u8],
) -> anyhow::Result<Vec<u8>> {
    write_op(store, group, |state| {
        mimi::mimi_accept_external_remove_proposal(
            state,
            bundle.to_vec(),
            external_proposal.to_vec(),
        )
    })
}

/// Add a member and carry `roster_payload` in the commit. Returns the Welcome and the Commit.
pub fn mimi_add_member_commit_appsync(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    key_package: &[u8],
    roster_payload: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    write_op(store, group, |state| {
        let (state, welcome, commit) = mimi::mimi_add_member_commit_appsync(
            state,
            bundle.to_vec(),
            key_package.to_vec(),
            roster_payload.to_vec(),
        )?;
        Ok((state, (welcome, commit)))
    })
}

/// Add every member in `key_packages` and carry `roster_payload` in the commit. Returns the Welcome and
/// the Commit.
pub fn mimi_add_members_bulk_commit_appsync(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    key_packages: &[Vec<u8>],
    roster_payload: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    write_op(store, group, |state| {
        let (state, welcome, commit) = mimi::mimi_add_members_bulk_commit_appsync(
            state,
            bundle.to_vec(),
            key_packages.to_vec(),
            roster_payload.to_vec(),
        )?;
        Ok((state, (welcome, commit)))
    })
}

/// Remove a member and carry `roster_payload` in the commit. Returns the Commit.
pub fn mimi_remove_member_commit_appsync(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    credential_identity: &str,
    roster_payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    write_op(store, group, |state| {
        mimi::mimi_remove_member_commit_appsync(
            state,
            bundle.to_vec(),
            credential_identity.to_owned(),
            roster_payload.to_vec(),
        )
    })
}

/// Apply a Commit another member made. Returns the roster payload it carried and its authenticated
/// sender.
pub fn mls_process_commit_appsync(
    store: &dyn MlsStore,
    group: &[u8],
    bundle: &[u8],
    commit: &[u8],
) -> anyhow::Result<(Vec<u8>, AuthenticatedSender)> {
    write_op(store, group, |state| {
        let (state, payload, sender) =
            mimi::mls_process_commit_appsync(state, bundle.to_vec(), commit.to_vec())?;
        Ok((state, (payload, sender)))
    })
}

/// Finish a join that [`mimi::prepare_welcome_retirement`] prepared, and store the group. Returns the
/// group id and the identity bundle. A failure to store after the join is reported as
/// [`MimiWelcomeError::Spent`], carrying the retired bundle the caller must persist.
pub fn complete_welcome(
    store: &dyn MlsStore,
    prepared: PreparedWelcome,
) -> Result<(Vec<u8>, Vec<u8>), MimiWelcomeError> {
    let (state, bundle) = mimi::complete_welcome(prepared)?;
    match commit(store, &BTreeMap::new(), state) {
        Ok(group) => Ok((group, bundle)),
        Err(error) => Err(MimiWelcomeError::Spent {
            retired_bundle: bundle,
            reason: format!("the joined group could not be stored: {error}"),
        }),
    }
}

#[cfg(test)]
mod tests;
