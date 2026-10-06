//! Where an MLS group's openmls storage entries live.
//!
//! An MLS group's secret state is a small set of openmls storage entries (the ratchet tree, the epoch
//! and message secrets, the group context and a few more), each a key and a value. [`MlsStore`] is the
//! consumer's home for them: crypto-core reads the entries an operation needs and writes back only the
//! ones the operation changed or removed, so a consumer sees exactly what changed and can journal it,
//! back it up as a log, or keep it in a database row per entry.
//!
//! Keys and values are opaque to the store. Values are secret material: an implementor protects them at
//! rest and does not log them. crypto-core stores each value in the compact binary form of
//! [`crate::mls::entry_codec`], which it reads back to the text openmls wrote; a value an older version
//! stored as text is read as it is.
//!
//! # Write contract
//!
//! An operation calls [`MlsStore::get`] and [`MlsStore::keys`] freely. It calls [`MlsStore::put`] and
//! [`MlsStore::delete`] only after its last fallible step, in one burst, and an operation that returns an
//! error has made none of those calls. Everything an operation changes is visible as those calls and
//! nothing else: no state is carried between operations. A consumer that needs a two-phase commit passes
//! a store that buffers the burst and applies it later.
//!
//! # State snapshots
//!
//! [`encode_state_v2`] and [`decode_state`] carry a whole group as one value, for a checkpoint or a
//! transfer: a format byte, then a compact binary body. [`decode_state`] also reads the earlier
//! `serde_json` form that the byte-in/byte-out functions of [`crate::mls::groups`] use.

use std::collections::BTreeMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::mls::entry_codec::{decode_value, encode_value};
use crate::mls::GroupState;

/// One storage entry: its key and its value.
pub type Entry = (Vec<u8>, Vec<u8>);

/// Why a store call failed.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum MlsStoreError {
    /// The store could not read or write.
    #[error("the MLS store failed: {0}")]
    Backend(String),
    /// What the store holds is not a valid entry or snapshot.
    #[error("the MLS store holds corrupt data: {0}")]
    Corrupt(String),
}

/// A consumer's storage for MLS group entries. See the module documentation for the write contract.
pub trait MlsStore {
    /// The value at `key` in `group`, or `None`.
    fn get(&self, group: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, MlsStoreError>;
    /// Store `value` at `key` in `group`, replacing any value.
    fn put(&self, group: &[u8], key: &[u8], value: &[u8]) -> Result<(), MlsStoreError>;
    /// Remove `key` from `group`. Removing an absent key succeeds.
    fn delete(&self, group: &[u8], key: &[u8]) -> Result<(), MlsStoreError>;
    /// Every key of `group`, in no particular order. An unknown group has none.
    fn keys(&self, group: &[u8]) -> Result<Vec<Vec<u8>>, MlsStoreError>;
}

/// A group's entries, by key.
pub type EntryMap = BTreeMap<Vec<u8>, Vec<u8>>;

/// An [`MlsStore`] held in memory. Its values are wiped when it is dropped.
#[derive(Default)]
pub struct MemoryMlsStore {
    groups: RwLock<BTreeMap<Vec<u8>, EntryMap>>,
}

impl MemoryMlsStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store holding the one group in `state`, in either snapshot form.
    pub fn from_state(state: &[u8]) -> Result<Self, MlsStoreError> {
        let store = Self::new();
        import_state(&store, state)?;
        Ok(store)
    }

    /// The group's snapshot in the earlier `serde_json` form.
    pub fn to_state_v1(&self, group: &[u8]) -> Result<Zeroizing<Vec<u8>>, MlsStoreError> {
        export_state_v1(self, group)
    }

    /// The group's snapshot in the binary form.
    pub fn to_state_v2(&self, group: &[u8]) -> Result<Zeroizing<Vec<u8>>, MlsStoreError> {
        export_state_v2(self, group)
    }

    /// The group's entries, sorted by key.
    #[must_use]
    pub fn entries(&self, group: &[u8]) -> Vec<Entry> {
        let groups = self
            .groups
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        groups
            .get(group)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Drop for MemoryMlsStore {
    fn drop(&mut self) {
        let groups = self
            .groups
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for entries in groups.values_mut() {
            for value in entries.values_mut() {
                value.zeroize();
            }
        }
    }
}

impl MlsStore for MemoryMlsStore {
    fn get(&self, group: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, MlsStoreError> {
        let groups = self
            .groups
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(groups
            .get(group)
            .and_then(|entries| entries.get(key))
            .cloned())
    }

    fn put(&self, group: &[u8], key: &[u8], value: &[u8]) -> Result<(), MlsStoreError> {
        let replaced = {
            let mut groups = self
                .groups
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            groups
                .entry(group.to_vec())
                .or_default()
                .insert(key.to_vec(), value.to_vec())
        };
        if let Some(mut old) = replaced {
            old.zeroize();
        }
        Ok(())
    }

    fn delete(&self, group: &[u8], key: &[u8]) -> Result<(), MlsStoreError> {
        let removed = {
            let mut groups = self
                .groups
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let removed = groups
                .get_mut(group)
                .and_then(|entries| entries.remove(key));
            if groups.get(group).is_some_and(BTreeMap::is_empty) {
                groups.remove(group);
            }
            removed
        };
        if let Some(mut old) = removed {
            old.zeroize();
        }
        Ok(())
    }

    fn keys(&self, group: &[u8]) -> Result<Vec<Vec<u8>>, MlsStoreError> {
        let groups = self
            .groups
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(groups
            .get(group)
            .map(|entries| entries.keys().cloned().collect())
            .unwrap_or_default())
    }
}

/// The format byte sequence that opens a binary snapshot: a name and the format version.
const STATE_V2_MAGIC: &[u8; 5] = b"MLSS\x02";

/// The body of a binary snapshot.
#[derive(Serialize, Deserialize)]
struct StateV2 {
    group_id: Vec<u8>,
    entries: Vec<Entry>,
}

impl Drop for StateV2 {
    fn drop(&mut self) {
        for (_, value) in &mut self.entries {
            value.zeroize();
        }
    }
}

/// Every entry of `group` in `store`, sorted by key, each value as the text openmls wrote.
pub fn read_entries(store: &dyn MlsStore, group: &[u8]) -> Result<EntryMap, MlsStoreError> {
    let mut entries = BTreeMap::new();
    for key in store.keys(group)? {
        let stored = store
            .get(group, &key)?
            .ok_or_else(|| MlsStoreError::Corrupt("a listed key has no value".into()))?;
        let value = decode_value(&stored)?;
        entries.insert(key, value.to_vec());
    }
    Ok(entries)
}

/// A binary snapshot of `group`: the format byte sequence, then the group id and its entries sorted by key.
pub fn encode_state_v2(
    group: &[u8],
    entries: &EntryMap,
) -> Result<Zeroizing<Vec<u8>>, MlsStoreError> {
    let body = StateV2 {
        group_id: group.to_vec(),
        entries: entries
            .iter()
            .map(|(k, v)| (k.clone(), encode_value(v)))
            .collect(),
    };
    let encoded = Zeroizing::new(
        postcard::to_allocvec(&body).map_err(|error| MlsStoreError::Corrupt(error.to_string()))?,
    );
    let mut bytes = Zeroizing::new(Vec::with_capacity(STATE_V2_MAGIC.len() + encoded.len()));
    bytes.extend_from_slice(STATE_V2_MAGIC);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

/// The group id and entries in a snapshot of either form: the binary form, or the `serde_json` form of
/// [`GroupState`].
pub fn decode_state(bytes: &[u8]) -> Result<(Vec<u8>, EntryMap), MlsStoreError> {
    if let Some(body) = bytes.strip_prefix(STATE_V2_MAGIC.as_slice()) {
        let state: StateV2 = postcard::from_bytes(body)
            .map_err(|error| MlsStoreError::Corrupt(format!("binary snapshot: {error}")))?;
        let mut entries = EntryMap::new();
        for (key, value) in &state.entries {
            entries.insert(key.clone(), decode_value(value)?.to_vec());
        }
        return Ok((state.group_id.clone(), entries));
    }
    let state: GroupState = serde_json::from_slice(bytes)
        .map_err(|error| MlsStoreError::Corrupt(format!("snapshot: {error}")))?;
    let entries = state
        .storage_map
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Ok((state.group_id.clone(), entries))
}

/// Put the group in `state` into `store`, replacing whatever the store held for that group, and return
/// the group id.
pub fn import_state(store: &dyn MlsStore, state: &[u8]) -> Result<Vec<u8>, MlsStoreError> {
    let (group, entries) = decode_state(state)?;
    apply_change(store, &group, &read_entries(store, &group)?, &entries)?;
    Ok(group)
}

/// The group's snapshot in the binary form.
pub fn export_state_v2(
    store: &dyn MlsStore,
    group: &[u8],
) -> Result<Zeroizing<Vec<u8>>, MlsStoreError> {
    encode_state_v2(group, &read_entries(store, group)?)
}

/// The group's snapshot in the `serde_json` form the byte-in/byte-out functions use.
pub fn export_state_v1(
    store: &dyn MlsStore,
    group: &[u8],
) -> Result<Zeroizing<Vec<u8>>, MlsStoreError> {
    state_v1(group, &read_entries(store, group)?)
}

/// The `serde_json` snapshot of `entries`.
pub(crate) fn state_v1(
    group: &[u8],
    entries: &EntryMap,
) -> Result<Zeroizing<Vec<u8>>, MlsStoreError> {
    let state = GroupState {
        group_id: group.to_vec(),
        storage_map: entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    };
    crate::mls::zeroizing_json(&state).map_err(|error| MlsStoreError::Corrupt(error.to_string()))
}

/// Make `store`'s entries for `group` equal `after`, given that they equal `before` (both as text): put what is
/// new or different, in the binary form, delete what is gone, and touch nothing else. Returns how many entries it put and deleted.
pub fn apply_change(
    store: &dyn MlsStore,
    group: &[u8],
    before: &EntryMap,
    after: &EntryMap,
) -> Result<(usize, usize), MlsStoreError> {
    let mut puts = 0;
    for (key, value) in after {
        if before.get(key) != Some(value) {
            store.put(group, key, &encode_value(value))?;
            puts += 1;
        }
    }
    let mut deletes = 0;
    for key in before.keys() {
        if !after.contains_key(key) {
            store.delete(group, key)?;
            deletes += 1;
        }
    }
    Ok((puts, deletes))
}

#[cfg(test)]
mod tests;
