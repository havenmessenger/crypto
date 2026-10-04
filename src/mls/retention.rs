//! Effective receive-secret retention and explicit migration of serialized groups.

use super::{inspection::InspectionProvider, GroupState};
use openmls::prelude::{GroupContext, GroupId, MlsGroup, MlsGroupJoinConfig};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    storage::{traits, Entity, StorageProvider, CURRENT_VERSION},
    OpenMlsProvider,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tls_codec::Deserialize as _;
use zeroize::Zeroize;

/// Receive secrets for three prior epochs tolerate bounded late application delivery.
pub const PAST_EPOCH_RETENTION: usize = 3;

/// Public retention metadata; capacity is distinct from the number of stored epochs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRetentionMetadata {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub configured_max_past_epochs: usize,
    pub effective_max_past_epochs: usize,
    pub retained_epochs: Vec<u64>,
}

// The public storage traits accept consumer-owned serialized entities. This adapter matches
// the locked MessageSecretsStore layout and preserves each secret payload without interpretation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageSecretsStore {
    max_epochs: usize,
    past_epoch_trees: Vec<EpochTree>,
    message_secrets: SecretPayload,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochTree {
    epoch: u64,
    message_secrets: SecretPayload,
    leaves: SecretPayload,
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct SecretPayload(Box<serde_json::value::RawValue>);

impl Drop for SecretPayload {
    fn drop(&mut self) {
        let mut bytes: Box<str> = std::mem::take(&mut self.0).into();
        bytes.zeroize();
    }
}

impl Entity<CURRENT_VERSION> for MessageSecretsStore {}
impl traits::MessageSecrets<CURRENT_VERSION> for MessageSecretsStore {}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct StoredJoinConfig {
    configuration: SecretPayload,
}

impl Entity<CURRENT_VERSION> for StoredJoinConfig {}
impl traits::MlsGroupJoinConfig<CURRENT_VERSION> for StoredJoinConfig {}

#[derive(Deserialize)]
struct RetentionConfig {
    max_past_epochs: usize,
}

fn with_state<T>(
    bytes: &[u8],
    operation: impl FnOnce(&mut GroupState, &InspectionProvider, &GroupId) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let mut state: GroupState = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("Invalid local MLS group state"))?;
    let mut keys = BTreeSet::new();
    if state.group_id.is_empty() || state.storage_map.iter().any(|(key, _)| !keys.insert(key)) {
        anyhow::bail!("Ambiguous local MLS group storage");
    }
    let group_id = GroupId::from_slice(&state.group_id);
    let provider = InspectionProvider(OpenMlsRustCrypto::default());
    *provider
        .0
        .storage()
        .values
        .write()
        .map_err(|_| anyhow::anyhow!("Local MLS retention storage is unavailable"))? =
        std::mem::take(&mut state.storage_map).into_iter().collect();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        operation(&mut state, &provider, &group_id)
    }))
    .map_err(|_| anyhow::anyhow!("Invalid local MLS retention metadata"))?
}

fn context_for_payload(payload: &SecretPayload) -> anyhow::Result<GroupContext> {
    #[derive(Deserialize)]
    struct SecretContext {
        serialized_context: Vec<u8>,
    }
    let context: SecretContext = serde_json::from_str(payload.0.get())
        .map_err(|_| anyhow::anyhow!("Invalid local MLS secret context"))?;
    GroupContext::tls_deserialize_exact(&context.serialized_context)
        .map_err(|_| anyhow::anyhow!("Invalid local MLS secret context"))
}

fn read_retention(
    provider: &InspectionProvider,
    group_id: &GroupId,
) -> anyhow::Result<(
    GroupRetentionMetadata,
    MessageSecretsStore,
    MlsGroupJoinConfig,
)> {
    let group = MlsGroup::load(provider.0.storage(), group_id)?
        .ok_or_else(|| anyhow::anyhow!("Local MLS group is incomplete"))?;
    if group.group_id() != group_id {
        anyhow::bail!("Local MLS group belongs to another group");
    }
    let config: MlsGroupJoinConfig = provider
        .0
        .storage()
        .mls_group_join_config(group_id)?
        .ok_or_else(|| anyhow::anyhow!("Local MLS group configuration is missing"))?;
    let persisted: StoredJoinConfig = provider
        .0
        .storage()
        .mls_group_join_config(group_id)?
        .ok_or_else(|| anyhow::anyhow!("Local MLS group configuration is missing"))?;
    let configuration = serde_json::to_value(&config)?;
    if serde_json::from_str::<serde_json::Value>(persisted.configuration.0.get())? != configuration
    {
        anyhow::bail!("Unsupported local MLS group configuration shape");
    }
    let configured = serde_json::from_value::<RetentionConfig>(configuration)?.max_past_epochs;
    let store: MessageSecretsStore = provider
        .0
        .storage()
        .message_secrets(group_id)?
        .ok_or_else(|| anyhow::anyhow!("Local MLS message-secret store is missing"))?;
    let epoch = group.epoch().as_u64();
    let capacity = u64::try_from(store.max_epochs)
        .map_err(|_| anyhow::anyhow!("Local MLS retention capacity is unsupported"))?;
    if store.past_epoch_trees.len() > store.max_epochs {
        anyhow::bail!("Local MLS retained epochs exceed capacity");
    }
    let current = context_for_payload(&store.message_secrets)?;
    let context: GroupContext = provider
        .0
        .storage()
        .group_context(group_id)?
        .ok_or_else(|| anyhow::anyhow!("Local MLS group context is missing"))?;
    if current != context {
        anyhow::bail!("Local MLS current secrets do not match the group epoch");
    }
    let mut previous = None;
    let mut retained_epochs = Vec::with_capacity(store.past_epoch_trees.len());
    for tree in &store.past_epoch_trees {
        let context = context_for_payload(&tree.message_secrets)?;
        if tree.epoch >= epoch
            || tree.epoch < epoch.saturating_sub(capacity)
            || previous.is_some_and(|prior| prior >= tree.epoch)
            || context.group_id() != group_id
            || context.epoch().as_u64() != tree.epoch
        {
            anyhow::bail!("Invalid local MLS retained epoch binding");
        }
        previous = Some(tree.epoch);
        retained_epochs.push(tree.epoch);
    }
    Ok((
        GroupRetentionMetadata {
            group_id: group_id.to_vec(),
            epoch,
            configured_max_past_epochs: configured,
            effective_max_past_epochs: store.max_epochs,
            retained_epochs,
        },
        store,
        config,
    ))
}

/// Inspect the actual persisted secret-store capacity without processing a message.
/// A config-only change remains visible as different configured and effective values.
/// Missing, corrupt, ambiguous or inconsistently bound storage is refused. Owned provider
/// and adapter copies are wiped on drop; upstream typed secret copies keep their existing
/// zeroization boundary. Capacity does not imply possession of every prior epoch's keys.
pub fn inspect_group_retention(bytes: &[u8]) -> anyhow::Result<GroupRetentionMetadata> {
    with_state(bytes, |_, provider, group_id| {
        Ok(read_retention(provider, group_id)?.0)
    })
}

pub(crate) fn historical_signature_key(
    provider: &OpenMlsRustCrypto,
    processed: &openmls::prelude::ProcessedMessage,
    leaf_index: openmls::prelude::LeafNodeIndex,
) -> anyhow::Result<Vec<u8>> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let store: MessageSecretsStore = provider
            .storage()
            .message_secrets(processed.group_id())?
            .ok_or_else(|| anyhow::anyhow!("Historical MLS message secrets are missing"))?;
        let mut epochs = store
            .past_epoch_trees
            .iter()
            .filter(|tree| tree.epoch == processed.epoch().as_u64());
        let tree = epochs
            .next()
            .ok_or_else(|| anyhow::anyhow!("Historical MLS sender epoch is missing"))?;
        if epochs.next().is_some() {
            anyhow::bail!("Historical MLS sender epoch is ambiguous");
        }
        let context = context_for_payload(&tree.message_secrets)?;
        if context.group_id() != processed.group_id() || context.epoch() != processed.epoch() {
            anyhow::bail!("Historical MLS sender belongs to another group epoch");
        }
        let leaves: Vec<openmls::prelude::Member> = serde_json::from_str(tree.leaves.0.get())
            .map_err(|_| anyhow::anyhow!("Historical MLS sender tree is invalid"))?;
        let mut matches = leaves.iter().filter(|member| member.index == leaf_index);
        let member = matches
            .next()
            .ok_or_else(|| anyhow::anyhow!("Historical MLS sender leaf is missing"))?;
        if matches.next().is_some() || &member.credential != processed.credential() {
            anyhow::bail!("Historical MLS sender credential does not match");
        }
        Ok(member.signature_key.clone())
    }))
    .map_err(|_| anyhow::anyhow!("Invalid historical MLS sender metadata"))?
}

/// Raise configured and effective receive-secret retention to three in an isolated provider.
/// Returns a complete replacement state, or `None` for an already coherent window of at
/// least three. Larger windows are never shrunk. This cannot recover erased historical keys.
/// All group secrets, ratchets, pending state and unrelated entries are preserved; only the
/// two retention fields change. The caller atomically persists the replacement through its
/// state owner. Errors return no replacement and never modify the borrowed input.
pub fn migrate_group_retention_to_three(bytes: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    with_state(bytes, |state, provider, group_id| {
        let (before, mut store, config) = read_retention(provider, group_id)?;
        if before.configured_max_past_epochs == before.effective_max_past_epochs
            && before.effective_max_past_epochs >= PAST_EPOCH_RETENTION
        {
            return Ok(None);
        }
        if before.configured_max_past_epochs > PAST_EPOCH_RETENTION
            || before.effective_max_past_epochs > PAST_EPOCH_RETENTION
        {
            anyhow::bail!("Inconsistent larger MLS retention window");
        }
        let mut configuration = serde_json::to_value(&config)?;
        configuration["max_past_epochs"] = PAST_EPOCH_RETENTION.into();
        let configuration: MlsGroupJoinConfig = serde_json::from_value(configuration)?;
        provider
            .0
            .storage()
            .write_mls_join_config(group_id, &configuration)?;
        store.max_epochs = PAST_EPOCH_RETENTION;
        provider
            .0
            .storage()
            .write_message_secrets(group_id, &store)?;
        let after = read_retention(provider, group_id)?.0;
        if after.epoch != before.epoch
            || after.group_id != before.group_id
            || after.retained_epochs != before.retained_epochs
            || after.configured_max_past_epochs != PAST_EPOCH_RETENTION
            || after.effective_max_past_epochs != PAST_EPOCH_RETENTION
        {
            anyhow::bail!("Local MLS retention migration did not preserve group metadata");
        }
        state.storage_map = provider
            .0
            .storage()
            .values
            .read()
            .map_err(|_| anyhow::anyhow!("Local MLS retention storage is unavailable"))?
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        Ok(Some(super::zeroizing_json(state)?.to_vec()))
    })
}

#[cfg(test)]
mod tests;
