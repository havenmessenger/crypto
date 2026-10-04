//! Read-only MLS framing and local group metadata, without decrypting or advancing state.

use openmls::prelude::{
    ContentType, GroupContext, GroupId, MlsGroupJoinConfig, MlsMessageIn, ProtocolMessage,
    WireFormat,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{storage::StorageProvider, OpenMlsProvider};
use tls_codec::Deserialize as _;
use zeroize::Zeroize;

/// The clear content type of a private MLS message, before authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateContentType {
    Application,
    Proposal,
    Commit,
}

/// Clear routing metadata only: these fields prove neither a sender nor a plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateMessageMetadata {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: PrivateContentType,
}

/// Inspect one complete, size-bounded MLS message using the library's TLS decoder.
/// Public messages and non-protocol objects return `None`; malformed input is refused.
/// No state, keys, plaintext or sender identity are read or returned.
pub fn inspect_private_message(bytes: &[u8]) -> anyhow::Result<Option<PrivateMessageMetadata>> {
    super::check_wire_size(bytes, "inspect_private_message")?;
    let message = std::panic::catch_unwind(|| MlsMessageIn::tls_deserialize_exact(bytes))
        .map_err(|_| anyhow::anyhow!("Invalid MLS message framing"))?
        .map_err(|_| anyhow::anyhow!("Invalid MLS message framing"))?;
    let Ok(protocol) = ProtocolMessage::try_from(message) else {
        return Ok(None);
    };
    if protocol.wire_format() != WireFormat::PrivateMessage {
        return Ok(None);
    }
    let content_type = match protocol.content_type() {
        ContentType::Application => PrivateContentType::Application,
        ContentType::Proposal => PrivateContentType::Proposal,
        ContentType::Commit => PrivateContentType::Commit,
    };
    Ok(Some(PrivateMessageMetadata {
        group_id: protocol.group_id().to_vec(),
        epoch: protocol.epoch().as_u64(),
        content_type,
    }))
}

/// Public local group metadata and the receive-secret retention configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupStateMetadata {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub max_past_epochs: usize,
}

// The provider configuration is serializable but has no public retention getter.
#[derive(serde::Deserialize)]
struct RetentionConfig {
    max_past_epochs: usize,
}

struct InspectionProvider(OpenMlsRustCrypto);

impl Drop for InspectionProvider {
    fn drop(&mut self) {
        let mut values = self
            .0
            .storage()
            .values
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for value in values.values_mut() {
            value.zeroize();
        }
    }
}

/// Read metadata from an existing serialized group without processing any message.
/// The caller's bytes are borrowed unchanged; copied provider storage is wiped on drop.
/// Missing or corrupt context/configuration and inconsistent group identities are errors.
pub fn inspect_group_state(bytes: &[u8]) -> anyhow::Result<GroupStateMetadata> {
    let mut state: super::GroupState = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("Invalid local MLS group state"))?;
    let group_id = GroupId::from_slice(&state.group_id);
    let provider = InspectionProvider(OpenMlsRustCrypto::default());
    *provider
        .0
        .storage()
        .values
        .write()
        .map_err(|_| anyhow::anyhow!("Local MLS inspection storage is unavailable"))? =
        std::mem::take(&mut state.storage_map).into_iter().collect();
    // Provider deserialization can panic on corrupt local metadata. Inspection is read-only,
    // so reject that snapshot without exposing an unwind to the caller's receive loop.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let context: GroupContext = provider
            .0
            .storage()
            .group_context(&group_id)?
            .ok_or_else(|| anyhow::anyhow!("Local MLS group context is missing"))?;
        if context.group_id() != &group_id {
            anyhow::bail!("Local MLS group context belongs to another group");
        }
        let config: MlsGroupJoinConfig = provider
            .0
            .storage()
            .mls_group_join_config(&group_id)?
            .ok_or_else(|| anyhow::anyhow!("Local MLS group configuration is missing"))?;
        Ok(GroupStateMetadata {
            group_id: group_id.to_vec(),
            epoch: context.epoch().as_u64(),
            max_past_epochs: serde_json::from_value::<RetentionConfig>(serde_json::to_value(
                config,
            )?)?
            .max_past_epochs,
        })
    }))
    .map_err(|_| anyhow::anyhow!("Invalid local MLS group metadata"))?
}

#[cfg(test)]
mod tests;
