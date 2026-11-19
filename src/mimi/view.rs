//! Read-only views of a MIMI-lane group, a KeyPackage and a processed Commit: what any member of the group can see.
//!
//! A view holds identities, leaf indexes, epochs, lifetimes and type codes, and nothing else. No view type has a field
//! that could carry key material (no private key, exporter or epoch secret, encryption key or signature key), so a
//! caller that prints a view prints nothing secret. Reading a view changes no state: the group is loaded into a
//! scratch provider whose storage is wiped when it is dropped.

use openmls::prelude::*;
use openmls::treesync::LeafNodeSource;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::Deserialize as _;

use crate::mls::inspection::InspectionProvider;
use crate::mls::GroupState;

/// One leaf of the group's tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimiLeafView {
    pub index: u32,
    /// The credential's content: for a basic credential, its identity.
    pub identity: Vec<u8>,
    /// The credential type (RFC 9420 §17.5: 1 basic, 2 x509).
    pub credential_type: u16,
    /// The leaf's lifetime (not before, not after, in seconds since the epoch) when the leaf came from a KeyPackage;
    /// none for a leaf set by an Update or a Commit, which carries no lifetime (RFC 9420 §7.2).
    pub lifetime: Option<(u64, u64)>,
}

/// The group as this member's state has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimiGroupView {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub cipher_suite: u16,
    /// This member's own leaf.
    pub own_leaf: u32,
    pub leaves: Vec<MimiLeafView>,
    /// The GroupContext's extensions, by type.
    pub context_extension_types: Vec<u16>,
    /// The components of the GroupContext's app data dictionary, by id (draft-ietf-mls-extensions §4.6); empty
    /// without the `mimi-app-data` feature.
    pub components: Vec<u16>,
}

/// A KeyPackage, as anyone it is published to can read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimiKeyPackageView {
    pub cipher_suite: u16,
    pub not_before: u64,
    pub not_after: u64,
    /// The KeyPackage's own extensions, by type.
    pub extension_types: Vec<u16>,
    /// Its leaf's capabilities: extensions, proposals and credentials, by type.
    pub capability_extensions: Vec<u16>,
    pub capability_proposals: Vec<u16>,
    pub capability_credentials: Vec<u16>,
    /// Marked last resort (draft-ietf-mls-extensions §6.4, or the `last_resort` extension).
    pub last_resort: bool,
}

/// A Commit this member processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimiCommitSummary {
    /// The epoch the Commit moved the group to.
    pub epoch: u64,
    pub committer_leaf: u32,
    /// Every proposal the Commit applies, by value or by reference, by type.
    pub proposal_types: Vec<u16>,
    /// Whether the Commit carried an UpdatePath.
    pub path_present: bool,
}

/// The view of the group `group_state_bytes` holds. Refuses state that does not decode or holds no group.
pub fn mimi_group_view(group_state_bytes: &[u8]) -> anyhow::Result<MimiGroupView> {
    let mut state: GroupState = serde_json::from_slice(group_state_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid local MLS group state"))?;
    let group_id = GroupId::from_slice(&state.group_id);
    let provider = InspectionProvider(OpenMlsRustCrypto::default());
    *provider
        .0
        .storage()
        .values
        .write()
        .map_err(|_| anyhow::anyhow!("Local MLS view storage is unavailable"))? =
        std::mem::take(&mut state.storage_map).into_iter().collect();
    // Loading can panic on corrupt local state; a view is read-only, so that state is refused instead.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let group = MlsGroup::load(provider.0.storage(), &group_id)
            .map_err(|_| anyhow::anyhow!("Local MLS group does not load"))?
            .ok_or_else(|| anyhow::anyhow!("Local MLS group is missing"))?;
        let public = group.public_group();
        let leaves = group
            .members()
            .map(|member| MimiLeafView {
                index: member.index.u32(),
                identity: member.credential.serialized_content().to_vec(),
                credential_type: member.credential.credential_type().into(),
                lifetime: public.leaf(member.index).and_then(|leaf| {
                    match leaf.leaf_node_source() {
                        LeafNodeSource::KeyPackage(lifetime) => {
                            Some((lifetime.not_before(), lifetime.not_after()))
                        }
                        _ => None,
                    }
                }),
            })
            .collect();
        // The app data dictionary exists only with the `mimi-app-data` feature; without it a group has no components.
        #[cfg_attr(not(feature = "mimi-app-data"), allow(unused_mut))]
        let mut components: Vec<u16> = Vec::new();
        #[cfg(feature = "mimi-app-data")]
        for extension in group.extensions().iter() {
            if let Extension::AppDataDictionary(dictionary) = extension {
                components.extend(
                    dictionary
                        .dictionary()
                        .entries()
                        .map(openmls::component::ComponentData::id),
                );
            }
        }
        Ok(MimiGroupView {
            group_id: group.group_id().to_vec(),
            epoch: group.epoch().as_u64(),
            cipher_suite: group.ciphersuite().into(),
            own_leaf: group.own_leaf_index().u32(),
            leaves,
            context_extension_types: group
                .extensions()
                .iter()
                .map(|extension| extension.extension_type().into())
                .collect(),
            components,
        })
    }))
    .map_err(|_| anyhow::anyhow!("Invalid local MLS group state"))?
}

/// The view of a KeyPackage, from its TLS encoding (as published). It is validated first (RFC 9420 §10.1), so a view
/// is only ever of a well-formed, correctly signed KeyPackage.
pub fn mimi_key_package_view(key_package_bytes: &[u8]) -> anyhow::Result<MimiKeyPackageView> {
    crate::mls::check_wire_size(key_package_bytes, "mimi KeyPackage view")?;
    let key_package = KeyPackageIn::tls_deserialize_exact(key_package_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid KeyPackage"))?
        .validate(
            OpenMlsRustCrypto::default().crypto(),
            ProtocolVersion::Mls10,
        )
        .map_err(|_| anyhow::anyhow!("KeyPackage does not validate"))?;
    let capabilities = key_package.leaf_node().capabilities();
    Ok(MimiKeyPackageView {
        cipher_suite: key_package.ciphersuite().into(),
        not_before: key_package.life_time().not_before(),
        not_after: key_package.life_time().not_after(),
        extension_types: key_package
            .extensions()
            .iter()
            .map(|extension| extension.extension_type().into())
            .collect(),
        capability_extensions: capabilities
            .extensions()
            .iter()
            .map(|&kind| kind.into())
            .collect(),
        capability_proposals: capabilities
            .proposals()
            .iter()
            .map(|&kind| kind.into())
            .collect(),
        capability_credentials: capabilities
            .credentials()
            .iter()
            .map(|&kind| kind.into())
            .collect(),
        last_resort: key_package.last_resort(),
    })
}

/// The summary of a staged Commit, sent by the member at `committer_leaf`.
pub(crate) fn commit_summary(staged: &StagedCommit, committer_leaf: u32) -> MimiCommitSummary {
    MimiCommitSummary {
        epoch: staged.group_context().epoch().as_u64(),
        committer_leaf,
        proposal_types: staged
            .queued_proposals()
            .map(|queued| queued.proposal().proposal_type().into())
            .collect(),
        path_present: staged.update_path_leaf_node().is_some(),
    }
}

#[cfg(test)]
#[path = "view_tests.rs"]
mod tests;
