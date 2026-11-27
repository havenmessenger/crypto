// SPDX-FileCopyrightText: 2026 The Haven Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sending, under the `virtual-clients` feature, as the one emulator that sends for its leaf.
//!
//! With virtual clients (draft-ietf-mls-virtual-clients), several emulator clients share one leaf and so one sending
//! ratchet. Two of them can encrypt at the same generation, and only one of those messages is accepted by the
//! delivery service. So openmls creates every message unconfirmed (`virtual-clients-draft`): the sender keeps the
//! ratchet secret it used until it confirms the message, which it is meant to do once the delivery service has
//! accepted exactly that message. If another emulator's message won that generation instead, the kept secret is
//! what decrypts it (§5.6.3, "Coordinating ratchet generations with the DS"). Under the feature, openmls offers no
//! call that sends without that step.
//!
//! This crate's API creates a message or commit in one call and hands it back. Here each one is confirmed in that
//! same call, so the sender keeps no secret beyond it: what a build without the feature does.
//!
//! That is correct only while **exactly one emulator sends for each leaf**. With one sender per leaf no generation
//! is ever contested, and a delivery-service refusal leaves an unused generation, as in any MLS group. An
//! application in which several emulators of one leaf send must not use these functions as they are: it has to
//! confirm after the delivery service accepts, and never confirm a message that lost its generation.
//!
//! Each function here does what openmls's own convenience method of the same name does, which the feature compiles
//! out, and then confirms what it created.

use openmls::ciphersuite::hash_ref::ProposalRef;
use openmls::messages::group_info::GroupInfo;
use openmls::prelude::{
    CommitMessageBundle, CustomProposal, HandshakeConfirmationData, KeyPackage, LeafNodeIndex,
    LeafNodeParameters, MlsGroup, MlsMessageOut, ProposalOrRefType, Propose,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::OpenMlsProvider;

/// Confirm the handshake message (proposal or commit) `confirmation` describes. A message framed as a
/// `PublicMessage` has no confirmation: there is nothing kept, so nothing to do.
fn confirm_handshake(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    confirmation: Option<&HandshakeConfirmationData>,
) -> anyhow::Result<()> {
    if let Some(data) = confirmation {
        group
            .confirm_handshake_message(provider.storage(), data.epoch, data.generation)
            .map_err(|e| anyhow::anyhow!("Error confirming the handshake message: {e:?}"))?;
    }
    Ok(())
}

/// Confirm a commit this member staged, before it is merged or sent.
pub fn confirm_commit(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    bundle: &CommitMessageBundle,
) -> anyhow::Result<()> {
    confirm_handshake(group, provider, bundle.confirmation())
}

/// `MlsGroup::create_message`: an application message, confirmed.
pub fn create_message(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &impl Signer,
    message: &[u8],
) -> anyhow::Result<MlsMessageOut> {
    let created = group
        .create_unconfirmed_message(provider, signer, message)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    group
        .confirm_application_message(provider.storage(), created.epoch, created.generation)
        .map_err(|e| anyhow::anyhow!("Error confirming the message: {e:?}"))?;
    Ok(created.message)
}

/// `MlsGroup::add_members`: a commit adding `key_packages` and updating the committer's own leaf, confirmed. Returns
/// the commit, the Welcome and the `GroupInfo`, as that method does.
pub fn add_members(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &impl Signer,
    key_packages: &[KeyPackage],
) -> anyhow::Result<(MlsMessageOut, MlsMessageOut, Option<GroupInfo>)> {
    if key_packages.is_empty() {
        anyhow::bail!("no KeyPackage to add");
    }
    let bundle = group
        .commit_builder()
        .propose_adds(key_packages.iter().cloned())
        .force_self_update(true)
        .load_psks(provider.storage())
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .stage_commit(provider)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    confirm_commit(group, provider, &bundle)?;
    let welcome = bundle
        .to_welcome_msg()
        .ok_or_else(|| anyhow::anyhow!("an Add commit produced no Welcome"))?;
    let (commit, _, group_info) = bundle.into_contents();
    group.set_aad(Vec::new());
    Ok((commit, welcome, group_info))
}

/// `MlsGroup::remove_members`: a commit removing `members`, confirmed. Returns the commit, a Welcome if the commit
/// made one, and the `GroupInfo`, as that method does.
pub fn remove_members(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &impl Signer,
    members: &[LeafNodeIndex],
) -> anyhow::Result<(MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>)> {
    if members.is_empty() {
        anyhow::bail!("no member to remove");
    }
    let bundle = group
        .commit_builder()
        .propose_removals(members.iter().copied())
        .load_psks(provider.storage())
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .stage_commit(provider)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    confirm_commit(group, provider, &bundle)?;
    let welcome = bundle.to_welcome_msg();
    let (commit, _, group_info) = bundle.into_contents();
    group.set_aad(Vec::new());
    Ok((commit, welcome, group_info))
}

/// `MlsGroup::self_update`: a commit renewing the committer's own leaf with `leaf_node_parameters` and covering the
/// pending proposals, confirmed.
pub fn self_update(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &impl Signer,
    leaf_node_parameters: LeafNodeParameters,
) -> anyhow::Result<CommitMessageBundle> {
    let bundle = group
        .commit_builder()
        .leaf_node_parameters(leaf_node_parameters)
        .consume_proposal_store(true)
        .load_psks(provider.storage())
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .stage_commit(provider)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    confirm_commit(group, provider, &bundle)?;
    group.set_aad(Vec::new());
    Ok(bundle)
}

/// `MlsGroup::leave_group`: a proposal, by reference, to remove this member's own leaf, confirmed.
pub fn leave_group(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &impl Signer,
) -> anyhow::Result<MlsMessageOut> {
    let own = group.own_leaf_index().u32();
    let (message, _reference, confirmation) = group
        .propose_unconfirmed(
            provider,
            signer,
            Propose::Remove(own),
            ProposalOrRefType::Reference,
        )
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    confirm_handshake(group, provider, confirmation.as_ref())?;
    Ok(message)
}

/// `MlsGroup::propose_custom_proposal_by_value`: a custom proposal, by value, confirmed.
pub fn propose_custom_proposal_by_value(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &impl Signer,
    custom: CustomProposal,
) -> anyhow::Result<(MlsMessageOut, ProposalRef)> {
    let (message, reference, confirmation) = group
        .propose_unconfirmed(
            provider,
            signer,
            Propose::Custom(custom),
            ProposalOrRefType::Proposal,
        )
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    confirm_handshake(group, provider, confirmation.as_ref())?;
    Ok((message, reference))
}

/// `MlsGroup::propose_app_data_update`: an `AppDataUpdate` proposal, by value, confirmed.
#[cfg(feature = "mimi-app-data")]
pub fn propose_app_data_update(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &impl Signer,
    component_id: openmls::component::ComponentId,
    operation: openmls::messages::proposals::AppDataUpdateOperation,
) -> anyhow::Result<(MlsMessageOut, ProposalRef)> {
    use openmls::messages::proposals::AppDataUpdateOperation;
    let propose = match operation {
        AppDataUpdateOperation::Update(update) => Propose::UpdateAppDataComponent {
            component_id,
            update: update.as_slice().to_vec(),
        },
        AppDataUpdateOperation::Remove => Propose::RemoveAppDataComponent { component_id },
    };
    let (message, reference, confirmation) = group
        .propose_unconfirmed(provider, signer, propose, ProposalOrRefType::Proposal)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    confirm_handshake(group, provider, confirmation.as_ref())?;
    Ok((message, reference))
}

#[cfg(test)]
#[path = "single_sender_tests.rs"]
mod tests;
