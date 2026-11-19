//! MIMI rooms whose state lives in the GroupContext's app data dictionary (draft-ietf-mls-extensions §4.6, §4.7), such
//! as the participant list (draft-ietf-mimi-room-policy), and changes by AppDataUpdate proposals.
//!
//! What a component's value means is the caller's. A commit carries each change as an update payload or a removal;
//! every member, the committer included, computes the component's value after it with the same [`Resolve`] function
//! the caller gives, so all of them arrive at the same dictionary. A member whose computation differs gets a different
//! GroupContext, and openmls refuses the commit on its confirmation tag.

use std::collections::BTreeMap;
use std::mem;

use openmls::component::ComponentData;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as _, Serialize as _};
use zeroize::{Zeroize as _, Zeroizing};

use super::{member_index, validated_key_package};
use crate::mls::pending::{open_group, staged, PendingCommit, WelcomeForm};
use crate::mls::{GroupState, IdentityBundle, MlsSigner};

/// One change to a component that a commit carries.
#[derive(Clone, Copy, Debug)]
pub enum Change<'a> {
    /// An update, with its payload.
    Update(&'a [u8]),
    /// The component's removal.
    Remove,
}

/// The value a component has after a commit's changes to it: given the component, its value before the commit (none
/// when absent) and every change the commit makes to it, in the commit's order. Updates give a value; a removal, which
/// is a component's only change when it has one, gives none. An error refuses the commit. This is the hand-off
/// draft-ietf-mls-extensions §4.7 describes: what a component's updates mean together is the component's to define.
///
/// It is not told who proposed a change. The room's hub is where a room's policy on who may change what is enforced
/// (draft-ietf-mimi-protocol); these rules say what the changes do to the value, and whether they can apply at all.
pub type Resolve<'a> =
    &'a dyn Fn(u16, Option<&[u8]>, &[Change<'_>]) -> anyhow::Result<Option<Vec<u8>>>;

/// The dictionary changes `operations` make: each component's changes, in the commit's order, resolved together from
/// its value before the commit.
fn resolve_changes(
    mut updater: AppDataDictionaryUpdater<'_>,
    operations: &[(u16, AppDataUpdateOperation)],
    resolve: Resolve<'_>,
) -> anyhow::Result<Option<AppDataUpdates>> {
    let mut by_component: BTreeMap<u16, Vec<Change<'_>>> = BTreeMap::new();
    for (component, operation) in operations {
        by_component
            .entry(*component)
            .or_default()
            .push(match operation {
                AppDataUpdateOperation::Update(update) => Change::Update(update.as_slice()),
                AppDataUpdateOperation::Remove => Change::Remove,
            });
    }
    let mut values = Vec::with_capacity(by_component.len());
    for (component, changes) in &by_component {
        let removal = changes
            .iter()
            .any(|change| matches!(change, Change::Remove));
        anyhow::ensure!(
            !removal || changes.len() == 1,
            "component {component} is both removed and changed in one commit"
        );
        let after = resolve(*component, updater.old_value(*component), changes)?;
        anyhow::ensure!(
            removal == after.is_none(),
            "component {component} resolved to {} after {}",
            if after.is_some() {
                "a value"
            } else {
                "no value"
            },
            if removal { "its removal" } else { "an update" }
        );
        values.push((*component, after));
    }
    for (component, value) in values {
        match value {
            Some(value) => updater.set(ComponentData::from_parts(component, value.into())),
            None => updater.remove(&component),
        }
    }
    Ok(updater.changes())
}

/// What a leaf of a MIMI room advertises: the generation suite only (INV-MLS-002), the app data dictionary, the
/// AppDataUpdate proposal and basic credentials.
pub fn mimi_app_data_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[crate::suite_policy::mls_generation_suite()]),
        Some(&[ExtensionType::AppDataDictionary]),
        Some(&[ProposalType::AppDataUpdate]),
        Some(&[CredentialType::Basic]),
    )
}

/// A new MIMI identity whose KeyPackage advertises [`mimi_app_data_capabilities`], credentialed as `user_id`.
pub fn mimi_generate_identity_app_data(
    user_id: String,
    now_secs: i64,
) -> anyhow::Result<(String, Vec<u8>, Vec<u8>)> {
    let provider = OpenMlsRustCrypto::default();
    let (priv_bytes, pub_bytes) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .map_err(|e| anyhow::anyhow!("Crypto error: {:?}", e))?;
    crate::identity::build_identity_with_capabilities(
        user_id,
        now_secs,
        priv_bytes,
        pub_bytes,
        mimi_app_data_capabilities(),
    )
}

/// A fresh KeyPackage for an identity made by [`mimi_generate_identity_app_data`], once its last one opened a Welcome or
/// nears its lifetime's end: the same credential and signing key, and a leaf that again advertises
/// [`mimi_app_data_capabilities`], so a room that requires them can still add it.
pub fn mimi_regenerate_key_package_app_data(
    bundle_bytes: Vec<u8>,
    now_secs: i64,
) -> anyhow::Result<(String, Vec<u8>, Vec<u8>)> {
    crate::mls::groups::regenerate_key_package_with_capabilities(
        bundle_bytes,
        now_secs,
        Some(mimi_app_data_capabilities()),
    )
}

/// The most `KeyPackage`s one call adds: what a provider's hub takes in one publish.
// LIMIT-REASON: wire-cost: a publish of more is refused by the hub (mimi-hubd MAX_PUBLISH)
pub const MAX_KEY_PACKAGES_ADDED: usize = 32;

/// The most `KeyPackage`s an identity holds at once: what a provider's hub keeps for one user. Past it, the oldest
/// one-time `KeyPackage`s are dropped, as the hub drops them.
// LIMIT-REASON: wire-cost: the hub keeps at most this many per user (mimi-hubd MAX_KEYPACKAGES_PER_USER)
pub const MAX_KEY_PACKAGES_HELD: usize = 64;

/// `count` new one-time `KeyPackage`s for an identity made by [`mimi_generate_identity_app_data`], and a new
/// last-resort one when `last_resort` (draft-ietf-mls-extensions, marked by its app data dictionary component), each
/// advertising [`mimi_app_data_capabilities`]: the bundle that now holds them and their private keys, and the new
/// `KeyPackage`s to publish.
///
/// The `KeyPackage`s the identity already holds stay, since its provider may still hand them out, except those whose
/// lifetime has ended at `now_secs`, the previous last-resort one when a new one is made, and, past
/// [`MAX_KEY_PACKAGES_HELD`], the oldest one-time ones. A dropped `KeyPackage` leaves the bundle's storage, so it can
/// open no Welcome.
pub fn mimi_add_key_packages(
    bundle_bytes: Vec<u8>,
    count: usize,
    last_resort: bool,
    now_secs: i64,
) -> anyhow::Result<(Vec<u8>, Vec<Vec<u8>>)> {
    anyhow::ensure!(
        count + usize::from(last_resort) <= MAX_KEY_PACKAGES_ADDED,
        "at most {MAX_KEY_PACKAGES_ADDED} KeyPackages are added at once"
    );
    anyhow::ensure!(count > 0 || last_resort, "no KeyPackage to add");
    let now = u64::try_from(now_secs)
        .map_err(|_| anyhow::anyhow!("now_secs must be non-negative, got {now_secs}"))?;
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;
    let provider = OpenMlsRustCrypto::default();
    *provider.storage().values.write().unwrap() =
        mem::take(&mut identity.storage_map).into_iter().collect();

    let held: Vec<KeyPackageBundle> = identity
        .key_package_bundle
        .take()
        .into_iter()
        .chain(mem::take(&mut identity.key_package_bundles))
        .collect();
    let drop_held = |kpb: &KeyPackageBundle| -> anyhow::Result<()> {
        let key = crate::mls::groups::kp_storage_key(kpb.key_package(), &provider)?;
        let removed = provider.storage().values.write().unwrap().remove(&key);
        if let Some(mut value) = removed {
            value.zeroize();
        }
        Ok(())
    };
    let mut kept = Vec::with_capacity(held.len());
    for kpb in held {
        let ended = kpb.key_package().life_time().not_after() <= now;
        if ended || (last_resort && kpb.key_package().last_resort()) {
            drop_held(&kpb)?;
        } else {
            kept.push(kpb);
        }
    }

    let signer = MlsSigner {
        key: Zeroizing::new(identity.private_key.clone()),
        scheme: identity.signature_scheme,
    };
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(identity.user_id.clone().into_bytes()).into(),
        signature_key: SignaturePublicKey::try_from(identity.public_key_bytes.clone())
            .map_err(|_| anyhow::anyhow!("Invalid public key bytes in stored bundle"))?,
    };
    let mut added = Vec::with_capacity(count + usize::from(last_resort));
    for marked in std::iter::repeat_n(false, count).chain(last_resort.then_some(true)) {
        let builder = KeyPackage::builder()
            .key_package_extensions(Extensions::empty())
            .key_package_lifetime(crate::mls::make_lifetime(now)?)
            .leaf_node_capabilities(mimi_app_data_capabilities());
        let builder = if marked {
            builder.mark_as_last_resort()
        } else {
            builder
        };
        let kpb = builder.build(
            crate::suite_policy::mls_generation_suite(),
            &provider,
            &signer,
            credential_with_key.clone(),
        )?;
        added.push(kpb.key_package().tls_serialize_detached()?);
        kept.push(kpb);
    }

    // Past the cap, the oldest one-time KeyPackages go first; a last-resort one is never among them.
    while kept.len() > MAX_KEY_PACKAGES_HELD {
        let Some(oldest) = kept.iter().position(|kpb| !kpb.key_package().last_resort()) else {
            break;
        };
        drop_held(&kept.remove(oldest))?;
    }
    identity.key_package_bundles = kept;
    identity.storage_map = provider
        .storage()
        .values
        .read()
        .unwrap()
        .clone()
        .into_iter()
        .collect();
    Ok((crate::mls::zeroizing_json(&identity)?.to_vec(), added))
}

/// A new MIMI room's group, with `components` (id, value) as its app data dictionary. Every member must support the
/// dictionary and AppDataUpdate (the group requires them), and handshake messages are PublicMessage-framed so the room's
/// hub, never a member, can read them (draft-ietf-mimi-protocol §5.3).
pub fn mimi_create_group_app_data(
    group_id: String,
    bundle_bytes: Vec<u8>,
    components: Vec<(u16, Vec<u8>)>,
) -> anyhow::Result<Vec<u8>> {
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;
    let provider = OpenMlsRustCrypto::default();
    let mut dictionary = AppDataDictionary::new();
    for (component, value) in components {
        anyhow::ensure!(
            dictionary.insert(component, value).is_none(),
            "component {component} is given twice"
        );
    }
    let extensions = Extensions::from_vec(vec![
        Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary)),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::AppDataDictionary],
            &[ProposalType::AppDataUpdate],
            &[CredentialType::Basic],
        )),
    ])
    .map_err(|e| anyhow::anyhow!("Invalid group extensions: {:?}", e))?;
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(crate::suite_policy::mls_generation_suite())
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(mimi_app_data_capabilities())
        .with_group_context_extensions(extensions)
        .build();
    let signer = MlsSigner {
        key: Zeroizing::new(mem::take(&mut identity.private_key)),
        scheme: identity.signature_scheme,
    };
    let public_key = SignaturePublicKey::try_from(mem::take(&mut identity.public_key_bytes))
        .map_err(|_| anyhow::anyhow!("Invalid public key bytes"))?;
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(mem::take(&mut identity.user_id).into_bytes()).into(),
        signature_key: public_key,
    };
    let group = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &config,
        GroupId::from_slice(group_id.as_bytes()),
        credential_with_key,
    )
    .map_err(|e| anyhow::anyhow!("Error creating group: {:?}", e))?;
    let state = GroupState {
        group_id: group.group_id().to_vec(),
        storage_map: provider
            .storage()
            .values
            .read()
            .unwrap()
            .clone()
            .into_iter()
            .collect(),
    };
    Ok(crate::mls::zeroizing_json(&state)?.to_vec())
}

/// A commit, staged and not yet installed, that adds the members of `key_packages`, removes the members whose
/// credentials name `removals`, and carries an AppDataUpdate for each `(component, update)` in `updates`, with
/// `authenticated_data` in its framing. Each component's value after it is `resolve`d from its value before, as every
/// receiver will compute it. Install the result only once the room's hub accepted the commit.
pub fn mimi_commit_app_data_pending(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    key_packages: Vec<Vec<u8>>,
    removals: Vec<String>,
    updates: Vec<(u16, Vec<u8>)>,
    resolve: Resolve<'_>,
    authenticated_data: Vec<u8>,
) -> anyhow::Result<PendingCommit> {
    anyhow::ensure!(
        key_packages.len() <= crate::mls::groups::MAX_BULK_MEMBERS,
        "the commit adds more members than one commit may"
    );
    let mut opened = open_group(group_state_bytes, bundle_bytes)?;
    let adds = key_packages
        .iter()
        .map(|key_package| validated_key_package(&opened, key_package))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let leaves = removals
        .iter()
        .map(|identity| member_index(&opened, identity))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let proposals = updates.iter().map(|(component, update)| {
        Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
            *component,
            update.clone(),
        )))
    });
    opened.group.set_aad(authenticated_data);
    let mut stage = opened
        .group
        .commit_builder()
        .add_proposals(proposals)
        .propose_adds(adds)
        .propose_removals(leaves)
        .load_psks(opened.provider.storage())
        .map_err(|e| anyhow::anyhow!("Error loading psks: {:?}", e))?;
    // Every AppDataUpdate the commit covers: those other members proposed (a leave), included by reference, then this
    // commit's own, sorted by component and otherwise in the commit's order, the order receivers resolve them in.
    let operations: Vec<(u16, AppDataUpdateOperation)> = stage
        .app_data_update_proposals()
        .map(|proposal| (proposal.component_id(), proposal.operation().clone()))
        .collect();
    let changes = resolve_changes(stage.app_data_dictionary_updater(), &operations, resolve)?;
    stage.with_app_data_dictionary_updates(changes);
    let (commit, welcome, _group_info) = stage
        .build(
            opened.provider.rand(),
            opened.provider.crypto(),
            &opened.signer,
            |_| true,
        )
        .map_err(|e| anyhow::anyhow!("Error building commit: {:?}", e))?
        .stage_commit(&opened.provider)
        .map_err(|e| anyhow::anyhow!("Error staging commit: {:?}", e))?
        .into_messages();
    staged(
        opened,
        &commit,
        welcome.map(WelcomeForm::WithRatchetTree),
        &[],
    )
}

/// Leave a MIMI room: a Remove of this member's own leaf and an AppDataUpdate for each `(component, update)`, the
/// proposals the room's next commit includes by reference (draft-ietf-mimi-protocol §5.3). The group state with them
/// queued, and the proposals as MLSMessage bytes in the order to send them.
pub fn mimi_leave_app_data(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    updates: Vec<(u16, Vec<u8>)>,
    authenticated_data: Vec<u8>,
) -> anyhow::Result<(Vec<u8>, Vec<Vec<u8>>)> {
    let mut opened = open_group(group_state_bytes, bundle_bytes)?;
    let mut proposals = Vec::with_capacity(updates.len() + 1);
    opened.group.set_aad(authenticated_data.clone());
    let remove = opened
        .group
        .leave_group(&opened.provider, &opened.signer)
        .map_err(|e| anyhow::anyhow!("Error proposing the leave: {:?}", e))?;
    proposals.push(remove.tls_serialize_detached()?);
    for (component, update) in updates {
        opened.group.set_aad(authenticated_data.clone());
        let (proposal, _) = opened
            .group
            .propose_app_data_update(
                &opened.provider,
                &opened.signer,
                component,
                AppDataUpdateOperation::Update(update.into()),
            )
            .map_err(|e| anyhow::anyhow!("Error proposing the app data update: {:?}", e))?;
        proposals.push(proposal.tls_serialize_detached()?);
    }
    let state = GroupState {
        group_id: opened.group.group_id().to_vec(),
        storage_map: opened
            .provider
            .storage()
            .values
            .read()
            .unwrap()
            .clone()
            .into_iter()
            .collect(),
    };
    Ok((crate::mls::zeroizing_json(&state)?.to_vec(), proposals))
}

/// Take another member's proposal to a MIMI room for the room's next commit: the group state holding it. Only the
/// proposals a leave sends are taken: a member's Remove of its own leaf, and its AppDataUpdate that updates a
/// component. Anything else is refused, a Remove of another member and a component's removal included, so a commit
/// that includes the stored proposals carries nothing this member did not vet.
pub fn mimi_process_proposal_app_data(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    proposal_bytes: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    let group_state_bytes = Zeroizing::new(group_state_bytes);
    let _bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut state: GroupState = serde_json::from_slice(&group_state_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid group state: {:?}", e))?;
    let provider = OpenMlsRustCrypto::default();
    *provider.storage().values.write().unwrap() =
        mem::take(&mut state.storage_map).into_iter().collect();
    let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&state.group_id))
        .map_err(|e| anyhow::anyhow!("Error loading group: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Group not found in storage"))?;
    crate::mls::check_wire_size(&proposal_bytes, "mimi_process_proposal_app_data proposal")?;
    let message = ProtocolMessage::try_from(MlsMessageIn::tls_deserialize_exact(
        proposal_bytes.as_slice(),
    )?)
    .map_err(|e| anyhow::anyhow!("Invalid protocol message: {:?}", e))?;
    crate::mls::own_message::refuse_own_sender(&group, &message)?;
    let processed = group
        .process_message(&provider, message)
        .map_err(|e| anyhow::anyhow!("Error processing the proposal: {:?}", e))?;
    let ProcessedMessageContent::ProposalMessage(queued) = processed.into_content() else {
        anyhow::bail!("Expected a proposal");
    };
    let Sender::Member(sender) = *queued.sender() else {
        anyhow::bail!("a room's proposals are taken only from its members");
    };
    match queued.proposal() {
        Proposal::Remove(remove) => anyhow::ensure!(
            remove.removed() == sender,
            "a member's Remove is taken only for its own leaf"
        ),
        Proposal::AppDataUpdate(update) => anyhow::ensure!(
            matches!(update.operation(), AppDataUpdateOperation::Update(_)),
            "a member's AppDataUpdate is taken only when it updates a component"
        ),
        _ => anyhow::bail!("only a member's Remove or AppDataUpdate is taken for the next commit"),
    }
    group
        .store_pending_proposal(provider.storage(), *queued)
        .map_err(|e| anyhow::anyhow!("Error storing the proposal: {:?}", e))?;
    let new_state = GroupState {
        group_id: mem::take(&mut state.group_id),
        storage_map: provider
            .storage()
            .values
            .read()
            .unwrap()
            .clone()
            .into_iter()
            .collect(),
    };
    Ok(crate::mls::zeroizing_json(&new_state)?.to_vec())
}

/// Take another member's commit to a MIMI room: the group state after it, and the member openmls authenticated as its
/// sender. Each AppDataUpdate it carries, an update or a removal, sets its component to what `resolve` computes; a
/// commit whose values differ from that is refused, and so is one `resolve` refuses. On a refusal the given state stays the current one.
pub fn mimi_process_commit_app_data(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    commit_bytes: Vec<u8>,
    resolve: Resolve<'_>,
) -> anyhow::Result<(Vec<u8>, crate::mls::AuthenticatedSender)> {
    let group_state_bytes = Zeroizing::new(group_state_bytes);
    let _bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut state: GroupState = serde_json::from_slice(&group_state_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid group state: {:?}", e))?;
    let provider = OpenMlsRustCrypto::default();
    *provider.storage().values.write().unwrap() =
        mem::take(&mut state.storage_map).into_iter().collect();
    let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&state.group_id))
        .map_err(|e| anyhow::anyhow!("Error loading group: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Group not found in storage"))?;
    crate::mls::check_wire_size(&commit_bytes, "mimi_process_commit_app_data Commit")?;
    let message = ProtocolMessage::try_from(MlsMessageIn::tls_deserialize_exact(
        commit_bytes.as_slice(),
    )?)
    .map_err(|e| anyhow::anyhow!("Invalid protocol message: {:?}", e))?;
    crate::mls::own_message::refuse_own_sender(&group, &message)?;
    let processed = group
        .process_message(&provider, message)
        .map_err(|e| anyhow::Error::new(crate::mls::CommitRefusal::processing(&e)))?;
    crate::mls::own_message::refuse_own_content(&processed)?;
    let sender = crate::mls::authenticated_sender(&group, &processed)?;
    let staged_commit = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => *staged_commit,
        ProcessedMessageContent::UnresolvedAppDataCommit(unresolved) => {
            // Sorted by component and otherwise in the commit's order.
            let operations: Vec<(u16, AppDataUpdateOperation)> = unresolved
                .app_data_update_proposals()
                .map(|proposal| (proposal.component_id(), proposal.operation().clone()))
                .collect();
            let changes =
                resolve_changes(group.app_data_dictionary_updater(), &operations, resolve)?;
            group
                .stage_app_data_commit(&provider, *unresolved, changes)
                .map_err(|e| anyhow::anyhow!("the commit's app data does not apply: {:?}", e))?
        }
        _ => anyhow::bail!("Expected a Commit, got a different message type"),
    };
    group
        .merge_staged_commit(&provider, staged_commit)
        .map_err(|e| anyhow::Error::new(crate::mls::CommitRefusal::merging(&e)))?;
    let new_state = GroupState {
        group_id: mem::take(&mut state.group_id),
        storage_map: provider
            .storage()
            .values
            .read()
            .unwrap()
            .clone()
            .into_iter()
            .collect(),
    };
    Ok((crate::mls::zeroizing_json(&new_state)?.to_vec(), sender))
}

/// A component's value in the group `group_state_bytes` holds, read from its GroupContext; none when absent.
pub fn mimi_app_data_value(
    group_state_bytes: &[u8],
    component: u16,
) -> anyhow::Result<Option<Vec<u8>>> {
    let state: GroupState = serde_json::from_slice(group_state_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid group state: {:?}", e))?;
    let provider = OpenMlsRustCrypto::default();
    *provider.storage().values.write().unwrap() = state.storage_map.iter().cloned().collect();
    let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&state.group_id))
        .map_err(|e| anyhow::anyhow!("Error loading group: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Group not found in storage"))?;
    let value = group
        .extensions()
        .iter()
        .find_map(|extension| match extension {
            Extension::AppDataDictionary(dictionary) => {
                dictionary.dictionary().get(&component).map(<[u8]>::to_vec)
            }
            _ => None,
        });
    Ok(value)
}

#[cfg(test)]
#[path = "app_data_tests.rs"]
mod tests;
