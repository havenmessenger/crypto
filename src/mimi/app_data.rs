//! MIMI rooms whose state lives in the GroupContext's app data dictionary (draft-ietf-mls-extensions §4.6, §4.7), such
//! as the participant list (draft-ietf-mimi-room-policy), and changes by AppDataUpdate proposals.
//!
//! What a component's value means is the caller's. A commit carries each change as an update payload; every member,
//! the committer included, computes the component's value after it with the same [`Resolve`] function the caller
//! gives, so all of them arrive at the same dictionary. A member whose computation differs gets a different GroupContext,
//! and openmls refuses the commit on its confirmation tag.

use std::collections::BTreeSet;
use std::mem;

use openmls::component::ComponentData;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::Deserialize as _;
use zeroize::Zeroizing;

use super::{member_index, validated_key_package};
use crate::mls::pending::{open_group, staged, PendingCommit, WelcomeForm};
use crate::mls::{GroupState, IdentityBundle, MlsSigner};

/// The value a component takes after an update: given the component, its value before (none when absent) and the
/// update's payload. An error refuses the commit.
pub type Resolve<'a> = &'a dyn Fn(u16, Option<&[u8]>, &[u8]) -> anyhow::Result<Vec<u8>>;

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
    let components: BTreeSet<u16> = updates.iter().map(|(component, _)| *component).collect();
    anyhow::ensure!(
        components.len() == updates.len(),
        "a component is updated twice in one commit"
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
    let mut values = stage.app_data_dictionary_updater();
    for (component, update) in &updates {
        let value = resolve(*component, values.old_value(*component), update)?;
        values.set(ComponentData::from_parts(*component, value.into()));
    }
    let changes = values.changes();
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

/// Take another member's commit to a MIMI room: the group state after it, and the member openmls authenticated as its
/// sender. Each AppDataUpdate it carries sets its component to the value `resolve` computes; a commit whose values
/// differ from that is refused, and so is one `resolve` refuses. On a refusal the given state stays the current one.
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
            let mut updater = group.app_data_dictionary_updater();
            for proposal in unresolved.app_data_update_proposals() {
                let component = proposal.component_id();
                match proposal.operation() {
                    AppDataUpdateOperation::Remove => updater.remove(&component),
                    AppDataUpdateOperation::Update(update) => {
                        let value =
                            resolve(component, updater.old_value(component), update.as_slice())?;
                        updater.set(ComponentData::from_parts(component, value.into()));
                    }
                }
            }
            let changes = updater.changes();
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
