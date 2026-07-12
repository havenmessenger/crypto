//! MIMI cross-provider MLS operations + the AppSync participant-list path. ADDITIVE -
//! INV-MIMI-003: the native Haven↔Haven path (`crate::mls::groups`) is untouched;
//! these produce the SELF-CONTAINED, RFC-9420-conformant Welcome (ratchet tree
//! embedded via `use_ratchet_tree_extension(true)`) that a foreign MIMI/MLS
//! implementation expects.
//!
//! The Dart-exposed entry points a consuming application defines are thin delegators over the
//! functions here. `mimi_appsync_capabilities` and `MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE` are
//! also used by other in-crate callers, including `crate::identity`.
//!
//! The MIMI/MLS wire form and the INV-MLS-002 / INV-CRYPTO-AGILITY-001 inbound
//! accept-gate calls (`suite_policy::gate_inbound_*`) are proven by this crate's own KATs.
//!
//! Lint posture: this module allows several pedantic/style lints with justification rather than
//! fixing them, because fixing some of them would be a logic edit on a KAT-pinned crypto path
//! (see per-lint comments below). `unwrap_used` is allowed module-wide ONLY because every
//! `.unwrap()` is the SAME pattern - acquiring an in-memory `RwLock` guard on a
//! freshly-created single-threaded `OpenMlsRustCrypto` provider's storage, where lock
//! poisoning is unreachable.
#![allow(
    clippy::unwrap_used, // in-memory provider RwLock guards only (see module doc)
    clippy::uninlined_format_args, // format-arg style only, not a correctness concern
    clippy::missing_panics_doc, // no panic-doc convention adopted in this crate
    clippy::needless_pass_by_value, // owned params so zeroize can wipe the caller's buffer on drop
    clippy::doc_markdown, // doc comments cite OpenMLS/KeyPackage/MIMI/etc. type names verbatim
    clippy::unnecessary_fallible_conversions, // try_from kept - it is the error-handling path
    clippy::manual_let_else, // mimi_remove_member_commit closure - idiom-cleanup candidate
    clippy::must_use_candidate, // mimi_appsync_capabilities has no meaningful must-use contract
    clippy::map_unwrap_or // mimi_remove_member_commit_appsync .map().unwrap_or(false)
)]

use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::OpenMlsProvider;
use std::convert::TryFrom;
use std::mem;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use zeroize::Zeroizing;

use crate::mls::{GroupState, IdentityBundle, MlsSigner};

/// The mimiParticipantList `AppSync` custom MLS proposal type (protocol-06 §5.3). MUST stay in lockstep
/// with the equivalent constant in the sibling `mimi-core` crate - duplicated here (NOT a
/// `use`) because this crate compiles to WASM and cannot depend on the native-only `mimi-core` (the WASM
/// wall). This is a Haven-chosen value pending WG/IANA guidance; changing it is a gated wire-format event.
/// `pub`: a separate demo/experimentation consumer's MIMI functions reference it, kept distinct
/// from the production surface. Retained in the shipped crate because
/// `build_identity_from_keypair` (the production path) takes the `appsync_caps` branch.
pub const MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE: u16 = 0xF7A0;

/// Leaf capabilities that advertise the mimiParticipantList AppSync custom proposal, so a commit carrying
/// it validates (openmls requires every member to advertise support). Suite pinned to 0x0001
/// (INV-MLS-002). Used ONLY by the MIMI/demo identity + group paths - never by production identities.
/// `pub`: shared with a separate demo/experimentation consumer; the `appsync_caps=true` branch is
/// reachable only via that demo path.
pub fn mimi_appsync_capabilities() -> Capabilities {
    Capabilities::new(
        None,                                                               // default protocol versions
        Some(&[crate::suite_policy::mls_generation_suite()]), // 0x0001 only (via seam)
        None,                                                 // default extensions
        Some(&[ProposalType::Custom(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE)]), // + AppSync custom proposal
        None,                                                               // default credentials
    )
}

pub fn mimi_generate_identity(
    user_id: String,
    now_secs: i64,
) -> anyhow::Result<(String, Vec<u8>, Vec<u8>)> {
    let provider = OpenMlsRustCrypto::default();
    let (priv_bytes, pub_bytes) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .map_err(|e| anyhow::anyhow!("Crypto error: {:?}", e))?;
    crate::identity::build_identity_from_keypair(user_id, now_secs, priv_bytes, pub_bytes, true)
}

pub fn mimi_create_group(group_id: String, bundle_bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    // Wrap the owned bundle input on entry - the same gap
    // crate::mls::groups::create_group's comment describes, closed the same way here.
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;
    let provider = OpenMlsRustCrypto::default();

    let group_config = MlsGroupCreateConfig::builder()
        // Mimi-lane handshake messages (Commits/Proposals) are PublicMessage-framed on the wire so
        // a spec-conformant hub (which is never a group member) can read them, per
        // draft-ietf-mimi-protocol-06 §7.4. `MIXED_PLAINTEXT`, not `PURE_PLAINTEXT`: this only
        // constrains what WE send; it stays permissive on what we ACCEPT from a federation partner
        // (an open question for the working group is whether receive-side strictness should
        // eventually match). Native lane (`crate::mls::groups::create_group`) is untouched, still
        // `WireFormatPolicy::default()` (PURE_CIPHERTEXT): Haven-to-Haven chat has no hub to read
        // handshake messages for.
        // Explicit generation-suite call, not openmls's default.
        .ciphersuite(crate::suite_policy::mls_generation_suite())
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true) // ← self-contained Welcome (the only delta vs create_group)
        .capabilities(mimi_appsync_capabilities()) // creator advertises the AppSync proposal
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

    let storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };
    let state = GroupState {
        group_id: group.group_id().to_vec(),
        storage_map,
    };
    Ok(crate::mls::zeroizing_json(&state)?.to_vec())
}

/// `mimi_create_group` variant that ALSO populates `GroupContext`'s `ExternalSendersExtension` with
/// exactly one entry - the room's hub credential (protocol-06 §7.4: MIMI-room groups MUST carry
/// `external_senders` naming the hub). `INV-MLS-001b` (`crypto-core::profile::allows_external_proposal
/// (Profile::Haven, Lane::Mimi) == AllowlistedRemoveOnly`) is what a future member's acceptance of a
/// proposal from THIS sender is gated by. See `mimi_accept_external_remove_proposal` below.
///
/// Additive, not a `mimi_create_group` signature change. `mimi_create_group` itself stays
/// UNCHANGED (still no `external_senders`); wiring a caller to supply a real hub credential
/// (which hub is of-record for a given room, sourced from wherever that's tracked) is separate,
/// later work, out of scope here. This function exists so the library has a real, KAT-proven,
/// spec-conformant creation path ready for that wiring.
pub fn mimi_create_group_with_external_senders(
    group_id: String,
    bundle_bytes: Vec<u8>,
    hub_signature_key_bytes: Vec<u8>,
    hub_credential_identity: String,
) -> anyhow::Result<Vec<u8>> {
    // Wrap the owned bundle input on entry (see mimi_create_group's comment).
    // hub_signature_key_bytes is the hub's PUBLIC signature key - not secret.
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;
    let provider = OpenMlsRustCrypto::default();

    let hub_public_key = SignaturePublicKey::try_from(hub_signature_key_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid hub signature key bytes"))?;
    let hub_credential: Credential =
        BasicCredential::new(hub_credential_identity.into_bytes()).into();
    let external_senders: ExternalSendersExtension =
        vec![ExternalSender::new(hub_public_key, hub_credential)];
    let group_context_extensions = Extensions::single(Extension::ExternalSenders(external_senders))
        .map_err(|e| anyhow::anyhow!("Error building external_senders extension: {:?}", e))?;

    let group_config = MlsGroupCreateConfig::builder()
        // Explicit generation-suite call, not openmls's default.
        .ciphersuite(crate::suite_policy::mls_generation_suite())
        // Same MIXED_PLAINTEXT rationale as mimi_create_group (see its own comment above).
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(mimi_appsync_capabilities())
        .with_group_context_extensions(group_context_extensions)
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

    let storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };
    let state = GroupState {
        group_id: group.group_id().to_vec(),
        storage_map,
    };
    Ok(crate::mls::zeroizing_json(&state)?.to_vec())
}

pub fn mimi_add_member(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    key_package_bytes: Vec<u8>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    // Wrap both owned secret-bearing inputs on entry (see
    // crate::mls::groups::add_member's comment). key_package_bytes is a public KeyPackage -
    // not secret.
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

    crate::mls::check_wire_size(&key_package_bytes, "mimi KeyPackage")?;
    let key_package = KeyPackageIn::tls_deserialize_exact(key_package_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Invalid KeyPackage: {:?}", e))?;
    let validated_kp = key_package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| anyhow::anyhow!("KeyPackage validation failed: {:?}", e))?;

    // INV-MLS-002 explicit accept-gate (MIMI foreign-ingest): refuse a foreign-suite KeyPackage.
    crate::suite_policy::gate_inbound_keypackage(&validated_kp)?;

    let (_commit, welcome, _group_info) = group
        .add_members(&provider, &signer, &[validated_kp])
        .map_err(|e| anyhow::anyhow!("Error adding member: {:?}", e))?;
    group
        .merge_pending_commit(&provider)
        .map_err(|e| anyhow::anyhow!("Error merging commit: {:?}", e))?;

    let new_storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };
    let new_state = GroupState {
        group_id: mem::take(&mut state.group_id),
        storage_map: new_storage_map,
    };
    let new_group_state = crate::mls::zeroizing_json(&new_state)?;
    // The welcome is an MlsMessageOut with the tree embedded → conformant, self-contained.
    let welcome_message_bytes = welcome.tls_serialize_detached()?;
    Ok((new_group_state.to_vec(), welcome_message_bytes))
}

pub fn mimi_add_member_commit(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    key_package_bytes: Vec<u8>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Wrap both owned secret-bearing inputs on entry (see mimi_add_member's
    // comment).
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

    crate::mls::check_wire_size(&key_package_bytes, "mimi KeyPackage")?;
    let key_package = KeyPackageIn::tls_deserialize_exact(key_package_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Invalid KeyPackage: {:?}", e))?;
    let validated_kp = key_package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| anyhow::anyhow!("KeyPackage validation failed: {:?}", e))?;

    // INV-MLS-002 explicit accept-gate (MIMI foreign-ingest): refuse a foreign-suite KeyPackage.
    crate::suite_policy::gate_inbound_keypackage(&validated_kp)?;

    let (commit, welcome, _group_info) = group
        .add_members(&provider, &signer, &[validated_kp])
        .map_err(|e| anyhow::anyhow!("Error adding member: {:?}", e))?;
    group
        .merge_pending_commit(&provider)
        .map_err(|e| anyhow::anyhow!("Error merging commit: {:?}", e))?;

    let new_storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };
    let new_state = GroupState {
        group_id: mem::take(&mut state.group_id),
        storage_map: new_storage_map,
    };
    let new_group_state = crate::mls::zeroizing_json(&new_state)?;
    let welcome_message_bytes = welcome.tls_serialize_detached()?;
    let commit_bytes = commit.tls_serialize_detached()?;
    Ok((
        new_group_state.to_vec(),
        welcome_message_bytes,
        commit_bytes,
    ))
}

pub fn mimi_remove_member_commit(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    credential_identity: String,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    // Wrap both owned secret-bearing inputs on entry (see mimi_add_member's
    // comment).
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
    let new_group_state = crate::mls::zeroizing_json(&new_state)?;
    let commit_bytes = commit.tls_serialize_detached()?;
    Ok((new_group_state.to_vec(), commit_bytes))
}

/// The mimi-lane external-proposal acceptance path
/// (`crypto-core::profile::allows_external_proposal(Profile::Haven, Lane::Mimi) ==
/// AllowlistedRemoveOnly`). An existing member receives a pending external proposal, already
/// validated by openmls against the group's `ExternalSendersExtension` (see
/// `mimi_create_group_with_external_senders`), and explicitly commits it ONLY if every one of the
/// three conditions holds: sender is the extension's one allowlisted entry (index 0), the
/// proposal's type is `Remove` (never `Add` or `GroupContextExtensions`), and this function is
/// reached at all (which, per the profile-seam assertion below, only happens for `Profile::Haven`'s
/// mimi lane). `consume_proposal_store(false)` + `add_proposal(...)` is the explicit-inclusion
/// mechanic. It never relies on openmls's default sweep-all-pending-into-commit behavior, so no
/// other pending proposal (member or external) rides along uninvited.
///
/// This is the ONE narrow, reviewable function every acceptance decision lives in, not scattered
/// across call sites. Native-lane groups never populate `ExternalSendersExtension` at all, so
/// `process_message` below fails closed (`NoExternalSendersExtension`) before this function's own
/// checks ever run. The native lane's protection is structural, not dependent on this function
/// being called correctly.
pub fn mimi_accept_external_remove_proposal(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    external_proposal_bytes: Vec<u8>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    // Wrap both owned secret-bearing inputs first, before the fallible guard below, so a
    // guard trip can never drop a bare, unwiped buffer on any exit path - wrapping at entry
    // makes "wiped across every exit path" true by construction, not by the guard's current
    // behavior. external_proposal_bytes is a wire MLS proposal - not secret.
    let group_state_bytes = Zeroizing::new(group_state_bytes);
    let bundle_bytes = Zeroizing::new(bundle_bytes);

    // Belt-and-suspenders tie to the profile seam this acceptance path is designed against: if the
    // seam's answer for Haven's mimi lane ever stops being AllowlistedRemoveOnly, this function's
    // logic needs re-review, not silent continued use.
    anyhow::ensure!(
        crate::profile::allows_external_proposal(
            crate::profile::Profile::Haven,
            crate::profile::Lane::Mimi
        ) == crate::profile::ExternalProposalPolicy::AllowlistedRemoveOnly,
        "mimi_accept_external_remove_proposal called against an unexpected profile/lane policy"
    );

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

    crate::mls::check_wire_size(&external_proposal_bytes, "mimi external proposal")?;
    let message_in = MlsMessageIn::tls_deserialize_exact(external_proposal_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Invalid MlsMessage: {:?}", e))?;
    let protocol_message = ProtocolMessage::try_from(message_in)
        .map_err(|e| anyhow::anyhow!("Invalid protocol message: {:?}", e))?;
    let processed = group
        .process_message(&provider, protocol_message)
        .map_err(|e| anyhow::anyhow!("Error processing external proposal: {:?}", e))?;

    let queued = match processed.into_content() {
        ProcessedMessageContent::ProposalMessage(queued) => *queued,
        // Name the variant by TYPE only - never `Debug`-format the content. For
        // ApplicationMessage specifically, `Debug` on the real variant includes the decrypted
        // byte payload; a caller that logs this error would leak plaintext. A fixed,
        // content-free message per arm closes that for every variant, not just the one that
        // happens to carry secrets today.
        ProcessedMessageContent::ApplicationMessage(_) => {
            return Err(anyhow::anyhow!(
                "Expected a staged proposal, got an ApplicationMessage"
            ))
        }
        ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
            return Err(anyhow::anyhow!(
                "Expected a staged proposal, got an ExternalJoinProposalMessage"
            ))
        }
        ProcessedMessageContent::StagedCommitMessage(_) => {
            return Err(anyhow::anyhow!(
                "Expected a staged proposal, got a StagedCommitMessage"
            ))
        }
    };

    // INV-MLS-001b clause 2(b): sender must be the group's ONE pre-configured external sender.
    // openmls already refused any other signer during process_message above (validation.rs); this
    // re-asserts it explicitly rather than trusting that silently, per watch-out (b).
    anyhow::ensure!(
        *queued.sender() == Sender::External(SenderExtensionIndex::new(0)),
        "external proposal sender is not the allowlisted hub (extension index 0)"
    );

    // INV-MLS-001b clause 2(c): allowlist, not denylist. ONLY Remove. Add and
    // GroupContextExtensions (the other two constructors openmls exposes for external senders, see
    // spec_capability_proof.rs) are refused here BY THIS FUNCTION even though openmls itself would
    // have validated and staged them just as readily. The acting policy is entirely ours.
    anyhow::ensure!(
        matches!(queued.proposal(), Proposal::Remove(_)),
        "external proposal type is not allowlisted (Remove-only)"
    );

    // Explicit-inclusion-only: consume_proposal_store(false) turns OFF openmls's default
    // sweep-all-pending-into-next-commit behavior, which would otherwise auto-commit any OTHER
    // proposal sitting in the pending store alongside this one - unvalidated by the checks above.
    // Only this ONE validated, type-checked, sender-checked proposal is added to the commit.
    let (commit, _welcome, _group_info) = group
        .commit_builder()
        .consume_proposal_store(false)
        .add_proposal(queued.proposal().clone())
        .load_psks(provider.storage())
        .map_err(|e| anyhow::anyhow!("Error loading psks: {:?}", e))?
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .map_err(|e| anyhow::anyhow!("Error building commit: {:?}", e))?
        .stage_commit(&provider)
        .map_err(|e| anyhow::anyhow!("Error staging commit: {:?}", e))?
        .into_messages();
    group
        .merge_pending_commit(&provider)
        .map_err(|e| anyhow::anyhow!("Error merging commit: {:?}", e))?;

    let new_storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };
    let new_state = GroupState {
        group_id: mem::take(&mut state.group_id),
        storage_map: new_storage_map,
    };
    let new_group_state = crate::mls::zeroizing_json(&new_state)?;
    let commit_bytes = commit.tls_serialize_detached()?;
    Ok((new_group_state.to_vec(), commit_bytes))
}

pub fn mimi_add_member_commit_appsync(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    key_package_bytes: Vec<u8>,
    roster_payload: Vec<u8>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Wrap both owned secret-bearing inputs on entry (see mimi_add_member's
    // comment). roster_payload is the AppSync custom-proposal payload - not secret.
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

    crate::mls::check_wire_size(&key_package_bytes, "mimi KeyPackage")?;
    let key_package = KeyPackageIn::tls_deserialize_exact(key_package_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Invalid KeyPackage: {:?}", e))?;
    let validated_kp = key_package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| anyhow::anyhow!("KeyPackage validation failed: {:?}", e))?;

    // INV-MLS-002 explicit accept-gate (MIMI foreign-ingest): refuse a foreign-suite KeyPackage.
    crate::suite_policy::gate_inbound_keypackage(&validated_kp)?;

    // Stage the roster custom proposal (by value, into the pending store), then build ONE commit that
    // ALSO inlines the Add by value (commit builder `propose_adds`) - both BY VALUE so the receiver can
    // process the commit without needing the proposals separately (atomicity: one commit, not two).
    let custom = CustomProposal::new(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, roster_payload);
    group
        .propose_custom_proposal_by_value(&provider, &signer, custom)
        .map_err(|e| anyhow::anyhow!("Error proposing roster: {:?}", e))?;
    let (commit, welcome, _gi) = group
        .commit_builder()
        .consume_proposal_store(true) // include the pending roster custom proposal
        .propose_adds([validated_kp]) // + the Add, inlined by value
        .load_psks(provider.storage())
        .map_err(|e| anyhow::anyhow!("Error loading psks: {:?}", e))?
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .map_err(|e| anyhow::anyhow!("Error building commit: {:?}", e))?
        .stage_commit(&provider)
        .map_err(|e| anyhow::anyhow!("Error staging commit: {:?}", e))?
        .into_messages();
    let welcome = welcome.ok_or_else(|| anyhow::anyhow!("Add commit produced no Welcome"))?;
    group
        .merge_pending_commit(&provider)
        .map_err(|e| anyhow::anyhow!("Error merging commit: {:?}", e))?;

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
    let commit_bytes = commit.tls_serialize_detached()?;
    Ok((new_group_state.to_vec(), welcome_bytes, commit_bytes))
}

pub fn mimi_remove_member_commit_appsync(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    credential_identity: String,
    roster_payload: Vec<u8>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    // Wrap both owned secret-bearing inputs on entry (see
    // mimi_add_member_commit_appsync's comment).
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

    let target_index = group
        .members()
        .find(|m| {
            BasicCredential::try_from(m.credential.clone())
                .map(|b| b.identity() == credential_identity.as_bytes())
                .unwrap_or(false)
        })
        .map(|m| m.index)
        .ok_or_else(|| anyhow::anyhow!("Member '{}' not found", credential_identity))?;

    // Stage the roster custom proposal, then build ONE commit inlining the Remove by value
    // (atomicity: one commit, not two).
    let custom = CustomProposal::new(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, roster_payload);
    group
        .propose_custom_proposal_by_value(&provider, &signer, custom)
        .map_err(|e| anyhow::anyhow!("Error proposing roster: {:?}", e))?;
    let (commit, _welcome, _gi) = group
        .commit_builder()
        .consume_proposal_store(true) // include the pending roster custom proposal
        .propose_removals([target_index]) // + the Remove, inlined by value
        .load_psks(provider.storage())
        .map_err(|e| anyhow::anyhow!("Error loading psks: {:?}", e))?
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .map_err(|e| anyhow::anyhow!("Error building commit: {:?}", e))?
        .stage_commit(&provider)
        .map_err(|e| anyhow::anyhow!("Error staging commit: {:?}", e))?
        .into_messages();
    group
        .merge_pending_commit(&provider)
        .map_err(|e| anyhow::anyhow!("Error merging commit: {:?}", e))?;

    let new_storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };
    let new_state = GroupState {
        group_id: mem::take(&mut state.group_id),
        storage_map: new_storage_map,
    };
    let new_group_state = crate::mls::zeroizing_json(&new_state)?;
    let commit_bytes = commit.tls_serialize_detached()?;
    Ok((new_group_state.to_vec(), commit_bytes))
}

pub fn mls_process_commit_appsync(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    commit_bytes: Vec<u8>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    // Wrap on entry (see crate::mls::groups::mls_process_commit's comment on the
    // unused-but-still-owned bundle_bytes pattern).
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

    crate::mls::check_wire_size(&commit_bytes, "mls_process_commit_appsync Commit")?;
    let message_in = MlsMessageIn::tls_deserialize_exact(commit_bytes.as_slice())?;
    let message = ProtocolMessage::try_from(message_in)
        .map_err(|e| anyhow::anyhow!("Invalid protocol message: {:?}", e))?;
    let processed = group
        .process_message(&provider, message)
        .map_err(|e| anyhow::anyhow!("Processing error: {:?}", e))?;
    let mut roster_payload: Vec<u8> = Vec::new();
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            // Surface the mimiParticipantList custom proposal payload (if present) BEFORE merging.
            for qp in staged.queued_proposals() {
                if let Proposal::Custom(c) = qp.proposal() {
                    if c.proposal_type() == MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE {
                        roster_payload = c.payload().to_vec();
                        break;
                    }
                }
            }
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
    Ok((
        crate::mls::zeroizing_json(&new_state)?.to_vec(),
        roster_payload,
    ))
}

/// Hub-identity pinning on join: `mimi_accept_external_remove_proposal` only ever checks
/// `Sender::External(index 0)` - a POSITION in the group's `ExternalSendersExtension`, not an
/// IDENTITY. Without this check, a member could join a valid group whose inviter placed an
/// unintended credential in that slot, and later acceptance would treat proposals from it as the
/// allowlisted hub. `expected_hub_signature_key_bytes`/`expected_hub_credential_identity`, when
/// non-empty, let the caller pin the hub it actually configured for this room: the joined group's
/// `ExternalSendersExtension` must be exactly the single entry matching what's expected, or the
/// join fails closed (`Err` - the caller never receives a group state pinned to the wrong hub).
/// Pass empty strings/bytes to skip the check for a group with no hub at all (the current
/// `mimi_create_group` production path never populates `external_senders`) - this preserves prior
/// behavior for the hub-less case while closing the gap for the hub-mediated one.
pub fn mimi_process_welcome(
    mls_welcome_message_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    expected_hub_signature_key_bytes: Vec<u8>,
    expected_hub_credential_identity: String,
) -> anyhow::Result<Vec<u8>> {
    // Wrap the owned bundle input on entry (see crate::mls::groups::
    // process_welcome's comment). mls_welcome_message_bytes is an MLS Welcome (HPKE-sealed
    // wire form) and expected_hub_signature_key_bytes is the hub's PUBLIC key - neither is
    // the plaintext key bundle.
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;
    let provider = OpenMlsRustCrypto::default();
    {
        let mut values = provider.storage().values.write().unwrap();
        *values = mem::take(&mut identity.storage_map).into_iter().collect();
    }

    crate::mls::check_wire_size(&mls_welcome_message_bytes, "mimi_process_welcome Welcome")?;
    let mls_message = MlsMessageIn::tls_deserialize_exact(mls_welcome_message_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Invalid MlsMessage: {:?}", e))?;
    let welcome = match mls_message.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => return Err(anyhow::anyhow!("Message is not a Welcome")),
    };

    // INV-MLS-002 explicit accept-gate (MIMI foreign-ingest): refuse a foreign-suite Welcome before
    // StagedWelcome - a MIMI provider takes objects whose suite the REMOTE chooses, so this gate is
    // mandatory here (the native emergent protections do not apply).
    crate::suite_policy::gate_inbound_welcome(&welcome)?;

    let mls_group_config = MlsGroupJoinConfig::builder()
        // Same MIXED_PLAINTEXT rationale as mimi_create_group above: a member who JOINS a mimi-lane
        // group must keep sending hub-readable (PublicMessage) handshake messages too, not just the
        // creator. Otherwise the group's hub-readability guarantee holds only until the first
        // non-creator member commits.
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    // None: the ratchet tree is embedded in the Welcome (use_ratchet_tree_extension).
    let staged_join = StagedWelcome::new_from_welcome(&provider, &mls_group_config, welcome, None)
        .map_err(|e| anyhow::anyhow!("Error processing Welcome: {:?}", e))?;
    let group = staged_join
        .into_group(&provider)
        .map_err(|e| anyhow::anyhow!("Error joining group: {:?}", e))?;

    // Pin the configured hub credential - only when the caller actually expects one (a
    // hub-less group skips this, preserving prior behavior). `ExternalSender`'s fields are
    // pub(crate) in openmls, so this compares TLS-SERIALIZED bytes rather than reaching into
    // private accessors - byte-identical serialization IS structural equality for this type, and
    // it's built the exact same way `mimi_create_group_with_external_senders` builds the real one.
    if !expected_hub_signature_key_bytes.is_empty() {
        let expected_pub = SignaturePublicKey::try_from(expected_hub_signature_key_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid expected hub signature key bytes"))?;
        let expected_credential: Credential =
            BasicCredential::new(expected_hub_credential_identity.into_bytes()).into();
        let expected_entry = ExternalSender::new(expected_pub, expected_credential);
        let expected_bytes = expected_entry
            .tls_serialize_detached()
            .map_err(|e| anyhow::anyhow!("Failed to serialize expected hub entry: {e:?}"))?;

        let actual_matches = match group.extensions().external_senders() {
            Some(list) if list.len() == 1 => {
                let actual_bytes = list[0]
                    .tls_serialize_detached()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize actual hub entry: {e:?}"))?;
                actual_bytes == expected_bytes
            }
            _ => false,
        };
        anyhow::ensure!(
            actual_matches,
            "mimi_process_welcome: joined group's external_senders does not match the expected \
             hub credential (hub-identity pin failed)"
        );
    }

    let storage_map = {
        let values = provider.storage().values.read().unwrap();
        values.clone().into_iter().collect()
    };
    let state = GroupState {
        group_id: group.group_id().to_vec(),
        storage_map,
    };
    Ok(crate::mls::zeroizing_json(&state)?.to_vec())
}

#[cfg(test)]
mod tests;
