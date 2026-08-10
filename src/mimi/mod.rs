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
//! poisoning is unreachable. The one exception is the post-spend read in `complete_welcome`:
//! it runs after a `catch_unwind` that could have poisoned the guard mid-write, so that read
//! alone is poison-tolerant (`PoisonError::into_inner`) rather than `.unwrap()`.
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
use std::collections::HashSet;
use std::convert::TryFrom;
use std::mem;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use zeroize::{Zeroize, Zeroizing};

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
) -> anyhow::Result<(Vec<u8>, Vec<u8>, crate::mls::AuthenticatedSender)> {
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
    // Read the committer openmls authenticated from the PRE-merge tree, before into_content()
    // consumes the processed message. On the MIMI lane this is the sender an Add's authorization is
    // decided against, so it is the verified leaf key rather than any identity the payload claims.
    let sender = crate::mls::authenticated_sender(&group, &processed)?;
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
        sender,
    ))
}

/// Why an AppSync Welcome did not yield a joined group, framed by the single-use status of the
/// KeyPackage - the one fact the caller must act on.
///
/// `StagedWelcome::new_from_welcome` SPENDS the KeyPackage (OpenMLS deletes it from provider storage)
/// as it opens the Welcome, before it finishes decrypting or validating it and even if the caller never
/// completes the join. So "the join did not complete" splits into two cases the caller must treat
/// oppositely:
///
///  - `Unspent`: the failure happened before the KeyPackage was spent - it is still live and usable,
///    and there is nothing to retire.
///  - `Spent`: the KeyPackage was consumed. Whatever the reason the join did not finish - a hub-pin
///    rejection, or a post-spend failure while opening or joining - the caller MUST persist
///    `retired_bundle` in place of its input bundle, or the spent KeyPackage stays live and opens a
///    second Welcome. One "you must persist this" variant, so a caller cannot honor one spent case and
///    miss another.
#[derive(thiserror::Error)]
pub enum MimiWelcomeError {
    /// The KeyPackage was NOT consumed - still live and usable; nothing to retire.
    #[error("the Welcome could not be processed: {0}")]
    Unspent(#[from] anyhow::Error),
    /// The KeyPackage WAS consumed but the join did not complete (a policy rejection or a post-spend
    /// failure). The caller MUST persist `retired_bundle` to preserve single-use, then discard the join.
    #[error("the Welcome spent the KeyPackage but the join did not complete: {reason}")]
    Spent {
        retired_bundle: Vec<u8>,
        reason: String,
    },
}

// Manual so a `.expect()` panic never dumps the private key material `retired_bundle` carries; it is
// reported by length only, as `PublishedKeyPackage`'s Debug is.
impl std::fmt::Debug for MimiWelcomeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspent(e) => f.debug_tuple("Unspent").field(e).finish(),
            Self::Spent {
                retired_bundle,
                reason,
            } => f
                .debug_struct("Spent")
                .field("retired_bundle_len", &retired_bundle.len())
                .field("reason", reason)
                .finish(),
        }
    }
}

/// A Welcome whose fail-closed retirement has been built WITHOUT spending the KeyPackage.
///
/// This is phase 1 of the crash-atomic single-use join (RFC 9420 §16.8): the fields carry the material
/// [`complete_welcome`] needs to open the Welcome, plus [`PreparedWelcome::retired_bundle`] - the
/// fail-closed retirement the caller MUST persist durably (in place of its input bundle) BEFORE calling
/// [`complete_welcome`]. Persisting it first is what makes single-use crash-atomic: the KeyPackage's
/// private init key is never used to open a Welcome until the durable state already reflects its
/// retirement, so a crash/OOM/abort during the open cannot leave the KeyPackage both durably-live and
/// replayable. See [`prepare_welcome_retirement`] / [`complete_welcome`].
///
/// The ephemeral material (`identity`, `original_storage`, `welcome`) is secret-bearing and is wiped on
/// drop; it is never durable and must not be persisted - only `retired_bundle` is.
#[must_use = "the caller MUST persist retired_bundle() durably before calling complete_welcome"]
pub struct PreparedWelcome {
    // The fail-closed retirement the caller persists BEFORE complete_welcome (see accessor). Wiped on
    // drop; the caller's persisted copy is the durable one.
    retired_bundle: Vec<u8>,
    // Ephemeral phase-2 material. `identity` self-wipes (its Drop); `original_storage` is wiped by this
    // struct's Drop; `welcome`/`expected_hub_entry` are public wire bytes. `Option` so complete_welcome
    // can move them out of a Drop type via `.take()` (Rust forbids moving fields out of a Drop type).
    identity: Option<IdentityBundle>,
    original_storage: Vec<(Vec<u8>, Vec<u8>)>,
    welcome: Option<Welcome>,
    expected_hub_entry: Option<Vec<u8>>,
}

impl PreparedWelcome {
    /// The fail-closed retirement to persist durably (in place of the input bundle) BEFORE calling
    /// [`complete_welcome`]. This is the single load-bearing output of phase 1: persisting it is what
    /// closes the crash-atomicity window.
    #[must_use]
    pub fn retired_bundle(&self) -> &[u8] {
        &self.retired_bundle
    }
}

impl Drop for PreparedWelcome {
    fn drop(&mut self) {
        self.retired_bundle.zeroize();
        for (_, v) in &mut self.original_storage {
            v.zeroize();
        }
        // identity (Option<IdentityBundle>) self-wipes via IdentityBundle::drop if still Some;
        // welcome and expected_hub_entry are HPKE-sealed / PUBLIC wire bytes, not secret material.
    }
}

// Manual Debug so a stray `{:?}` never dumps the secret ephemeral material or the retirement (which
// carries the surviving identity signing key), matching MimiWelcomeError's redaction.
impl std::fmt::Debug for PreparedWelcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedWelcome")
            .field("retired_bundle_len", &self.retired_bundle.len())
            .field("completed", &self.identity.is_none())
            .finish_non_exhaustive()
    }
}

/// A joined-group provider-storage snapshot whose secret values are zeroized on drop.
///
/// The snapshot holds joined-group epoch/message/ratchet secrets copied out of provider storage after
/// the spend. On an early return (hub-pin rejection, serialization failure, a caught partial-join
/// panic) no `GroupState` is ever constructed to own and wipe it, so without this wrapper the raw
/// `Vec` would free unwiped, leaving ratchet material in allocator memory. On the success path the
/// values move out via `mem::take` into `GroupState` (whose own `Drop` then owns the wipe), and this
/// wrapper drops an empty `Vec`.
struct PostJoinStorage(Vec<(Vec<u8>, Vec<u8>)>);

impl Drop for PostJoinStorage {
    fn drop(&mut self) {
        for (_, v) in &mut self.0 {
            v.zeroize();
        }
    }
}

/// The provider storage keys a Welcome's `EncryptedGroupSecrets` reference - the KeyPackage entries
/// OpenMLS looks up to open it. Same layout as `crate::mls::groups::kp_storage_key` (the `KeyPackage`
/// label, the serialized authenticated hash reference, the storage version). Uses only PUBLIC hash
/// references from the Welcome - never a private init key - so identifying the target does not consume
/// it. Coupled to `openmls_memory_storage`'s key layout, the same coupling the storage-key regression
/// test (`field_clear_gate_matches_openmls_storage_key`) pins.
fn welcome_target_storage_keys(welcome: &Welcome) -> anyhow::Result<Vec<Vec<u8>>> {
    welcome
        .secrets()
        .iter()
        .map(|egs| {
            let mut key = b"KeyPackage".to_vec();
            key.extend_from_slice(&serde_json::to_vec(&egs.new_member())?);
            key.extend_from_slice(&openmls_traits::storage::CURRENT_VERSION.to_be_bytes());
            Ok(key)
        })
        .collect()
}

/// Build a fail-closed retirement for the KeyPackages publicly referenced by a Welcome.
///
/// The candidate set is sufficient before opening the Welcome: every non-last-resort KeyPackage
/// OpenMLS can spend is named by one of these storage keys. If this calculation fails, callers must
/// use the broader conservative retirement instead.
fn candidate_retirement(
    identity: &IdentityBundle,
    original_storage: &[(Vec<u8>, Vec<u8>)],
    candidates: &HashSet<Vec<u8>>,
    provider: &impl OpenMlsProvider,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if candidates.is_empty() {
        anyhow::bail!("Welcome did not identify a KeyPackage candidate");
    }

    let field_is_candidate = identity
        .key_package_bundle
        .as_ref()
        .map(|kpb| crate::mls::groups::kp_storage_key(kpb.key_package(), provider))
        .transpose()?
        .is_some_and(|key| candidates.contains(&key));
    let kept = original_storage
        .iter()
        .filter(|(key, _)| !candidates.contains(key))
        .cloned()
        .collect();
    let retired = IdentityBundle {
        key_package_bundle: (!field_is_candidate)
            .then(|| identity.key_package_bundle.clone())
            .flatten(),
        private_key: identity.private_key.clone(),
        signature_scheme: identity.signature_scheme,
        public_key_bytes: identity.public_key_bytes.clone(),
        user_id: identity.user_id.clone(),
        storage_map: kept,
    };
    crate::mls::zeroizing_json(&retired)
}

/// PHASE 1 of the crash-atomic AppSync Welcome join: build the fail-closed retirement WITHOUT spending
/// the KeyPackage.
///
/// Runs every pre-spend check ([`MimiWelcomeError::Unspent`] on failure - the KeyPackage is still live
/// and there is nothing to retire): parse the bundle, reject aliased KeyPackage entries, wire-size and
/// deserialize the Welcome, gate the ciphersuite (INV-MLS-002 foreign-ingest), confirm the Welcome
/// actually targets a KeyPackage this bundle holds, and build the expected hub entry. It does NOT run
/// OpenMLS and does NOT open the Welcome, so the KeyPackage's private init key is never used here.
///
/// On success it returns a [`PreparedWelcome`] whose [`PreparedWelcome::retired_bundle`] the caller MUST
/// persist durably (in place of its input bundle) BEFORE calling [`complete_welcome`]. That persist is
/// the single-use transaction boundary: because it lands before the KeyPackage is ever used to open a
/// Welcome, a crash/OOM/abort during [`complete_welcome`] cannot leave the KeyPackage both durably-live
/// and replayable (on restart the durable bundle already reflects the retirement). This closes the
/// crash-atomicity gap that `catch_unwind` alone cannot close.
///
/// The retirement removes the public-reference KeyPackage candidates from the bundle. If those
/// candidates cannot be determined, it falls back to the fail-closed `conservative_retirement`, which
/// retires every KeyPackage rather than risking a spent KeyPackage remaining live. [`complete_welcome`]
/// refines it to the precise retirement on a successful join (restoring KeyPackages not actually
/// consumed, including a last-resort package).
///
/// Hub-identity pinning: `expected_hub_signature_key_bytes`/`expected_hub_credential_identity`, when
/// non-empty, pin the hub the caller configured for this room (checked in [`complete_welcome`] against
/// the joined group's single `ExternalSendersExtension` entry). Empty = a hub-less group (the current
/// `mimi_create_group` production path), pinning nothing.
pub fn prepare_welcome_retirement(
    mls_welcome_message_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    expected_hub_signature_key_bytes: Vec<u8>,
    expected_hub_credential_identity: String,
) -> Result<PreparedWelcome, MimiWelcomeError> {
    // Wrap the owned bundle input on entry (see crate::mls::groups::process_welcome's comment).
    // mls_welcome_message_bytes is an MLS Welcome (HPKE-sealed wire form) and
    // expected_hub_signature_key_bytes is the hub's PUBLIC key - neither is the plaintext key bundle.
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;
    // A provider is needed ONLY for reject_aliased_kp_entries' KeyPackage-hash check; no storage is
    // loaded into it and no join runs here, so nothing is spent in phase 1.
    let provider = OpenMlsRustCrypto::default();
    // Snapshot the caller's KeyPackage storage and reject aliased entries: an alias K_A ->
    // serialized_bundle(B) beside the genuine K_B -> B would let a spent KeyPackage replay a later
    // Welcome. Carried into complete_welcome to seed the ephemeral provider and diff the retirement.
    let original_storage = crate::mls::groups::reject_aliased_kp_entries(
        mem::take(&mut identity.storage_map),
        &provider,
    );

    crate::mls::check_wire_size(
        &mls_welcome_message_bytes,
        "prepare_welcome_retirement Welcome",
    )?;
    let mls_message = MlsMessageIn::tls_deserialize_exact(mls_welcome_message_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Invalid MlsMessage: {:?}", e))?;
    let welcome = match mls_message.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => return Err(anyhow::anyhow!("Message is not a Welcome").into()),
    };

    // INV-MLS-002 explicit accept-gate (MIMI foreign-ingest): refuse a foreign-suite Welcome before it
    // is ever opened - a MIMI provider takes objects whose suite the REMOTE chooses, so this gate is
    // mandatory here (the native emergent protections do not apply).
    crate::suite_policy::gate_inbound_welcome(&welcome)?;

    // Does this Welcome target a KeyPackage the caller actually holds? If not, there is nothing to
    // spend and nothing to retire (Unspent) - a non-targeting or hostile Welcome MUST NOT be able to
    // force-retire the caller's KeyPackages. The lookup uses only PUBLIC storage-key hashing, never a
    // private init key, so identifying the target does not itself consume it.
    let target_keys = welcome_target_storage_keys(&welcome)?;
    let candidates: HashSet<Vec<u8>> = target_keys
        .into_iter()
        .filter(|target| original_storage.iter().any(|(key, _)| key == target))
        .collect();
    if candidates.is_empty() {
        return Err(anyhow::anyhow!(
            "the Welcome does not target any KeyPackage this bundle holds"
        )
        .into());
    }

    // Build the expected hub entry BEFORE returning, so a malformed expectation fails while the
    // KeyPackage is still unspent (Unspent, nothing to retire). An empty expected key is a hub-less
    // group and pins nothing. `ExternalSender`'s fields are pub(crate) in openmls, so the pin compares
    // TLS-serialized bytes - byte-identical serialization IS structural equality for this type, built
    // the exact way `mimi_create_group_with_external_senders` builds the real one.
    let expected_hub_entry: Option<Vec<u8>> = if expected_hub_signature_key_bytes.is_empty() {
        None
    } else {
        let expected_pub = SignaturePublicKey::try_from(expected_hub_signature_key_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid expected hub signature key bytes"))?;
        let expected_credential: Credential =
            BasicCredential::new(expected_hub_credential_identity.into_bytes()).into();
        let expected_entry = ExternalSender::new(expected_pub, expected_credential);
        Some(
            expected_entry
                .tls_serialize_detached()
                .map_err(|e| anyhow::anyhow!("Failed to serialize expected hub entry: {e:?}"))?,
        )
    };

    // Built with NO join and NO spend. If a candidate-specific retirement cannot be made, retain the
    // broader fail-closed fallback rather than leaving a potentially spent KeyPackage live.
    let conservative = candidate_retirement(&identity, &original_storage, &candidates, &provider)
        .or_else(|_| {
        crate::mls::groups::conservative_retirement(&identity, &original_storage)
    })?;

    Ok(PreparedWelcome {
        retired_bundle: conservative.to_vec(),
        identity: Some(identity),
        original_storage,
        welcome: Some(welcome),
        expected_hub_entry,
    })
}

/// PHASE 2 of the crash-atomic AppSync Welcome join: open the Welcome on an EPHEMERAL copy of the
/// KeyPackage material and return the joined group.
///
/// MUST be called only after the caller has durably persisted [`PreparedWelcome::retired_bundle`] from
/// phase 1. Returns `(new_group_state, updated_bundle)` - the same shape as
/// [`crate::mls::groups::process_welcome`] - where `updated_bundle` is the PRECISE retirement (RFC 9420
/// §16.8): it retires exactly the consumed KeyPackage and keeps a last-resort package or any KeyPackage
/// the join did not consume, refining the over-retiring conservative bundle the caller already persisted.
/// The caller SHOULD persist `updated_bundle` in place of the conservative one.
///
/// The spend runs against a fresh provider seeded from a COPY of the phase-1 material; nothing here
/// mutates anything the caller durably owns. So a crash/OOM/abort in the open - the window `catch_unwind`
/// cannot cover, since a retirement built only after the spend would be lost - cannot
/// leave the KeyPackage durably-live and replayable: the caller's durable state already reflects the
/// phase-1 retirement. `catch_unwind` is retained as defense-in-depth (a debug confirmation-tag
/// `debug_assert!` panic must not unwind past the crypto boundary) but is no longer the transaction
/// boundary.
///
/// Because the retirement is already durable, every outcome here keeps it: a join that does not
/// complete - a hub-pin rejection or any post-open error - is a [`MimiWelcomeError::Spent`] carrying
/// the best retirement obtainable (precise when it can be built, else the conservative the caller
/// already holds); there is no `Unspent` outcome in phase 2.
#[allow(clippy::too_many_lines)]
pub fn complete_welcome(
    mut prepared: PreparedWelcome,
) -> Result<(Vec<u8>, Vec<u8>), MimiWelcomeError> {
    // Move the ephemeral material out of the Drop type via `.take()`/`mem::take` (Rust forbids moving
    // fields out of a Drop type). The husk left behind holds only empty/None, so its Drop wipes nothing.
    // Take this first so even defensive-invalid phase-2 states preserve the already-durable
    // retirement rather than returning Unspent.
    let conservative = Zeroizing::new(mem::take(&mut prepared.retired_bundle));
    let identity = match prepared.identity.take() {
        Some(identity) => identity,
        None => {
            return Err(MimiWelcomeError::Spent {
                retired_bundle: conservative.to_vec(),
                reason: "PreparedWelcome has already been completed".to_string(),
            });
        }
    };
    let welcome = match prepared.welcome.take() {
        Some(welcome) => welcome,
        None => {
            return Err(MimiWelcomeError::Spent {
                retired_bundle: conservative.to_vec(),
                reason: "PreparedWelcome has already been completed".to_string(),
            });
        }
    };
    let original_storage = mem::take(&mut prepared.original_storage);
    let expected_hub_entry = prepared.expected_hub_entry.take();
    // The conservative retirement the caller already persisted; the fail-closed fallback if the precise
    // retirement cannot be built. Zeroizing so this in-process copy wipes on return.

    // EPHEMERAL provider, seeded from a COPY of the caller's material. The caller's durable store
    // already reflects the phase-1 retirement and is never touched here, so the spend below is
    // crash-atomic by construction.
    let provider = OpenMlsRustCrypto::default();
    {
        let mut values = provider.storage().values.write().unwrap();
        *values = original_storage.iter().cloned().collect();
    }

    let mls_group_config = MlsGroupJoinConfig::builder()
        // Same MIXED_PLAINTEXT rationale as mimi_create_group: a member who JOINS a mimi-lane group
        // must keep sending hub-readable (PublicMessage) handshake messages too, or the group's
        // hub-readability guarantee holds only until the first non-creator member commits.
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();

    // THE SPEND, on the ephemeral provider. OpenMLS deletes the (non-last-resort) KeyPackage at the
    // very start of new_from_welcome, before it finishes decrypting/validating - so BOTH new_from_welcome
    // and into_group can fail after the (ephemeral) KeyPackage is spent. A confirmation-tag mismatch is
    // a debug-build panic (openmls `debug_assert!`) that becomes a plain Err in release; catch_unwind
    // stays as defense-in-depth (no longer the transaction boundary). None: the ratchet tree is embedded
    // in the Welcome (use_ratchet_tree_extension).
    let join: anyhow::Result<MlsGroup> =
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let staged =
                StagedWelcome::new_from_welcome(&provider, &mls_group_config, welcome, None)
                    .map_err(|e| anyhow::anyhow!("Error processing Welcome: {:?}", e))?;
            staged
                .into_group(&provider)
                .map_err(|e| anyhow::anyhow!("Error joining group: {:?}", e))
        })) {
            Ok(result) => result,
            Err(_panic) => Err(anyhow::anyhow!("panic while opening the Welcome")),
        };

    // Read provider storage AFTER the boundary, regardless of Ok/Err/panic. This is the ONE read that
    // cannot rely on the module's "lock never poisons" invariant - a caught panic could have poisoned
    // the guard mid-write - so it alone is poison-tolerant rather than `.unwrap()`. Wrapped so its
    // secret values wipe on every early return.
    let mut post_join_storage = PostJoinStorage({
        let values = provider
            .storage()
            .values
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        values.clone().into_iter().collect()
    });

    let group = match join {
        Ok(group) => group,
        Err(e) => {
            // The caller already durably persisted the fail-closed retirement in phase 1, so the
            // retirement stands regardless - there is no Unspent outcome here. Refine to the precise
            // retirement when it can be built (restoring KeyPackages the conservative over-retired,
            // including a last-resort package that was not actually consumed); otherwise the caller
            // keeps the conservative bundle it already holds.
            let retired_bundle = crate::mls::groups::retire_consumed_key_package(
                identity,
                original_storage,
                &post_join_storage.0,
                &provider,
            )
            .map(|z| z.to_vec())
            .unwrap_or_else(|_| conservative.to_vec());
            return Err(MimiWelcomeError::Spent {
                retired_bundle,
                reason: format!("the join did not complete after the Welcome was opened: {e}"),
            });
        }
    };

    // Join succeeded: build the precise retirement (honors the last-resort exception, retires exactly
    // the consumed KeyPackage). Shared with the non-appsync path so the single-use retirement is one
    // implementation. Fail closed to the conservative the caller already persisted.
    let retired_bundle = match crate::mls::groups::retire_consumed_key_package(
        identity,
        original_storage,
        &post_join_storage.0,
        &provider,
    ) {
        Ok(bundle) => bundle.to_vec(),
        Err(_) => {
            return Err(MimiWelcomeError::Spent {
                retired_bundle: conservative.to_vec(),
                reason:
                    "the join succeeded but the precise KeyPackage retirement could not be built"
                        .to_string(),
            });
        }
    };

    // Pin the configured hub credential BEFORE serializing the joined state, so a rejection never builds
    // (and then drops unwiped) a GroupState buffer. The retirement is already durable, so a rejection
    // travels back as a Spent for the caller to persist over the conservative one.
    if let Some(expected_bytes) = expected_hub_entry {
        let matches = match group.extensions().external_senders() {
            Some(list) if list.len() == 1 => list[0]
                .tls_serialize_detached()
                .map(|actual| actual == expected_bytes)
                .unwrap_or(false),
            _ => false,
        };
        if !matches {
            return Err(MimiWelcomeError::Spent {
                retired_bundle,
                reason:
                    "joined group's external_senders does not match the expected hub credential"
                        .to_string(),
            });
        }
    }

    // Move the joined-group storage into GroupState (mem::take leaves the wrapper empty; GroupState's
    // own Drop then owns the wipe). If it cannot be serialized, still hand back the retirement (Spent).
    let group_id = group.group_id().to_vec();
    let state_bytes = match crate::mls::zeroizing_json(&GroupState {
        group_id,
        storage_map: mem::take(&mut post_join_storage.0),
    }) {
        Ok(state) => state,
        Err(_) => {
            return Err(MimiWelcomeError::Spent {
                retired_bundle,
                reason: "the join succeeded but its group state could not be serialized"
                    .to_string(),
            });
        }
    };

    Ok((state_bytes.to_vec(), retired_bundle))
}

/// Process an AppSync-lane Welcome to join a group, in a single call.
///
/// Returns `(new_group_state, updated_bundle)`, the same shape as the non-appsync
/// [`crate::mls::groups::process_welcome`]. The updated bundle is the caller's bundle with the
/// KeyPackage this join consumed retired (single-use, RFC 9420 §16.8); the caller MUST persist the
/// returned bundle in place of the input.
///
/// This convenience form is non-atomic. Callers needing crash-atomic single-use handling must use
/// [`prepare_welcome_retirement`], persist [`PreparedWelcome::retired_bundle`], then call
/// [`complete_welcome`].
///
/// Hub-identity pinning is as documented on [`prepare_welcome_retirement`]. A failure before the
/// KeyPackage is targeted/opened is [`MimiWelcomeError::Unspent`]; a failure after the Welcome is opened
/// is [`MimiWelcomeError::Spent`] carrying the retirement.
#[deprecated(
    note = "use prepare_welcome_retirement, persist PreparedWelcome::retired_bundle, then call complete_welcome"
)]
pub fn mimi_process_welcome_non_atomic(
    mls_welcome_message_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    expected_hub_signature_key_bytes: Vec<u8>,
    expected_hub_credential_identity: String,
) -> Result<(Vec<u8>, Vec<u8>), MimiWelcomeError> {
    let prepared = prepare_welcome_retirement(
        mls_welcome_message_bytes,
        bundle_bytes,
        expected_hub_signature_key_bytes,
        expected_hub_credential_identity,
    )?;
    complete_welcome(prepared)
}

#[cfg(test)]
mod tests;
