//! A commit this member made that the group has not accepted yet.
//!
//! Every outbound membership change (`*_pending` in [`crate::mls::groups`] and [`crate::mimi`]) stops
//! after OpenMLS stages the commit and returns a [`PendingCommit`]: the predecessor epoch with OpenMLS's
//! own staged commit inside it. No successor state exists until [`PendingCommit::confirm`] runs
//! `merge_pending_commit`, and that happens only against a [`CommitAcceptance`] naming this exact
//! commit. A successor therefore cannot become canonical before the group's delivery service has
//! accepted the commit that produces it, and the commit and its successor are linked by construction:
//! the successor is OpenMLS merging the staged commit that serialized to these commit bytes.
//!
//! There are exactly two exits. `confirm` returns the successor to install. `abandon`, for a commit the
//! delivery service refused for good, returns the predecessor-epoch state to install in its place.
//! That state is not always the caller's original predecessor: in a group whose handshake messages are
//! encrypted, staging the commit consumed one sender-ratchet generation, and continuing from the
//! original would reuse it.
//!
//! The caller's canonical state is never modified by any of this. A pending commit is persisted with
//! [`PendingCommit::to_bytes`] before the commit is first sent, so a restart resends the same bytes
//! rather than minting a different commit.
//!
//! crypto-core cannot authenticate a delivery service. A [`CommitAcceptance`] binds the group, the
//! predecessor epoch, the digest of the accepted bytes and the caller's submission identity, so an
//! acceptance for another group, epoch, commit or retry cannot confirm this one. Whether the acceptance
//! really came from the delivery service is the constructing caller's responsibility.
#![allow(
    clippy::unwrap_used, // in-memory provider RwLock guards only (see crate::mls::groups module doc)
    clippy::doc_markdown // doc comments cite OpenMLS type names verbatim
)]

use std::collections::BTreeSet;
use std::mem;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use openmls::ciphersuite::hash_ref::ProposalRef;
use openmls::credentials::BasicCredential;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use zeroize::{Zeroize, Zeroizing};

use crate::mls::groups::IndexedMlsMember;
use crate::mls::{GroupState, IdentityBundle, MlsSigner};

const STAGED_FORMAT: &str = "pending-commit/staged/1";
const LEGACY_FORMAT: &str = "pending-commit/legacy-merged/1";
const BINDING_DOMAIN: &[u8] = b"crypto-core pending-commit epoch binding v1";

/// Why a pending commit was refused, or could not be read.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum PendingCommitError {
    #[error("the acceptance names a different group")]
    WrongGroup,
    #[error("the acceptance names a different predecessor epoch")]
    WrongEpoch,
    #[error("the accepted commit bytes are not this pending commit")]
    CommitMismatch,
    #[error("no submission identity is bound to this pending commit")]
    SubmissionUnbound,
    #[error("the submission identity does not match the one bound to this pending commit")]
    SubmissionMismatch,
    #[error("the canonical state is no longer this commit's predecessor")]
    PredecessorMoved,
    #[error("unknown pending-commit format")]
    UnsupportedFormat,
    #[error("malformed pending commit: {0}")]
    Malformed(&'static str),
    #[error("legacy pending row refused: {0}")]
    LegacyBindingInvalid(&'static str),
    #[error("MLS operation failed: {0}")]
    Mls(String),
}

/// Membership before and after a pending commit, read without producing any group state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCommitSummary {
    pub from_epoch: u64,
    pub to_epoch: u64,
    /// Members the commit adds, at the leaves they occupy after it.
    pub added: Vec<IndexedMlsMember>,
    /// Members the commit removes, at the leaves they occupied before it.
    pub removed: Vec<IndexedMlsMember>,
    pub members_after: Vec<IndexedMlsMember>,
}

/// The delivery service's acceptance of one exact commit.
///
/// Construct it from the bytes that were actually sent and the submission identity they were sent
/// under, in the one place that matches a delivery-service answer to its request. Never construct it
/// from [`PendingCommit::commit`]: that would accept whatever is pending rather than what was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitAcceptance {
    group_id: Vec<u8>,
    predecessor_epoch: u64,
    commit_digest: [u8; 32],
    submission: Vec<u8>,
}

impl CommitAcceptance {
    #[must_use]
    pub fn new(
        group_id: &[u8],
        predecessor_epoch: u64,
        accepted_commit: &[u8],
        submission: &[u8],
    ) -> Self {
        Self {
            group_id: group_id.to_vec(),
            predecessor_epoch,
            commit_digest: Sha256::digest(accepted_commit).into(),
            submission: submission.to_vec(),
        }
    }
}

/// Group state after an accepted commit: the state to install as canonical. Same encoding as the
/// group state every other function in this crate takes and returns.
#[must_use = "a confirmed commit's successor must be installed as the canonical group state"]
pub struct ConfirmedGroupState(Zeroizing<Vec<u8>>);

impl std::fmt::Debug for ConfirmedGroupState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfirmedGroupState(<group secrets>)")
    }
}

impl ConfirmedGroupState {
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

/// Predecessor-epoch group state after a refused commit: the state to install as canonical in place of
/// the predecessor the commit was made from.
#[must_use = "an abandoned commit's state must replace the canonical predecessor"]
pub struct AbandonedGroupState(Zeroizing<Vec<u8>>);

impl std::fmt::Debug for AbandonedGroupState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AbandonedGroupState(<group secrets>)")
    }
}

impl AbandonedGroupState {
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

/// A refused confirmation: the reason, and the pending commit, unchanged.
#[derive(Debug)]
pub struct ConfirmRefused {
    pub pending: Box<PendingCommit>,
    pub reason: PendingCommitError,
}

enum Body {
    /// The predecessor storage with OpenMLS's staged commit, plus the proposals this operation queued
    /// for the commit to carry (removed again on abandon).
    Staged {
        storage: GroupState,
        own_proposals: Vec<Vec<u8>>,
    },
    /// A row written before pending commits existed: the merged successor and the predecessor it
    /// replaced.
    LegacyMerged {
        predecessor: GroupState,
        successor: GroupState,
    },
}

/// A commit this member made and the group has not accepted yet. See the module documentation.
#[must_use = "a pending commit is not group state: persist it, send commit(), then confirm() or abandon()"]
pub struct PendingCommit {
    group_id: Vec<u8>,
    predecessor_epoch: u64,
    predecessor_binding: [u8; 32],
    successor_binding: [u8; 32],
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
    submission: Option<Vec<u8>>,
    summary: PendingCommitSummary,
    body: Body,
}

impl std::fmt::Debug for PendingCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingCommit")
            .field("group_id", &hex::encode(&self.group_id))
            .field("predecessor_epoch", &self.predecessor_epoch)
            .field("commit_digest", &hex::encode(self.commit_digest()))
            .field(
                "format",
                &match self.body {
                    Body::Staged { .. } => STAGED_FORMAT,
                    Body::LegacyMerged { .. } => LEGACY_FORMAT,
                },
            )
            .finish_non_exhaustive()
    }
}

impl PendingCommit {
    #[must_use]
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// The epoch the commit was made in, which the group leaves when it accepts it.
    #[must_use]
    pub const fn predecessor_epoch(&self) -> u64 {
        self.predecessor_epoch
    }

    /// The exact commit to send, and to resend unchanged on retry.
    #[must_use]
    pub fn commit(&self) -> &[u8] {
        &self.commit
    }

    #[must_use]
    pub fn commit_digest(&self) -> [u8; 32] {
        Sha256::digest(&self.commit).into()
    }

    /// The Welcome for added members, encoded as the generating function's older form returned it.
    #[must_use]
    pub fn welcome(&self) -> Option<&[u8]> {
        self.welcome.as_deref()
    }

    #[must_use]
    pub fn submission(&self) -> Option<&[u8]> {
        self.submission.as_deref()
    }

    #[must_use]
    pub const fn summary(&self) -> &PendingCommitSummary {
        &self.summary
    }

    /// Whether `canonical_now` is still the state this commit was made from.
    pub fn applies_to(&self, canonical_now: &[u8]) -> Result<bool, PendingCommitError> {
        Ok(state_binding(canonical_now)? == self.predecessor_binding)
    }

    /// Whether `canonical_now` is already this commit's successor: a confirmation installed before a
    /// restart, whose pending row was not yet cleared.
    pub fn is_installed_in(&self, canonical_now: &[u8]) -> Result<bool, PendingCommitError> {
        Ok(state_binding(canonical_now)? == self.successor_binding)
    }

    /// Bind the identity this commit is submitted under. Bind before the first send; a retry
    /// re-binds the same identity, and a different one is refused.
    pub fn bind_submission(&mut self, submission: &[u8]) -> Result<(), PendingCommitError> {
        match &self.submission {
            None => {
                self.submission = Some(submission.to_vec());
                Ok(())
            }
            Some(bound) if bound.as_slice() == submission => Ok(()),
            Some(_) => Err(PendingCommitError::SubmissionMismatch),
        }
    }

    /// Install-ready successor state, only for an acceptance of exactly this commit made from exactly
    /// `canonical_now`. A refusal returns this pending commit unchanged; nothing is written either way.
    pub fn confirm(
        self,
        canonical_now: &[u8],
        acceptance: &CommitAcceptance,
    ) -> Result<ConfirmedGroupState, ConfirmRefused> {
        if let Err(reason) = self.check_acceptance(canonical_now, acceptance) {
            return Err(ConfirmRefused {
                pending: Box::new(self),
                reason,
            });
        }
        match self.successor_bytes() {
            Ok(bytes) => Ok(ConfirmedGroupState(bytes)),
            Err(reason) => Err(ConfirmRefused {
                pending: Box::new(self),
                reason,
            }),
        }
    }

    fn check_acceptance(
        &self,
        canonical_now: &[u8],
        acceptance: &CommitAcceptance,
    ) -> Result<(), PendingCommitError> {
        if acceptance.group_id != self.group_id {
            return Err(PendingCommitError::WrongGroup);
        }
        if acceptance.predecessor_epoch != self.predecessor_epoch {
            return Err(PendingCommitError::WrongEpoch);
        }
        if acceptance.commit_digest != self.commit_digest() {
            return Err(PendingCommitError::CommitMismatch);
        }
        match &self.submission {
            None => return Err(PendingCommitError::SubmissionUnbound),
            Some(bound) if *bound != acceptance.submission => {
                return Err(PendingCommitError::SubmissionMismatch)
            }
            Some(_) => {}
        }
        if !self.applies_to(canonical_now)? {
            return Err(PendingCommitError::PredecessorMoved);
        }
        Ok(())
    }

    fn successor_bytes(&self) -> Result<Zeroizing<Vec<u8>>, PendingCommitError> {
        match &self.body {
            Body::Staged { storage, .. } => {
                let (provider, mut group) = load_group(storage)?;
                group
                    .merge_pending_commit(&provider)
                    .map_err(|e| PendingCommitError::Mls(format!("merge: {e:?}")))?;
                if binding(&group) != self.successor_binding {
                    return Err(PendingCommitError::Malformed(
                        "merged state does not match the staged successor",
                    ));
                }
                export_state(&provider, &self.group_id)
            }
            Body::LegacyMerged { successor, .. } => encode_state(successor),
        }
    }

    /// Install-ready predecessor-epoch state for a commit the delivery service refused for good. Call
    /// it only on a terminal refusal: if the commit could still be accepted, this member would lose the
    /// key material for the epoch the group moves to.
    pub fn abandon(self) -> Result<AbandonedGroupState, PendingCommitError> {
        match &self.body {
            Body::Staged {
                storage,
                own_proposals,
            } => {
                let (provider, mut group) = load_group(storage)?;
                group
                    .clear_pending_commit(provider.storage())
                    .map_err(|e| PendingCommitError::Mls(format!("clear pending commit: {e:?}")))?;
                for reference in own_proposals {
                    let reference = ProposalRef::tls_deserialize_exact(reference.as_slice())
                        .map_err(|_| PendingCommitError::Malformed("proposal reference"))?;
                    group
                        .remove_pending_proposal(provider.storage(), &reference)
                        .map_err(|e| PendingCommitError::Mls(format!("remove proposal: {e:?}")))?;
                }
                if binding(&group) != self.predecessor_binding {
                    return Err(PendingCommitError::Malformed(
                        "abandoned state is not the predecessor epoch",
                    ));
                }
                Ok(AbandonedGroupState(export_state(
                    &provider,
                    &self.group_id,
                )?))
            }
            Body::LegacyMerged { predecessor, .. } => {
                Ok(AbandonedGroupState(encode_state(predecessor)?))
            }
        }
    }

    /// The durable form, written before the commit is first sent. It carries group secrets.
    pub fn to_bytes(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let (format, state, predecessor_state, own_proposals) = match &self.body {
            Body::Staged {
                storage,
                own_proposals,
            } => (
                STAGED_FORMAT,
                entries_repr(storage),
                None,
                own_proposals.iter().map(|p| B64(p.clone())).collect(),
            ),
            Body::LegacyMerged {
                predecessor,
                successor,
            } => (
                LEGACY_FORMAT,
                entries_repr(successor),
                Some(entries_repr(predecessor)),
                Vec::new(),
            ),
        };
        let repr = Repr {
            format: format.to_owned(),
            group_id: B64(self.group_id.clone()),
            predecessor_epoch: self.predecessor_epoch,
            predecessor_binding: hex::encode(self.predecessor_binding),
            successor_binding: hex::encode(self.successor_binding),
            commit: B64(self.commit.clone()),
            welcome: self.welcome.clone().map(B64),
            submission: self.submission.clone().map(B64),
            summary: SummaryRepr::from(&self.summary),
            state,
            predecessor_state,
            own_proposals,
        };
        Ok(Zeroizing::new(serde_json::to_vec(&repr)?))
    }

    /// Read a pending commit written by [`PendingCommit::to_bytes`]. Every binding is recomputed from
    /// the stored state; anything that does not agree is refused by name, never read as something else.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PendingCommitError> {
        let repr: Repr = serde_json::from_slice(bytes)
            .map_err(|_| PendingCommitError::Malformed("not a pending-commit record"))?;
        let predecessor_binding = hex32(&repr.predecessor_binding)?;
        let successor_binding = hex32(&repr.successor_binding)?;
        let group_id = repr.group_id.0.clone();
        let summary = repr.summary.into_summary()?;
        let body = match repr.format.as_str() {
            STAGED_FORMAT => {
                if repr.predecessor_state.is_some() {
                    return Err(PendingCommitError::Malformed(
                        "a staged record carries no predecessor",
                    ));
                }
                let storage = state_from_entries(&group_id, repr.state);
                let (_provider, group) = load_group(&storage)?;
                let staged = group
                    .pending_commit()
                    .ok_or(PendingCommitError::Malformed("no staged commit"))?;
                if group.epoch().as_u64() != repr.predecessor_epoch
                    || binding(&group) != predecessor_binding
                {
                    return Err(PendingCommitError::Malformed("predecessor binding"));
                }
                let next = staged
                    .epoch_authenticator()
                    .ok_or(PendingCommitError::Malformed(
                        "staged commit has no successor",
                    ))?;
                if binding_parts(&group_id, repr.predecessor_epoch + 1, next.as_slice())
                    != successor_binding
                {
                    return Err(PendingCommitError::Malformed("successor binding"));
                }
                Body::Staged {
                    storage,
                    own_proposals: repr
                        .own_proposals
                        .into_iter()
                        .map(|p| p.0.clone())
                        .collect(),
                }
            }
            LEGACY_FORMAT => {
                let predecessor = state_from_entries(
                    &group_id,
                    repr.predecessor_state.ok_or(PendingCommitError::Malformed(
                        "legacy record without predecessor",
                    ))?,
                );
                let successor = state_from_entries(&group_id, repr.state);
                if state_binding_of(&predecessor)? != predecessor_binding
                    || state_binding_of(&successor)? != successor_binding
                {
                    return Err(PendingCommitError::Malformed("legacy binding"));
                }
                Body::LegacyMerged {
                    predecessor,
                    successor,
                }
            }
            _ => return Err(PendingCommitError::UnsupportedFormat),
        };
        let commit = repr.commit.0.clone();
        check_commit_framing(&commit, &group_id, repr.predecessor_epoch)
            .map_err(|_| PendingCommitError::Malformed("commit framing"))?;
        Ok(Self {
            group_id,
            predecessor_epoch: repr.predecessor_epoch,
            predecessor_binding,
            successor_binding,
            commit,
            welcome: repr.welcome.map(|w| w.0.clone()),
            submission: repr.submission.map(|s| s.0.clone()),
            summary,
            body,
        })
    }

    /// Recover a row written before pending commits existed, which already holds the merged successor.
    /// Checked: both states are the same group, the successor is one epoch later, and the commit is a
    /// Commit framed in the predecessor's group and epoch by a member of it. Not checked, because
    /// OpenMLS does not expose what it would need (the predecessor's interim transcript hash): that the
    /// successor resulted from this particular commit. Use it once per pre-existing row; new commits are
    /// only ever staged.
    pub fn from_legacy_merged(
        predecessor: &[u8],
        successor: &[u8],
        commit: &[u8],
        welcome: Option<&[u8]>,
    ) -> Result<Self, PendingCommitError> {
        use PendingCommitError::LegacyBindingInvalid as Invalid;
        let predecessor: GroupState =
            serde_json::from_slice(predecessor).map_err(|_| Invalid("predecessor state"))?;
        let successor: GroupState =
            serde_json::from_slice(successor).map_err(|_| Invalid("successor state"))?;
        if predecessor.group_id != successor.group_id {
            return Err(Invalid("states are different groups"));
        }
        let group_id = predecessor.group_id.clone();
        let (_p, before) = load_group(&predecessor).map_err(|_| Invalid("predecessor state"))?;
        let (_s, after) = load_group(&successor).map_err(|_| Invalid("successor state"))?;
        let predecessor_epoch = before.epoch().as_u64();
        if after.epoch().as_u64() != predecessor_epoch + 1 {
            return Err(Invalid("successor is not the next epoch"));
        }
        let sender = check_commit_framing(commit, &group_id, predecessor_epoch)?;
        if let Some(leaf) = sender {
            if before.member_at(leaf).is_none() {
                return Err(Invalid("commit sender is not a member"));
            }
        }
        let summary = summarize(&before, &after)?;
        Ok(Self {
            predecessor_binding: binding(&before),
            successor_binding: binding(&after),
            group_id,
            predecessor_epoch,
            commit: commit.to_vec(),
            welcome: welcome.map(<[u8]>::to_vec),
            submission: None,
            summary,
            body: Body::LegacyMerged {
                predecessor,
                successor,
            },
        })
    }

    /// The older all-in-one behavior, kept for the functions that still return a merged successor.
    pub(crate) fn into_merged(self) -> anyhow::Result<Merged> {
        let successor = self
            .successor_bytes()
            .map_err(|e| anyhow::anyhow!("Error merging commit: {e}"))?;
        Ok((successor, self.welcome, self.commit))
    }
}

/// The older functions' result: successor state, Welcome when there is one, and the commit.
pub(crate) type Merged = (Zeroizing<Vec<u8>>, Option<Vec<u8>>, Vec<u8>);

/// A group opened for an outbound change: the provider holding its storage, the group, and the signer.
pub(crate) struct OpenedGroup {
    pub(crate) provider: OpenMlsRustCrypto,
    pub(crate) group: MlsGroup,
    pub(crate) signer: MlsSigner,
    group_id: Vec<u8>,
}

/// Open `group_state_bytes` with the member's `bundle_bytes`, for a function that will stage a commit.
pub(crate) fn open_group(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
) -> anyhow::Result<OpenedGroup> {
    // Both inputs carry secrets; wrapping them on entry wipes them on every exit path.
    let group_state_bytes = Zeroizing::new(group_state_bytes);
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    let mut state: GroupState = serde_json::from_slice(&group_state_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid group state: {e:?}"))?;
    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {e:?}"))?;
    let provider = OpenMlsRustCrypto::default();
    {
        let mut values = provider.storage().values.write().unwrap();
        *values = mem::take(&mut state.storage_map).into_iter().collect();
    }
    let signer = MlsSigner {
        key: Zeroizing::new(mem::take(&mut identity.private_key)),
        scheme: identity.signature_scheme,
    };
    let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&state.group_id))
        .map_err(|e| anyhow::anyhow!("Error loading group: {e:?}"))?
        .ok_or_else(|| anyhow::anyhow!("Group not found in storage"))?;
    Ok(OpenedGroup {
        provider,
        group,
        signer,
        group_id: mem::take(&mut state.group_id),
    })
}

/// How the generating function encodes the Welcome for added members.
pub(crate) enum WelcomeForm {
    /// The `MlsMessageOut` Welcome alone.
    Bare(MlsMessageOut),
    /// JSON `(welcome, ratchet_tree)`, the tree being the post-commit tree.
    WithRatchetTree(MlsMessageOut),
}

/// Wrap a group in which a commit has just been staged. `own_proposals` are the proposals this
/// operation queued for the commit to carry.
pub(crate) fn staged(
    opened: OpenedGroup,
    commit: &MlsMessageOut,
    welcome: Option<WelcomeForm>,
    own_proposals: &[ProposalRef],
) -> anyhow::Result<PendingCommit> {
    let OpenedGroup {
        provider,
        group,
        signer: _,
        group_id,
    } = opened;
    let staged_commit = group
        .pending_commit()
        .ok_or_else(|| anyhow::anyhow!("no staged commit"))?;
    let next = staged_commit
        .epoch_authenticator()
        .ok_or_else(|| anyhow::anyhow!("staged commit has no successor epoch"))?;
    let predecessor_epoch = group.epoch().as_u64();
    let successor_binding = binding_parts(&group_id, predecessor_epoch + 1, next.as_slice());
    let storage = GroupState {
        group_id: group_id.clone(),
        storage_map: provider
            .storage()
            .values
            .read()
            .unwrap()
            .clone()
            .into_iter()
            .collect(),
    };

    // The successor, computed in a throwaway provider for the summary and the Welcome's tree, and
    // wiped before return: it never leaves this function.
    let (scratch, mut after) = load_group(&storage).map_err(|e| anyhow::anyhow!("{e}"))?;
    after
        .merge_pending_commit(&scratch)
        .map_err(|e| anyhow::anyhow!("Error merging commit: {e:?}"))?;
    anyhow::ensure!(
        binding(&after) == successor_binding,
        "staged successor does not match its merge"
    );
    let summary = summarize(&group, &after).map_err(|e| anyhow::anyhow!("{e}"))?;
    let welcome = match welcome {
        None => None,
        Some(WelcomeForm::Bare(welcome)) => Some(welcome.tls_serialize_detached()?),
        Some(WelcomeForm::WithRatchetTree(welcome)) => {
            let tree = after.export_ratchet_tree().tls_serialize_detached()?;
            Some(serde_json::to_vec(&(
                welcome.tls_serialize_detached()?,
                tree,
            ))?)
        }
    };
    wipe(&scratch);

    let own_proposals = own_proposals
        .iter()
        .map(TlsSerialize::tls_serialize_detached)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PendingCommit {
        predecessor_binding: binding(&group),
        successor_binding,
        group_id,
        predecessor_epoch,
        commit: commit.tls_serialize_detached()?,
        welcome,
        submission: None,
        summary,
        body: Body::Staged {
            storage,
            own_proposals,
        },
    })
}

fn wipe(provider: &OpenMlsRustCrypto) {
    for value in provider.storage().values.write().unwrap().values_mut() {
        value.zeroize();
    }
}

fn load_group(state: &GroupState) -> Result<(OpenMlsRustCrypto, MlsGroup), PendingCommitError> {
    let provider = OpenMlsRustCrypto::default();
    *provider.storage().values.write().unwrap() = state.storage_map.iter().cloned().collect();
    let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&state.group_id))
        .map_err(|_| PendingCommitError::Malformed("group state does not load"))?
        .ok_or(PendingCommitError::Malformed("group not in state"))?;
    Ok((provider, group))
}

fn export_state(
    provider: &OpenMlsRustCrypto,
    group_id: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PendingCommitError> {
    let state = GroupState {
        group_id: group_id.to_vec(),
        storage_map: provider
            .storage()
            .values
            .read()
            .unwrap()
            .clone()
            .into_iter()
            .collect(),
    };
    wipe(provider);
    encode_state(&state)
}

fn encode_state(state: &GroupState) -> Result<Zeroizing<Vec<u8>>, PendingCommitError> {
    crate::mls::zeroizing_json(state).map_err(|_| PendingCommitError::Malformed("encode state"))
}

/// What identifies one epoch of one group across re-serialization: its id, epoch and epoch
/// authenticator. Distinct even for a recreated group that reuses an id at the same epoch number.
fn binding(group: &MlsGroup) -> [u8; 32] {
    binding_parts(
        group.group_id().as_slice(),
        group.epoch().as_u64(),
        group.epoch_authenticator().as_slice(),
    )
}

fn binding_parts(group_id: &[u8], epoch: u64, authenticator: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(BINDING_DOMAIN);
    hash.update((group_id.len() as u64).to_be_bytes());
    hash.update(group_id);
    hash.update(epoch.to_be_bytes());
    hash.update(authenticator);
    hash.finalize().into()
}

fn state_binding(state_bytes: &[u8]) -> Result<[u8; 32], PendingCommitError> {
    let state: GroupState = serde_json::from_slice(state_bytes)
        .map_err(|_| PendingCommitError::Malformed("canonical state"))?;
    state_binding_of(&state)
}

fn state_binding_of(state: &GroupState) -> Result<[u8; 32], PendingCommitError> {
    let (provider, group) = load_group(state)?;
    let bound = binding(&group);
    wipe(&provider);
    Ok(bound)
}

/// The commit must be an MLS Commit framed in `group_id` at `epoch`. Returns the sender leaf when the
/// framing shows it (a PublicMessage).
fn check_commit_framing(
    commit: &[u8],
    group_id: &[u8],
    epoch: u64,
) -> Result<Option<LeafNodeIndex>, PendingCommitError> {
    use PendingCommitError::LegacyBindingInvalid as Invalid;
    crate::mls::check_wire_size(commit, "pending commit").map_err(|_| Invalid("commit size"))?;
    let message =
        MlsMessageIn::tls_deserialize_exact(commit).map_err(|_| Invalid("commit bytes"))?;
    let protocol = ProtocolMessage::try_from(message)
        .map_err(|_| Invalid("commit is not a protocol message"))?;
    if protocol.group_id().as_slice() != group_id || protocol.epoch().as_u64() != epoch {
        return Err(Invalid("commit is framed in another group or epoch"));
    }
    if protocol.content_type() != ContentType::Commit {
        return Err(Invalid("message is not a commit"));
    }
    match &protocol {
        ProtocolMessage::PublicMessage(public) => match public.sender() {
            Sender::Member(leaf) => Ok(Some(*leaf)),
            _ => Err(Invalid("commit sender is not a member")),
        },
        ProtocolMessage::PrivateMessage(_) => Ok(None),
    }
}

fn members(group: &MlsGroup) -> Result<Vec<IndexedMlsMember>, PendingCommitError> {
    group
        .members()
        .map(|member| {
            let credential = BasicCredential::try_from(member.credential)
                .map_err(|_| PendingCommitError::Malformed("non-Basic credential"))?;
            Ok(IndexedMlsMember {
                leaf_index: member.index.u32(),
                credential_identity: credential.identity().to_vec(),
                signature_key: hex::encode_upper(member.signature_key),
            })
        })
        .collect()
}

fn summarize(
    before: &MlsGroup,
    after: &MlsGroup,
) -> Result<PendingCommitSummary, PendingCommitError> {
    let before_members = members(before)?;
    let members_after = members(after)?;
    let keys = |list: &[IndexedMlsMember]| -> BTreeSet<String> {
        list.iter().map(|m| m.signature_key.clone()).collect()
    };
    let (before_keys, after_keys) = (keys(&before_members), keys(&members_after));
    Ok(PendingCommitSummary {
        from_epoch: before.epoch().as_u64(),
        to_epoch: after.epoch().as_u64(),
        added: members_after
            .iter()
            .filter(|m| !before_keys.contains(&m.signature_key))
            .cloned()
            .collect(),
        removed: before_members
            .iter()
            .filter(|m| !after_keys.contains(&m.signature_key))
            .cloned()
            .collect(),
        members_after,
    })
}

fn hex32(text: &str) -> Result<[u8; 32], PendingCommitError> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).map_err(|_| PendingCommitError::Malformed("binding"))?;
    Ok(out)
}

fn entries_repr(state: &GroupState) -> Vec<(B64, B64)> {
    state
        .storage_map
        .iter()
        .map(|(k, v)| (B64(k.clone()), B64(v.clone())))
        .collect()
}

fn state_from_entries(group_id: &[u8], entries: Vec<(B64, B64)>) -> GroupState {
    GroupState {
        group_id: group_id.to_vec(),
        storage_map: entries
            .into_iter()
            .map(|(k, v)| (k.0.clone(), v.0.clone()))
            .collect(),
    }
}

/// Bytes stored as a base64 string, wiped on drop: storage values are group secrets.
struct B64(Vec<u8>);

impl Drop for B64 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Serialize for B64 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = Zeroizing::new(BASE64.encode(&self.0));
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        BASE64
            .decode(text.as_bytes())
            .map(B64)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Repr {
    format: String,
    group_id: B64,
    predecessor_epoch: u64,
    predecessor_binding: String,
    successor_binding: String,
    commit: B64,
    welcome: Option<B64>,
    submission: Option<B64>,
    summary: SummaryRepr,
    state: Vec<(B64, B64)>,
    predecessor_state: Option<Vec<(B64, B64)>>,
    own_proposals: Vec<B64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryRepr {
    from_epoch: u64,
    to_epoch: u64,
    added: Vec<MemberRepr>,
    removed: Vec<MemberRepr>,
    members_after: Vec<MemberRepr>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberRepr {
    leaf_index: u32,
    credential_identity: B64,
    signature_key: String,
}

impl From<&PendingCommitSummary> for SummaryRepr {
    fn from(summary: &PendingCommitSummary) -> Self {
        let list = |members: &[IndexedMlsMember]| {
            members
                .iter()
                .map(|m| MemberRepr {
                    leaf_index: m.leaf_index,
                    credential_identity: B64(m.credential_identity.clone()),
                    signature_key: m.signature_key.clone(),
                })
                .collect()
        };
        Self {
            from_epoch: summary.from_epoch,
            to_epoch: summary.to_epoch,
            added: list(&summary.added),
            removed: list(&summary.removed),
            members_after: list(&summary.members_after),
        }
    }
}

impl SummaryRepr {
    fn into_summary(self) -> Result<PendingCommitSummary, PendingCommitError> {
        if self.to_epoch != self.from_epoch + 1 {
            return Err(PendingCommitError::Malformed("summary epochs"));
        }
        let list = |members: Vec<MemberRepr>| {
            members
                .into_iter()
                .map(|m| IndexedMlsMember {
                    leaf_index: m.leaf_index,
                    credential_identity: m.credential_identity.0.clone(),
                    signature_key: m.signature_key,
                })
                .collect()
        };
        Ok(PendingCommitSummary {
            from_epoch: self.from_epoch,
            to_epoch: self.to_epoch,
            added: list(self.added),
            removed: list(self.removed),
            members_after: list(self.members_after),
        })
    }
}

#[cfg(test)]
mod tests;
