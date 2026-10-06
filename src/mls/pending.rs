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

/// Storage entries staging wrote, each with the predecessor's value, or `None` where it had none.
type RestoreSet = Vec<(Vec<u8>, Option<Vec<u8>>)>;

enum Body {
    /// The predecessor storage with OpenMLS's staged commit, plus the proposals this operation
    /// queued for the commit to carry. `restore` is present when the commit is a PublicMessage,
    /// which consumes no key material: it holds the predecessor value
    /// (`None` for absent) of every entry staging wrote, so abandoning returns the predecessor exactly.
    Staged {
        storage: GroupState,
        own_proposals: Vec<Vec<u8>>,
        restore: Option<(RestoreSet, Original)>,
    },
    /// A row written before pending commits existed: the merged successor and the predecessor it
    /// replaced.
    LegacyMerged {
        predecessor: GroupState,
        successor: GroupState,
        predecessor_original: Original,
        successor_original: Original,
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
            Body::Staged {
                storage,
                own_proposals,
                ..
            } => {
                let (provider, mut group) = load_group(storage)?;
                group
                    .merge_pending_commit(&provider)
                    .map_err(|e| PendingCommitError::Mls(format!("merge: {e:?}")))?;
                // The commit consumed the proposals this member staged for it. Merging empties the
                // in-memory proposal store but leaves each proposal's stored entry, which would stay in
                // the group's state for every later epoch.
                for reference in own_proposals {
                    let reference = ProposalRef::tls_deserialize_exact(reference.as_slice())
                        .map_err(|_| PendingCommitError::Malformed("proposal reference"))?;
                    match group.remove_pending_proposal(provider.storage(), &reference) {
                        Ok(()) | Err(RemoveProposalError::ProposalNotFound) => {}
                        Err(e) => {
                            return Err(PendingCommitError::Mls(format!("remove proposal: {e:?}")))
                        }
                    }
                }
                if binding(&group) != self.successor_binding {
                    return Err(PendingCommitError::Malformed(
                        "merged state does not match the staged successor",
                    ));
                }
                export_state(&provider, &self.group_id)
            }
            Body::LegacyMerged {
                successor,
                successor_original,
                ..
            } => original_bytes(successor_original, successor),
        }
    }

    /// Install-ready predecessor-epoch state for a commit the delivery service refused for good. Call
    /// it only on a terminal refusal: if the commit could still be accepted, this member would lose the
    /// key material for the epoch the group moves to.
    pub fn abandon(self) -> Result<AbandonedGroupState, PendingCommitError> {
        match &self.body {
            Body::Staged {
                storage,
                restore: Some((restore, original)),
                ..
            } => {
                let predecessor = reverted(storage, restore);
                let (provider, group) = load_group(&predecessor)?;
                wipe(&provider);
                if group.pending_commit().is_some() || binding(&group) != self.predecessor_binding {
                    return Err(PendingCommitError::Malformed(
                        "restored state is not the predecessor",
                    ));
                }
                Ok(AbandonedGroupState(original_bytes(original, &predecessor)?))
            }
            Body::Staged {
                storage,
                own_proposals,
                restore: None,
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
            Body::LegacyMerged {
                predecessor,
                predecessor_original,
                ..
            } => Ok(AbandonedGroupState(original_bytes(
                predecessor_original,
                predecessor,
            )?)),
        }
    }

    /// The durable form, written before the commit is first sent. It carries group secrets.
    pub fn to_bytes(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let mut repr = Repr {
            format: String::new(),
            group_id: B64(self.group_id.clone()),
            predecessor_epoch: self.predecessor_epoch,
            predecessor_binding: hex::encode(self.predecessor_binding),
            successor_binding: hex::encode(self.successor_binding),
            commit: B64(self.commit.clone()),
            welcome: self.welcome.clone().map(B64),
            submission: self.submission.clone().map(B64),
            summary: SummaryRepr::from(&self.summary),
            state: Vec::new(),
            predecessor_state: None,
            own_proposals: Vec::new(),
            restore: None,
            predecessor_original: None,
            successor_original: None,
        };
        match &self.body {
            Body::Staged {
                storage,
                own_proposals,
                restore,
            } => {
                STAGED_FORMAT.clone_into(&mut repr.format);
                repr.state = entries_repr(storage);
                repr.own_proposals = own_proposals.iter().map(|p| B64(p.clone())).collect();
                if let Some((set, original)) = restore {
                    repr.restore = Some(
                        set.iter()
                            .map(|(k, v)| (B64(k.clone()), v.clone().map(B64)))
                            .collect(),
                    );
                    repr.predecessor_original = Some(OriginalRepr::from(original));
                }
            }
            Body::LegacyMerged {
                predecessor,
                successor,
                predecessor_original,
                successor_original,
            } => {
                LEGACY_FORMAT.clone_into(&mut repr.format);
                repr.state = entries_repr(successor);
                repr.predecessor_state = Some(entries_repr(predecessor));
                repr.predecessor_original = Some(OriginalRepr::from(predecessor_original));
                repr.successor_original = Some(OriginalRepr::from(successor_original));
            }
        }
        Ok(Zeroizing::new(serde_json::to_vec(&repr)?))
    }

    /// Read a pending commit written by [`PendingCommit::to_bytes`]. Every binding is recomputed from
    /// the stored state; anything that does not agree is refused by name, never read as something else.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PendingCommitError> {
        let mut repr: Repr = serde_json::from_slice(bytes)
            .map_err(|_| PendingCommitError::Malformed("not a pending-commit record"))?;
        let bindings = Bindings {
            epoch: repr.predecessor_epoch,
            predecessor: hex32(&repr.predecessor_binding)?,
            successor: hex32(&repr.successor_binding)?,
        };
        let group_id = repr.group_id.0.clone();
        let parts = BodyParts {
            state: mem::take(&mut repr.state),
            predecessor_state: repr.predecessor_state.take(),
            own_proposals: mem::take(&mut repr.own_proposals),
            restore: repr.restore.take(),
            predecessor_original: repr.predecessor_original.take(),
            successor_original: repr.successor_original.take(),
        };
        let body = match repr.format.as_str() {
            STAGED_FORMAT => staged_body(&group_id, &bindings, parts)?,
            LEGACY_FORMAT => legacy_body(&group_id, &bindings, parts)?,
            _ => return Err(PendingCommitError::UnsupportedFormat),
        };
        let commit = repr.commit.0.clone();
        check_commit_framing(&commit, &group_id, bindings.epoch)
            .map_err(|_| PendingCommitError::Malformed("commit framing"))?;
        Ok(Self {
            group_id,
            predecessor_epoch: bindings.epoch,
            predecessor_binding: bindings.predecessor,
            successor_binding: bindings.successor,
            commit,
            welcome: repr.welcome.take().map(|w| w.0.clone()),
            submission: repr.submission.take().map(|s| s.0.clone()),
            summary: repr.summary.into_summary()?,
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
        let predecessor_raw = predecessor;
        let successor_raw = successor;
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
        if predecessor_epoch.checked_add(1) != Some(after.epoch().as_u64()) {
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
                predecessor_original: Original::capture(predecessor_raw, &predecessor),
                successor_original: Original::capture(successor_raw, &successor),
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

/// What a durable record says its group, epoch and two epochs are.
struct Bindings {
    epoch: u64,
    predecessor: [u8; 32],
    successor: [u8; 32],
}

/// The state-bearing fields of a durable record, read by the reader of its format.
struct BodyParts {
    state: Vec<(B64, B64)>,
    predecessor_state: Option<Vec<(B64, B64)>>,
    own_proposals: Vec<B64>,
    restore: Option<Vec<(B64, Option<B64>)>>,
    predecessor_original: Option<OriginalRepr>,
    successor_original: Option<OriginalRepr>,
}

fn staged_body(
    group_id: &[u8],
    bindings: &Bindings,
    parts: BodyParts,
) -> Result<Body, PendingCommitError> {
    if parts.predecessor_state.is_some() {
        return Err(PendingCommitError::Malformed(
            "a staged record carries no predecessor",
        ));
    }
    let storage = state_from_entries(group_id, parts.state);
    let (_provider, group) = load_group(&storage)?;
    let staged = group
        .pending_commit()
        .ok_or(PendingCommitError::Malformed("no staged commit"))?;
    if group.epoch().as_u64() != bindings.epoch || binding(&group) != bindings.predecessor {
        return Err(PendingCommitError::Malformed("predecessor binding"));
    }
    let next = staged
        .epoch_authenticator()
        .ok_or(PendingCommitError::Malformed(
            "staged commit has no successor",
        ))?;
    let next_epoch = bindings
        .epoch
        .checked_add(1)
        .ok_or(PendingCommitError::Malformed("epoch"))?;
    if binding_parts(group_id, next_epoch, next.as_slice()) != bindings.successor {
        return Err(PendingCommitError::Malformed("successor binding"));
    }
    if parts.successor_original.is_some() {
        return Err(PendingCommitError::Malformed(
            "a staged record carries no successor",
        ));
    }
    let restore = match (parts.restore, parts.predecessor_original) {
        (None, None) => None,
        (Some(entries), Some(original)) => {
            let set: RestoreSet = entries
                .into_iter()
                .map(|(k, v)| (k.0.clone(), v.map(|v| v.0.clone())))
                .collect();
            let original = original.into_original()?;
            let predecessor = reverted(&storage, &set);
            let (provider, loaded) = load_group(&predecessor)?;
            wipe(&provider);
            if loaded.pending_commit().is_some() || binding(&loaded) != bindings.predecessor {
                return Err(PendingCommitError::Malformed("restore set"));
            }
            original_bytes(&original, &predecessor)?;
            Some((set, original))
        }
        _ => {
            return Err(PendingCommitError::Malformed(
                "a restore set needs the predecessor's original bytes",
            ))
        }
    };
    Ok(Body::Staged {
        storage,
        own_proposals: parts
            .own_proposals
            .into_iter()
            .map(|p| p.0.clone())
            .collect(),
        restore,
    })
}

fn legacy_body(
    group_id: &[u8],
    bindings: &Bindings,
    parts: BodyParts,
) -> Result<Body, PendingCommitError> {
    if parts.restore.is_some() {
        return Err(PendingCommitError::Malformed(
            "a legacy record carries no restore set",
        ));
    }
    let predecessor_original = parts
        .predecessor_original
        .ok_or(PendingCommitError::Malformed(
            "legacy record without originals",
        ))?
        .into_original()?;
    let successor_original = parts
        .successor_original
        .ok_or(PendingCommitError::Malformed(
            "legacy record without originals",
        ))?
        .into_original()?;
    let predecessor = state_from_entries(
        group_id,
        parts
            .predecessor_state
            .ok_or(PendingCommitError::Malformed(
                "legacy record without predecessor",
            ))?,
    );
    let successor = state_from_entries(group_id, parts.state);
    if state_binding_of(&predecessor)? != bindings.predecessor
        || state_binding_of(&successor)? != bindings.successor
    {
        return Err(PendingCommitError::Malformed("legacy binding"));
    }
    original_bytes(&predecessor_original, &predecessor)?;
    original_bytes(&successor_original, &successor)?;
    Ok(Body::LegacyMerged {
        predecessor,
        successor,
        predecessor_original,
        successor_original,
    })
}

/// A group opened for an outbound change: the provider holding its storage, the group, and the signer.
pub(crate) struct OpenedGroup {
    pub(crate) provider: OpenMlsRustCrypto,
    pub(crate) group: MlsGroup,
    pub(crate) signer: MlsSigner,
    group_id: Vec<u8>,
    /// The caller's state as given, decoded and as the bytes it arrived in.
    predecessor: GroupState,
    predecessor_raw: Zeroizing<Vec<u8>>,
}

/// Open `group_state_bytes` with the member's `bundle_bytes`, for a function that will stage a commit.
pub(crate) fn open_group(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
) -> anyhow::Result<OpenedGroup> {
    // Both inputs carry secrets; wrapping them on entry wipes them on every exit path.
    let group_state_bytes = Zeroizing::new(group_state_bytes);
    let bundle_bytes = Zeroizing::new(bundle_bytes);
    let state: GroupState = serde_json::from_slice(&group_state_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid group state: {e:?}"))?;
    let mut identity: IdentityBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid bundle: {e:?}"))?;
    let provider = OpenMlsRustCrypto::default();
    *provider.storage().values.write().unwrap() = state.storage_map.iter().cloned().collect();
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
        group_id: state.group_id.clone(),
        predecessor: state,
        predecessor_raw: group_state_bytes,
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
        predecessor,
        predecessor_raw,
    } = opened;
    let staged_commit = group
        .pending_commit()
        .ok_or_else(|| anyhow::anyhow!("no staged commit"))?;
    let next = staged_commit
        .epoch_authenticator()
        .ok_or_else(|| anyhow::anyhow!("staged commit has no successor epoch"))?;
    let predecessor_epoch = group.epoch().as_u64();
    let next_epoch = predecessor_epoch
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("epoch overflow"))?;
    let successor_binding = binding_parts(&group_id, next_epoch, next.as_slice());
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
    let commit_bytes = commit.tls_serialize_detached()?;
    // A PublicMessage commit consumed no key material, so abandoning it can return the predecessor
    // exactly: record what staging wrote, and prove here that undoing it reproduces the predecessor.
    let restore = match check_commit_framing(&commit_bytes, &group_id, group.epoch().as_u64())
        .map_err(|e| anyhow::anyhow!("{e}"))?
    {
        Some(_) => {
            let restore = restore_set(&storage, &predecessor);
            anyhow::ensure!(
                same_entries(&reverted(&storage, &restore), &predecessor),
                "staging removed a predecessor entry; the predecessor could not be restored exactly"
            );
            Some((restore, Original::capture(&predecessor_raw, &predecessor)))
        }
        None => None,
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
        commit: commit_bytes,
        welcome,
        submission: None,
        summary,
        body: Body::Staged {
            storage,
            own_proposals,
            restore,
        },
    })
}

/// How to hand a caller's state back exactly as it was given: the digest of its bytes, and either the
/// order its entries were written in, when writing them in that order reproduces the bytes, or the
/// bytes themselves. States written before encoding was sorted keep their own order this way.
struct Original {
    digest: [u8; 32],
    order: Option<Vec<u32>>,
    raw: Option<Vec<u8>>,
}

impl Drop for Original {
    fn drop(&mut self) {
        if let Some(raw) = &mut self.raw {
            raw.zeroize();
        }
    }
}

impl Original {
    fn capture(raw: &[u8], state: &GroupState) -> Self {
        let digest = Sha256::digest(raw).into();
        let mut keys: Vec<&[u8]> = state
            .storage_map
            .iter()
            .map(|(k, _)| k.as_slice())
            .collect();
        keys.sort_unstable();
        keys.dedup();
        let order: Option<Vec<u32>> = (keys.len() == state.storage_map.len())
            .then(|| {
                state
                    .storage_map
                    .iter()
                    .map(|(k, _)| {
                        keys.binary_search(&k.as_slice())
                            .ok()
                            .and_then(|i| u32::try_from(i).ok())
                    })
                    .collect()
            })
            .flatten();
        let reproduces = encode_in_order(&state.group_id, &state.storage_map)
            .is_ok_and(|bytes| bytes.as_slice() == raw);
        match order {
            Some(order) if reproduces => Self {
                digest,
                order: Some(order),
                raw: None,
            },
            _ => Self {
                digest,
                order: None,
                raw: Some(raw.to_vec()),
            },
        }
    }
}

/// The original bytes of `state`, whose entries are the original's in any order. Refused unless they
/// hash to the recorded digest.
fn original_bytes(
    original: &Original,
    state: &GroupState,
) -> Result<Zeroizing<Vec<u8>>, PendingCommitError> {
    let bytes = match (&original.raw, &original.order) {
        (Some(raw), _) => Zeroizing::new(raw.clone()),
        (None, Some(order)) => {
            let mut sorted: Vec<&(Vec<u8>, Vec<u8>)> = state.storage_map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            if order.len() != sorted.len() {
                return Err(PendingCommitError::Malformed("original order"));
            }
            let in_order = GroupState {
                group_id: state.group_id.clone(),
                storage_map: order
                    .iter()
                    .map(|&i| sorted.get(i as usize).map(|entry| (*entry).clone()))
                    .collect::<Option<_>>()
                    .ok_or(PendingCommitError::Malformed("original order"))?,
            };
            encode_in_order(&in_order.group_id, &in_order.storage_map)
                .map_err(|_| PendingCommitError::Malformed("encode state"))?
        }
        (None, None) => return Err(PendingCommitError::Malformed("original")),
    };
    if <[u8; 32]>::from(Sha256::digest(bytes.as_slice())) != original.digest {
        return Err(PendingCommitError::Malformed("original bytes"));
    }
    Ok(bytes)
}

/// A group state's encoding with its entries in the order given, as states were written before
/// encoding was sorted.
fn encode_in_order(
    group_id: &[u8],
    entries: &[(Vec<u8>, Vec<u8>)],
) -> serde_json::Result<Zeroizing<Vec<u8>>> {
    #[derive(Serialize)]
    struct InOrder<'a> {
        group_id: &'a [u8],
        storage_map: &'a [(Vec<u8>, Vec<u8>)],
    }
    serde_json::to_vec(&InOrder {
        group_id,
        storage_map: entries,
    })
    .map(Zeroizing::new)
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

/// Whether two states hold the same entries, in any order.
fn same_entries(a: &GroupState, b: &GroupState) -> bool {
    let set = |state: &GroupState| -> BTreeSet<(Vec<u8>, Vec<u8>)> {
        state.storage_map.iter().cloned().collect()
    };
    a.group_id == b.group_id && set(a) == set(b)
}

/// What staging wrote: every entry of `staged` that differs from `predecessor`, with the
/// predecessor's value, or `None` where the predecessor had no such entry.
fn restore_set(staged: &GroupState, predecessor: &GroupState) -> RestoreSet {
    let before: std::collections::HashMap<&[u8], &Vec<u8>> = predecessor
        .storage_map
        .iter()
        .map(|(k, v)| (k.as_slice(), v))
        .collect();
    staged
        .storage_map
        .iter()
        .filter(|(k, v)| before.get(k.as_slice()) != Some(&v))
        .map(|(k, _)| (k.clone(), before.get(k.as_slice()).map(|v| (*v).clone())))
        .collect()
}

/// `staged` with `restore` undone.
fn reverted(staged: &GroupState, restore: &[(Vec<u8>, Option<Vec<u8>>)]) -> GroupState {
    let undo: std::collections::HashMap<&[u8], &Option<Vec<u8>>> =
        restore.iter().map(|(k, v)| (k.as_slice(), v)).collect();
    GroupState {
        group_id: staged.group_id.clone(),
        storage_map: staged
            .storage_map
            .iter()
            .filter_map(|(k, v)| match undo.get(k.as_slice()) {
                None => Some((k.clone(), v.clone())),
                Some(Some(old)) => Some((k.clone(), old.clone())),
                Some(None) => None,
            })
            .collect(),
    }
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
    let mut entries: Vec<&(Vec<u8>, Vec<u8>)> = state.storage_map.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
        .into_iter()
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
    restore: Option<Vec<(B64, Option<B64>)>>,
    predecessor_original: Option<OriginalRepr>,
    successor_original: Option<OriginalRepr>,
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalRepr {
    digest: String,
    order: Option<Vec<u32>>,
    raw: Option<B64>,
}

impl From<&Original> for OriginalRepr {
    fn from(original: &Original) -> Self {
        Self {
            digest: hex::encode(original.digest),
            order: original.order.clone(),
            raw: original.raw.clone().map(B64),
        }
    }
}

impl OriginalRepr {
    fn into_original(self) -> Result<Original, PendingCommitError> {
        if self.order.is_some() == self.raw.is_some() {
            return Err(PendingCommitError::Malformed("original"));
        }
        Ok(Original {
            digest: hex32(&self.digest)?,
            order: self.order,
            raw: self.raw.map(|raw| raw.0.clone()),
        })
    }
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
        if self.from_epoch.checked_add(1) != Some(self.to_epoch) {
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
