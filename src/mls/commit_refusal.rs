//! Why a Commit was not applied, as a closed reason a caller can match, with the MLS implementation's words kept.
//!
//! The reason is decided here by a match over every variant of the MLS implementation's refusals, with no catch-all
//! arm, so a release of the implementation that adds a variant fails this crate's build until someone decides what
//! the new variant means. Anything that names no reason a caller acts on is [`CommitRefusalReason::Other`], and the
//! words still say what happened.

use std::fmt;

use openmls::prelude::{
    KeyPackageVerifyError, MergeCommitError, ProcessMessageError, ProposalValidationError,
    StageCommitError, ValidationError,
};
use openmls::treesync::errors::LeafNodeValidationError;

/// What a refused Commit's refusal says about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommitRefusalReason {
    /// The Commit is for another epoch than the one this member's copy of the group is at.
    WrongEpoch,
    /// A `KeyPackage` or leaf in the Commit carries a lifetime that does not hold now.
    Lifetime,
    /// A signature in the Commit did not verify.
    Signature,
    /// The Commit needs a capability, extension, ciphersuite, version or proposal type this group does not support.
    Capabilities,
    /// A credential in the Commit was not accepted.
    Credential,
    /// The Commit's membership or confirmation tag does not match this member's copy of the group.
    TagMismatch,
    /// None of the above; the words say what.
    Other,
}

/// A Commit [`crate::mimi::mls_process_commit_appsync_with`] did not apply.
///
/// It reads exactly as the refusal read before it was typed (`Processing error: ` or `Error merging staged commit: `
/// followed by the refusal's Debug), so text read from it is unchanged. A caller holding the `anyhow::Error` can
/// `downcast_ref` to this type and match [`CommitRefusal::reason`] rather than read the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRefusal {
    reason: CommitRefusalReason,
    words: String,
}

impl CommitRefusal {
    /// A Commit the MLS implementation refused to process.
    pub(crate) fn processing<S: fmt::Debug>(refusal: &ProcessMessageError<S>) -> Self {
        Self {
            reason: of_processing(refusal),
            words: format!("Processing error: {refusal:?}"),
        }
    }

    /// A Commit the MLS implementation processed and then could not merge.
    pub(crate) fn merging<S: fmt::Debug>(refusal: &MergeCommitError<S>) -> Self {
        Self {
            reason: of_merging(refusal),
            words: format!("Error merging staged commit: {refusal:?}"),
        }
    }

    /// What the refusal says about the Commit.
    #[must_use]
    pub const fn reason(&self) -> CommitRefusalReason {
        self.reason
    }
}

impl fmt::Display for CommitRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.words)
    }
}

/// The text is the whole report, as it is for every other error here, so the refusal is not also given as a source.
impl std::error::Error for CommitRefusal {}

const fn of_processing<S>(refusal: &ProcessMessageError<S>) -> CommitRefusalReason {
    use CommitRefusalReason::{Capabilities, Other};
    match refusal {
        ProcessMessageError::ValidationError(refusal) => of_validation(refusal),
        ProcessMessageError::InvalidCommit(refusal) => of_staging(refusal),
        ProcessMessageError::UnsupportedProposalType => Capabilities,
        ProcessMessageError::LibraryError(_)
        | ProcessMessageError::StorageError(_)
        | ProcessMessageError::IncompatibleWireFormat
        | ProcessMessageError::GroupStateError(_)
        | ProcessMessageError::UnauthorizedExternalApplicationMessage
        | ProcessMessageError::UnauthorizedExternalCommitMessage => Other,
    }
}

const fn of_validation(refusal: &ValidationError) -> CommitRefusalReason {
    use CommitRefusalReason::{Capabilities, Other, Signature, TagMismatch, WrongEpoch};
    match refusal {
        ValidationError::WrongEpoch | ValidationError::NoPastEpochData => WrongEpoch,
        ValidationError::InvalidMembershipTag => TagMismatch,
        ValidationError::InvalidSignature | ValidationError::InvalidLeafNodeSignature => Signature,
        ValidationError::KeyPackageVerifyError(refusal) => of_key_package(refusal),
        ValidationError::InvalidAddProposalCiphersuite | ValidationError::InvalidExtension(_) => {
            Capabilities
        }
        ValidationError::LibraryError(_)
        | ValidationError::WrongGroupId
        | ValidationError::NotACommit
        | ValidationError::NotAnExternalAddProposal
        | ValidationError::NoPath
        | ValidationError::UnencryptedApplicationMessage
        | ValidationError::UnknownMember
        | ValidationError::MissingMembershipTag
        | ValidationError::MissingConfirmationTag
        | ValidationError::WrongWireFormat
        | ValidationError::NonMemberApplicationMessage
        | ValidationError::UnableToDecrypt(_)
        | ValidationError::UnauthorizedExternalSender
        | ValidationError::NoExternalSendersExtension
        | ValidationError::UpdatePathError(_)
        | ValidationError::InvalidLeafNodeSourceType
        | ValidationError::InvalidSenderType
        | ValidationError::CommitterIncludedOwnUpdate
        | ValidationError::ExternalCommitValidation(_) => Other,
    }
}

const fn of_staging(refusal: &StageCommitError) -> CommitRefusalReason {
    use CommitRefusalReason::{Capabilities, Other, Signature, TagMismatch, WrongEpoch};
    match refusal {
        StageCommitError::EpochMismatch => WrongEpoch,
        StageCommitError::ConfirmationTagMismatch => TagMismatch,
        StageCommitError::PathLeafNodeVerificationFailure => Signature,
        StageCommitError::ProposalValidationError(refusal) => of_proposal(refusal),
        StageCommitError::LeafNodeValidation(refusal) => of_leaf_node(refusal),
        StageCommitError::GroupContextExtensionsProposalValidationError(_) => Capabilities,
        StageCommitError::LibraryError(_)
        | StageCommitError::OwnCommitMismatch
        | StageCommitError::WrongPlaintextContentType
        | StageCommitError::RequiredPathNotFound
        | StageCommitError::ConfirmationTagMissing
        | StageCommitError::AttemptedSelfRemoval
        | StageCommitError::MissingProposal
        | StageCommitError::OwnKeyNotFound
        | StageCommitError::InconsistentSenderIndex
        | StageCommitError::SenderTypeExternal
        | StageCommitError::SenderTypeNewMemberProposal
        | StageCommitError::TooManyNewMembers
        | StageCommitError::PskError(_)
        | StageCommitError::ExternalCommitValidation(_)
        | StageCommitError::UpdatePathError(_)
        | StageCommitError::MissingDecryptionKey
        | StageCommitError::VerifiedUpdatePathError(_)
        | StageCommitError::DuplicatePskId(_) => Other,
    }
}

const fn of_proposal(refusal: &ProposalValidationError) -> CommitRefusalReason {
    use CommitRefusalReason::{Capabilities, Other};
    match refusal {
        ProposalValidationError::LeafNodeValidation(refusal) => of_leaf_node(refusal),
        ProposalValidationError::InsufficientCapabilities
        | ProposalValidationError::InvalidAddProposalCiphersuiteOrVersion
        | ProposalValidationError::UnsupportedProposalType
        | ProposalValidationError::ReInitUnsupportedVersion => Capabilities,
        ProposalValidationError::LibraryError(_)
        | ProposalValidationError::UnknownMember
        | ProposalValidationError::DuplicateSignatureKey
        | ProposalValidationError::DuplicateEncryptionKey
        | ProposalValidationError::DuplicateInitKey
        | ProposalValidationError::InitEncryptionKeyCollision
        | ProposalValidationError::DuplicateMemberRemoval
        | ProposalValidationError::UnknownMemberRemoval
        | ProposalValidationError::UpdateFromNonMember
        | ProposalValidationError::CommitterIncludedOwnUpdate
        | ProposalValidationError::Psk(_)
        | ProposalValidationError::ExternalInitProposalInRegularCommit
        | ProposalValidationError::ReInitProposalNotAlone
        | ProposalValidationError::ReInitDowngrade => Other,
    }
}

const fn of_leaf_node(refusal: &LeafNodeValidationError) -> CommitRefusalReason {
    use CommitRefusalReason::{Capabilities, Credential, Lifetime, Other};
    match refusal {
        LeafNodeValidationError::Lifetime(_) => Lifetime,
        LeafNodeValidationError::UnsupportedExtensions
        | LeafNodeValidationError::UnsupportedProposals
        | LeafNodeValidationError::ExtensionsNotInCapabilities
        | LeafNodeValidationError::CiphersuiteNotInCapabilities => Capabilities,
        LeafNodeValidationError::UnsupportedCredentials
        | LeafNodeValidationError::CredentialNotInCapabilities
        | LeafNodeValidationError::LeafNodeCredentialNotSupportedByMember
        | LeafNodeValidationError::MemberCredentialNotSupportedByLeafNode => Credential,
        LeafNodeValidationError::SignatureKeyAlreadyInUse
        | LeafNodeValidationError::EncryptionKeyAlreadyInUse
        | LeafNodeValidationError::InvalidLeafNodeSource => Other,
    }
}

const fn of_key_package(refusal: &KeyPackageVerifyError) -> CommitRefusalReason {
    use CommitRefusalReason::{Capabilities, Lifetime, Other, Signature};
    match refusal {
        KeyPackageVerifyError::LifetimeError(_) | KeyPackageVerifyError::MissingLifetime => {
            Lifetime
        }
        KeyPackageVerifyError::InvalidSignature
        | KeyPackageVerifyError::InvalidLeafNodeSignature => Signature,
        KeyPackageVerifyError::UnsupportedExtension
        | KeyPackageVerifyError::InvalidProtocolVersion
        | KeyPackageVerifyError::UnsupportedCiphersuite(_)
        | KeyPackageVerifyError::ExtensionTypeNotValidInKeyPackage(_) => Capabilities,
        KeyPackageVerifyError::LibraryError(_)
        | KeyPackageVerifyError::InvalidLeafNodeSourceType
        | KeyPackageVerifyError::InitKeyEqualsEncryptionKey => Other,
    }
}

const fn of_merging<S>(refusal: &MergeCommitError<S>) -> CommitRefusalReason {
    match refusal {
        MergeCommitError::LibraryError(_) | MergeCommitError::StorageError(_) => {
            CommitRefusalReason::Other
        }
    }
}

#[cfg(test)]
#[path = "commit_refusal_tests.rs"]
mod tests;
