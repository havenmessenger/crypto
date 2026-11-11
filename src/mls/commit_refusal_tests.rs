use super::{CommitRefusal, CommitRefusalReason};
use crate::mimi::{
    complete_welcome, mimi_add_member, mimi_add_member_commit_appsync, mimi_create_group,
    mimi_generate_identity, mls_process_commit_appsync, prepare_welcome_retirement,
};
use openmls::prelude::{
    KeyPackageVerifyError, MergeCommitError, ProcessMessageError, ProposalValidationError,
    StageCommitError, ValidationError,
};
use openmls::treesync::errors::{LeafNodeValidationError, LifetimeError};
use openmls_rust_crypto::MemoryStorageError;

fn processing(refusal: ProcessMessageError<MemoryStorageError>) -> CommitRefusal {
    CommitRefusal::processing(&refusal)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
        .try_into()
        .expect("a clock before 2262")
}

/// Each reason a caller acts on is reached from the refusal the MLS implementation gives for it, at whatever depth the
/// implementation nests it, and the words are the refusal's Debug as they were before it was typed.
#[test]
fn each_refusal_reads_as_its_reason_and_keeps_its_words() {
    let lapsed = || LifetimeError::Expired {
        not_after: 1,
        now: 2,
    };
    let cases = [
        (
            processing(ProcessMessageError::ValidationError(
                ValidationError::WrongEpoch,
            )),
            CommitRefusalReason::WrongEpoch,
        ),
        (
            processing(ProcessMessageError::InvalidCommit(
                StageCommitError::EpochMismatch,
            )),
            CommitRefusalReason::WrongEpoch,
        ),
        (
            processing(ProcessMessageError::InvalidCommit(
                StageCommitError::ProposalValidationError(
                    ProposalValidationError::LeafNodeValidation(LeafNodeValidationError::Lifetime(
                        lapsed(),
                    )),
                ),
            )),
            CommitRefusalReason::Lifetime,
        ),
        (
            processing(ProcessMessageError::ValidationError(
                ValidationError::KeyPackageVerifyError(KeyPackageVerifyError::LifetimeError(
                    lapsed(),
                )),
            )),
            CommitRefusalReason::Lifetime,
        ),
        (
            processing(ProcessMessageError::InvalidCommit(
                StageCommitError::PathLeafNodeVerificationFailure,
            )),
            CommitRefusalReason::Signature,
        ),
        (
            processing(ProcessMessageError::ValidationError(
                ValidationError::InvalidSignature,
            )),
            CommitRefusalReason::Signature,
        ),
        (
            processing(ProcessMessageError::InvalidCommit(
                StageCommitError::ProposalValidationError(
                    ProposalValidationError::InsufficientCapabilities,
                ),
            )),
            CommitRefusalReason::Capabilities,
        ),
        (
            processing(ProcessMessageError::InvalidCommit(
                StageCommitError::LeafNodeValidation(
                    LeafNodeValidationError::MemberCredentialNotSupportedByLeafNode,
                ),
            )),
            CommitRefusalReason::Credential,
        ),
        (
            processing(ProcessMessageError::ValidationError(
                ValidationError::InvalidMembershipTag,
            )),
            CommitRefusalReason::TagMismatch,
        ),
        (
            processing(ProcessMessageError::InvalidCommit(
                StageCommitError::ConfirmationTagMismatch,
            )),
            CommitRefusalReason::TagMismatch,
        ),
        (
            processing(ProcessMessageError::InvalidCommit(
                StageCommitError::MissingProposal,
            )),
            CommitRefusalReason::Other,
        ),
    ];
    for (refusal, reason) in cases {
        assert_eq!(refusal.reason(), reason, "{refusal}");
    }
    assert_eq!(
        processing(ProcessMessageError::InvalidCommit(
            StageCommitError::ConfirmationTagMismatch
        ))
        .to_string(),
        "Processing error: InvalidCommit(ConfirmationTagMismatch)"
    );
    let merging = CommitRefusal::merging(&MergeCommitError::<MemoryStorageError>::StorageError(
        MemoryStorageError::SerializationError,
    ));
    assert_eq!(merging.reason(), CommitRefusalReason::Other);
    assert_eq!(
        merging.to_string(),
        "Error merging staged commit: StorageError(SerializationError)"
    );
}

/// A Commit read a second time, after the member applied it, is refused for its epoch, and the caller reads that from
/// the error it holds without reading the text.
#[test]
fn a_commit_applied_twice_is_refused_for_its_epoch() {
    let now = now_secs();
    let (_, _, alice) = mimi_generate_identity("alice@refusal.test".into(), now).expect("alice");
    let (_, bob_key_package, bob) =
        mimi_generate_identity("bob@refusal.test".into(), now).expect("bob");
    let (_, carol_key_package, carol) =
        mimi_generate_identity("carol@refusal.test".into(), now).expect("carol");
    let group = mimi_create_group("refusal".into(), alice.clone()).expect("create_group");
    let (group, welcome_bob) =
        mimi_add_member(group, alice.clone(), bob_key_package).expect("add bob");
    let prepared = prepare_welcome_retirement(welcome_bob, bob.clone(), Vec::new(), String::new())
        .expect("bob's welcome");
    let (bob_state, _) = complete_welcome(prepared).expect("bob joins");
    let (_, welcome_carol, commit) =
        mimi_add_member_commit_appsync(group, alice, carol_key_package, vec![1])
            .expect("add carol");
    let prepared = prepare_welcome_retirement(welcome_carol, carol, Vec::new(), String::new())
        .expect("carol's welcome");
    complete_welcome(prepared).expect("carol joins");
    let (bob_state, _, _) = mls_process_commit_appsync(bob_state, bob.clone(), commit.clone())
        .expect("bob applies the add");

    let error = mls_process_commit_appsync(bob_state, bob, commit).expect_err("applied already");
    let refusal = error
        .downcast_ref::<CommitRefusal>()
        .expect("the refusal is typed");
    assert_eq!(
        refusal.reason(),
        CommitRefusalReason::WrongEpoch,
        "{refusal}"
    );
    assert!(
        error.to_string().starts_with("Processing error: "),
        "the words are as before: {error}"
    );
}
