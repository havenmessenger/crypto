//! A member's renewed leaf keeps its credential identity (RFC 9420 §5.3.1).
//!
//! A member replaces its own leaf by an Update proposal, or as committer by the leaf in its Commit's `UpdatePath`. The new
//! leaf may carry a new signing key (a rotation) and new encryption keys, but its credential must name the same client:
//! RFC 9420 §5.3.1 leaves it to the application to check that a replacing credential is "valid as a successor" to the
//! old one, and the MLS implementation does not. A Basic credential's identity is not bound by the leaf's signing key,
//! so without this check a member could rename its leaf to any identity, and every lookup of a member by its credential
//! (a removal by name included) would then find the wrong leaf or none.
//!
//! The successor rule here: the leaf before carries a Basic credential, and the new leaf carries a Basic credential
//! with the same identity bytes. Anything else refuses the Commit before it is merged, so the caller's state stays as it
//! was.

use openmls::credentials::Credential;
use openmls::prelude::{CredentialType, LeafNodeIndex, MlsGroup, Sender, StagedCommit};

use crate::mls::commit_refusal::CommitRefusal;

/// The words a refused Commit carries. They name no member.
pub const LEAF_IDENTITY_CHANGED: &str =
    "a member's new leaf names another credential identity than the leaf it replaces";

/// The identity a credential names: its bytes, for a Basic credential, and none for any other.
fn identity(credential: &Credential) -> Option<&[u8]> {
    (credential.credential_type() == CredentialType::Basic).then(|| credential.serialized_content())
}

/// Whether `new` may replace the credential of the leaf at `leaf` in `group`: the leaf is in the group, its credential
/// names an identity, and `new` names the same one.
fn is_successor(group: &MlsGroup, leaf: LeafNodeIndex, new: &Credential) -> bool {
    group.member_at(leaf).is_some_and(|member| {
        identity(&member.credential).is_some_and(|before| identity(new) == Some(before))
    })
}

/// Refuse `staged`, a Commit by the member at `committer` processed on `group` (the group before it is merged), when a
/// leaf it installs for an existing member names another identity than that member's leaf: the committer's `UpdatePath`
/// leaf, or the leaf of an Update proposal it covers.
pub fn require_leaf_identity_kept(
    group: &MlsGroup,
    staged: &StagedCommit,
    committer: LeafNodeIndex,
) -> Result<(), CommitRefusal> {
    if let Some(leaf) = staged.update_path_leaf_node() {
        if !is_successor(group, committer, leaf.credential()) {
            return Err(CommitRefusal::leaf_identity_changed());
        }
    }
    for update in staged.update_proposals() {
        let Sender::Member(leaf) = update.sender() else {
            return Err(CommitRefusal::leaf_identity_changed());
        };
        if !is_successor(
            group,
            *leaf,
            update.update_proposal().leaf_node().credential(),
        ) {
            return Err(CommitRefusal::leaf_identity_changed());
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "leaf_succession_tests.rs"]
pub mod tests;
