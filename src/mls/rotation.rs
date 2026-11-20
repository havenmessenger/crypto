//! A member replacing its leaf's signing key in a group (RFC 9420 §12.1.2, an `UpdatePath` that carries a new leaf).
//!
//! [`rotate_signer_pending`] stages one commit that does what [`super::groups::self_update_pending`] does, new leaf
//! encryption keys and a new epoch, and also moves the leaf to the signature key of `new_bundle_bytes`. Once every
//! other member has processed it they verify this member's messages under the new key only, so a signing key taken
//! with a lost device stops being accepted in the group.
//!
//! The commit itself is signed with the member's current key, since receivers verify a commit against the
//! committer's leaf as it stood before the commit; the leaf it installs, and any `GroupInfo` for the new epoch, carry
//! the new key. A caller therefore keeps the current key until the group has accepted the commit, and opens the group
//! with `new_bundle_bytes` from then on.

use std::mem;

use openmls::credentials::{BasicCredential, CredentialWithKey, NewSignerBundle};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use zeroize::Zeroizing;

use crate::mls::pending::{open_group, staged, PendingCommit};
use crate::mls::{IdentityBundle, MlsSigner};

/// Stage a commit that renews this member's leaf and replaces its signing key with `new_bundle_bytes`' key. Refused,
/// with nothing staged, when the new bundle names another user than the leaf's credential or uses another signature
/// scheme than the group's ciphersuite.
pub fn rotate_signer_pending(
    group_state_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    new_bundle_bytes: Vec<u8>,
) -> anyhow::Result<PendingCommit> {
    // The new bundle carries a private key; wrapping it on entry wipes it on every exit path.
    let new_bundle_bytes = Zeroizing::new(new_bundle_bytes);
    let mut new_identity: IdentityBundle = serde_json::from_slice(&new_bundle_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid new bundle: {e:?}"))?;
    let mut opened = open_group(group_state_bytes, bundle_bytes)?;

    let credential = opened
        .group
        .own_leaf_node()
        .ok_or_else(|| anyhow::anyhow!("This member has no leaf in the group"))?
        .credential()
        .clone();
    let named = BasicCredential::try_from(credential.clone())
        .map_err(|e| anyhow::anyhow!("The leaf's credential is not a basic credential: {e:?}"))?;
    if named.identity() != new_identity.user_id.as_bytes() {
        anyhow::bail!("The new bundle names another user than this member's leaf");
    }
    let scheme = opened.group.ciphersuite().signature_algorithm();
    if new_identity.signature_scheme != scheme {
        anyhow::bail!("The new bundle's signature scheme is not the group's");
    }
    let new_signer = MlsSigner {
        key: Zeroizing::new(mem::take(&mut new_identity.private_key)),
        scheme,
    };
    let signature_key = mem::take(&mut new_identity.public_key_bytes);

    let bundle = opened
        .group
        .commit_builder()
        .leaf_node_parameters(LeafNodeParameters::default())
        .consume_proposal_store(true)
        .load_psks(opened.provider.storage())
        .map_err(|e| anyhow::anyhow!("Error loading PSKs: {e:?}"))?
        .build_with_new_signer(
            opened.provider.rand(),
            opened.provider.crypto(),
            &opened.signer,
            NewSignerBundle {
                signer: &new_signer,
                credential_with_key: CredentialWithKey {
                    credential,
                    signature_key: signature_key.into(),
                },
            },
            |_| true,
        )
        .map_err(|e| anyhow::anyhow!("Error building the rotation commit: {e:?}"))?
        .stage_commit(&opened.provider)
        .map_err(|e| anyhow::anyhow!("Error staging the rotation commit: {e:?}"))?;
    let (commit, _welcome, _group_info) = bundle.into_messages();
    staged(opened, &commit, None, &[])
}

#[cfg(test)]
#[path = "rotation_tests.rs"]
mod tests;
