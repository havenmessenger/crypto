//! Real openmls groups for the targeted-message tests: every member owns its provider (and so its
//! own storage), exactly as separate devices do.

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use tls_codec::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::mls::MlsSigner;

pub(super) fn suite() -> Ciphersuite {
    crate::suite_policy::mls_generation_suite()
}

pub(super) struct Peer {
    pub provider: OpenMlsRustCrypto,
    pub signer: MlsSigner,
    pub credential_with_key: CredentialWithKey,
    pub group: Option<MlsGroup>,
}

impl Peer {
    pub fn new(name: &str, suite: Ciphersuite) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let scheme = suite.signature_algorithm();
        let (private, public) = provider
            .crypto()
            .signature_key_gen(scheme)
            .expect("signature key generation");
        let credential = BasicCredential::new(name.as_bytes().to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: SignaturePublicKey::from(public),
        };
        Self {
            provider,
            signer: MlsSigner {
                key: Zeroizing::new(private),
                scheme,
            },
            credential_with_key,
            group: None,
        }
    }

    pub fn key_package(&self, suite: Ciphersuite) -> KeyPackage {
        KeyPackage::builder()
            .build(
                suite,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .expect("key package")
            .key_package()
            .clone()
    }

    pub fn group(&self) -> &MlsGroup {
        self.group.as_ref().expect("member is in a group")
    }

    pub fn leaf(&self) -> LeafNodeIndex {
        self.group().own_leaf_index()
    }

    /// Create a group and add `others` in one commit; every member ends in the same epoch.
    pub fn found(&mut self, suite: Ciphersuite, others: &mut [&mut Peer]) {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(suite)
            .use_ratchet_tree_extension(true)
            .build();
        let mut group = MlsGroup::new(
            &self.provider,
            &self.signer,
            &config,
            self.credential_with_key.clone(),
        )
        .expect("create group");
        let packages: Vec<KeyPackage> = others.iter().map(|m| m.key_package(suite)).collect();
        let (_commit, welcome, _info) = group
            .add_members(&self.provider, &self.signer, &packages)
            .expect("add members");
        group
            .merge_pending_commit(&self.provider)
            .expect("merge commit");
        let welcome_bytes = welcome.tls_serialize_detached().expect("welcome bytes");
        for member in others.iter_mut() {
            member.join(&welcome_bytes);
        }
        self.group = Some(group);
    }

    pub fn join(&mut self, welcome_bytes: &[u8]) {
        let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes).expect("welcome message");
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            panic!("not a welcome");
        };
        let config = MlsGroupJoinConfig::builder().build();
        let staged = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .expect("stage welcome");
        self.group = Some(staged.into_group(&self.provider).expect("join"));
    }

    /// Commit an update of this member's own leaf and return the commit bytes.
    pub fn self_update(&mut self) -> Vec<u8> {
        let provider = &self.provider;
        let signer = &self.signer;
        let group = self.group.as_mut().expect("group");
        let bundle = group
            .self_update(provider, signer, LeafNodeParameters::default())
            .expect("self update");
        group.merge_pending_commit(provider).expect("merge update");
        bundle
            .commit()
            .tls_serialize_detached()
            .expect("commit bytes")
    }

    /// Commit the removal of the member at `leaf` and return the commit bytes.
    pub fn remove(&mut self, leaf: LeafNodeIndex) -> Vec<u8> {
        let provider = &self.provider;
        let signer = &self.signer;
        let group = self.group.as_mut().expect("group");
        let (commit, _welcome, _info) = group
            .remove_members(provider, signer, &[leaf])
            .expect("remove member");
        group.merge_pending_commit(provider).expect("merge removal");
        commit.tls_serialize_detached().expect("commit bytes")
    }

    /// Apply another member's commit.
    pub fn apply(&mut self, commit_bytes: &[u8]) {
        let provider = &self.provider;
        let group = self.group.as_mut().expect("group");
        let message = MlsMessageIn::tls_deserialize_exact(commit_bytes).expect("commit message");
        let protocol = ProtocolMessage::try_from(message).expect("protocol message");
        let processed = group.process_message(provider, protocol).expect("process");
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("not a commit");
        };
        group
            .merge_staged_commit(provider, *staged)
            .expect("merge staged commit");
    }
}

/// Three members in one group: A (leaf 0), B (leaf 1), C (leaf 2).
pub(super) fn three() -> (Peer, Peer, Peer) {
    let suite = suite();
    let mut a = Peer::new("a", suite);
    let mut b = Peer::new("b", suite);
    let mut c = Peer::new("c", suite);
    a.found(suite, &mut [&mut b, &mut c]);
    (a, b, c)
}
