//! MLS targeted messages: `draft-ietf-mls-targeted-messages-01`.
//!
//! A targeted message carries an application payload from one member of an MLS group to exactly one
//! other member, so no third member can read it. The payload is encrypted with HPKE in PSK mode to
//! the recipient's leaf encryption key, with a pre-shared key exported from the epoch's key
//! schedule, and is signed by the sender's leaf signature key. The sender's identity travels
//! encrypted under a second exporter-derived secret, keyed by a sample of the ciphertext.
//!
//! [`seal`] performs the sender steps of section 6 in the draft's order; [`open`] performs the
//! recipient steps of section 7 in the draft's order. The message is bound to the current epoch:
//! a message for any other epoch is refused, and nothing is retained for past epochs. The
//! signature is verified before any content decryption, and no plaintext is released unless every
//! step succeeded.
//!
//! The result of [`seal`] is a versioned [`wire::Envelope`] (see that module for why the draft's
//! `MLSMessage` framing is not used). All algorithms come from the group's ciphersuite through
//! `crate::suite_policy::targeted_message_suite`.
//!
//! A targeted message has no replay protection of its own (draft section 8.6): an application that
//! needs it puts a unique value in `authenticated_data` and tracks the values it has seen.
//! Forward secrecy is per epoch: compromise of the recipient's leaf key within the epoch exposes
//! the targeted messages of that epoch.

mod hpke;
mod labels;
mod leaf_key;
pub mod wire;

#[cfg(test)]
mod tests;

use openmls::prelude::{LeafNodeIndex, MlsGroup};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize, VLBytes};
use zeroize::Zeroizing;

use crate::mls::MAX_MLS_WIRE_BYTES;
use crate::suite_policy::{targeted_message_suite, TargetedSuite};
use wire::{
    from_bytes_exact, to_bytes, Envelope, HpkeContext, PskId, SenderAuthData, SenderAuthDataAad,
    TargetedMessage, Tbm, Tbs, DRAFT_VERSION_01, HPKE_CONTEXT_LABEL, PROTOCOL_VERSION_MLS10,
    PSK_LABEL, WIRE_FORMAT_TARGETED_MESSAGE,
};

/// Exporter label shared by both derived secrets (draft section 5).
const EXPORTER_LABEL: &str = "targeted message";
const EXPORTER_CONTEXT_PSK: &[u8] = b"psk";
const EXPORTER_CONTEXT_SENDER_AUTH: &[u8] = b"sender auth data secret";
const SIGN_LABEL: &str = "TargetedMessageTBS";

/// Largest `authenticated_data` accepted by [`seal`].
pub const MAX_AUTHENTICATED_DATA_BYTES: usize = 64 * 1024;
/// Largest application data plus padding accepted by [`seal`].
pub const MAX_CONTENT_BYTES: usize = 512 * 1024;

/// Why [`seal`] refused. No variant carries secret material or content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    #[error("the group's ciphersuite is not accepted for targeted messages")]
    Suite,
    #[error("the signer's signature scheme does not match the group's ciphersuite")]
    SignerScheme,
    #[error("authenticated data or content is larger than the allowed maximum")]
    TooLarge,
    #[error("the recipient is not a member of the group, or is this member")]
    Recipient,
    #[error("the epoch's exporter secrets are not available")]
    Export,
    #[error("the HPKE encryption failed")]
    Encrypt,
    #[error("signing failed")]
    Sign,
    #[error("the sender authentication data could not be encrypted")]
    SenderAuthData,
    #[error("the message could not be serialized")]
    Serialize,
}

/// Why [`open`] refused: one variant per step of the draft's recipient validation, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    #[error("the group's ciphersuite is not accepted for targeted messages")]
    Suite,
    #[error("the envelope is larger than the allowed maximum")]
    TooLarge,
    #[error("the envelope or the message inside it is malformed")]
    Malformed,
    #[error("the envelope names a draft version this library does not implement")]
    UnsupportedVersion,
    #[error("the message is for a different group")]
    GroupMismatch,
    #[error("the message is not for the group's current epoch")]
    EpochNotCurrent,
    #[error("the message is addressed to a different member")]
    NotForThisMember,
    #[error("the epoch's exporter secrets are not available")]
    Export,
    #[error("the sender authentication data could not be decrypted")]
    SenderAuthData,
    #[error("the sender is not a member of the group")]
    SenderLeaf,
    #[error("the sender's signature is invalid")]
    Signature,
    #[error("this member's leaf decryption key is not available")]
    LeafKey,
    #[error("the content could not be decrypted")]
    Decrypt,
    #[error("the padding is not all zero")]
    Padding,
}

/// A message that passed every validation step.
pub struct Opened {
    /// The leaf index of the sender, authenticated by its signature.
    pub sender_leaf_index: u32,
    pub authenticated_data: Vec<u8>,
    pub application_data: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("sender_leaf_index", &self.sender_leaf_index)
            .field("authenticated_data_len", &self.authenticated_data.len())
            .field("application_data_len", &self.application_data.len())
            .finish()
    }
}

/// The two exporter-derived secrets of an epoch.
struct EpochSecrets {
    psk: Zeroizing<Vec<u8>>,
    sender_auth_data: Zeroizing<Vec<u8>>,
}

fn epoch_secrets(
    crypto: &impl OpenMlsCrypto,
    group: &MlsGroup,
    suite: &TargetedSuite,
) -> Option<EpochSecrets> {
    let psk = group
        .export_secret(crypto, EXPORTER_LABEL, EXPORTER_CONTEXT_PSK, suite.kdf_nh)
        .ok()?;
    let sender_auth_data = group
        .export_secret(
            crypto,
            EXPORTER_LABEL,
            EXPORTER_CONTEXT_SENDER_AUTH,
            suite.kdf_nh,
        )
        .ok()?;
    Some(EpochSecrets {
        psk: Zeroizing::new(psk),
        sender_auth_data: Zeroizing::new(sender_auth_data),
    })
}

/// An AEAD key and its nonce.
type KeyAndNonce = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

/// The AEAD key and nonce protecting the sender authentication data, from a sample of the content
/// ciphertext (draft section 6.3).
fn sender_auth_key_nonce(
    crypto: &impl OpenMlsCrypto,
    suite: &TargetedSuite,
    secret: &[u8],
    ciphertext: &[u8],
) -> Option<KeyAndNonce> {
    let sample = &ciphertext[..ciphertext.len().min(suite.kdf_nh)];
    let key = labels::expand_with_label(crypto, suite.hash, secret, "key", sample, suite.aead_nk)?;
    let nonce =
        labels::expand_with_label(crypto, suite.hash, secret, "nonce", sample, suite.aead_nn)?;
    Some((key, nonce))
}

fn psk_id(group_id: &[u8], epoch: u64) -> Option<Vec<u8>> {
    to_bytes(&PskId {
        group_id,
        epoch,
        label: PSK_LABEL,
    })
}

fn hpke_info() -> Option<Vec<u8>> {
    to_bytes(&HpkeContext {
        label: HPKE_CONTEXT_LABEL,
        context: b"",
    })
}

/// Seal `application_data` (plus `padding_len` zero bytes) to `recipient`, a member of `group`'s
/// current epoch, signed by `signer` as this member. `authenticated_data` is carried in the clear
/// and authenticated.
pub fn seal<P: OpenMlsProvider>(
    provider: &P,
    group: &MlsGroup,
    signer: &impl Signer,
    recipient: LeafNodeIndex,
    authenticated_data: &[u8],
    application_data: &[u8],
    padding_len: usize,
) -> Result<Vec<u8>, SealError> {
    let suite = targeted_message_suite(group.ciphersuite()).map_err(|_| SealError::Suite)?;
    if signer.signature_scheme() != suite.signature {
        return Err(SealError::SignerScheme);
    }
    let content_len = application_data
        .len()
        .checked_add(padding_len)
        .ok_or(SealError::TooLarge)?;
    if authenticated_data.len() > MAX_AUTHENTICATED_DATA_BYTES || content_len > MAX_CONTENT_BYTES {
        return Err(SealError::TooLarge);
    }
    if recipient == group.own_leaf_index() || group.member_at(recipient).is_none() {
        return Err(SealError::Recipient);
    }

    // Sized once so the buffer never reallocates and leaves an unwiped copy behind.
    let mut content = Zeroizing::new(Vec::with_capacity(content_len + 8));
    content.extend_from_slice(
        &to_bytes(&VLBytes::new(application_data.to_vec())).ok_or(SealError::Serialize)?,
    );
    let padded_len = content.len() + padding_len;
    content.resize(padded_len, 0);
    seal_content(
        provider,
        group,
        signer,
        recipient,
        authenticated_data,
        &content,
    )
}

/// Steps of draft section 6.2 and 6.3 over an already-encoded `TargetedMessageContent`.
fn seal_content<P: OpenMlsProvider>(
    provider: &P,
    group: &MlsGroup,
    signer: &impl Signer,
    recipient: LeafNodeIndex,
    authenticated_data: &[u8],
    content: &[u8],
) -> Result<Vec<u8>, SealError> {
    let suite = targeted_message_suite(group.ciphersuite()).map_err(|_| SealError::Suite)?;
    let sender = group.own_leaf_index();
    let recipient_key = group
        .member_at(recipient)
        .ok_or(SealError::Recipient)?
        .encryption_key;
    let crypto = provider.crypto();
    let group_id = group.group_id().as_slice();
    let epoch = group.epoch().as_u64();
    let secrets = epoch_secrets(crypto, group, &suite).ok_or(SealError::Export)?;

    let psk_id = psk_id(group_id, epoch).ok_or(SealError::Serialize)?;
    let info = hpke_info().ok_or(SealError::Serialize)?;
    let (kem_output, ciphertext) = hpke::seal(
        &suite,
        &recipient_key,
        &info,
        &secrets.psk,
        &psk_id,
        |kem_output| {
            to_bytes(&Tbm {
                group_id,
                epoch,
                recipient_leaf_index: recipient.u32(),
                authenticated_data,
                sender_leaf_index: sender.u32(),
                kem_output,
            })
        },
        content,
    )
    .map_err(|_| SealError::Encrypt)?;

    let ciphertext_hash = crypto
        .hash(suite.hash, &ciphertext)
        .map_err(|_| SealError::Sign)?;
    let tbs = to_bytes(&Tbs {
        version: PROTOCOL_VERSION_MLS10,
        wire_format: WIRE_FORMAT_TARGETED_MESSAGE,
        group_id,
        epoch,
        recipient_leaf_index: recipient.u32(),
        authenticated_data,
        sender_leaf_index: sender.u32(),
        kem_output: &kem_output,
        ciphertext_hash: &ciphertext_hash,
    })
    .ok_or(SealError::Serialize)?;
    let signature = labels::sign_with_label(signer, SIGN_LABEL, &tbs).ok_or(SealError::Sign)?;

    let sender_auth_data = Zeroizing::new(
        to_bytes(&SenderAuthData {
            sender_leaf_index: sender.u32(),
            signature: VLBytes::new(signature),
            kem_output: VLBytes::new(kem_output),
        })
        .ok_or(SealError::Serialize)?,
    );
    let (key, nonce) =
        sender_auth_key_nonce(crypto, &suite, &secrets.sender_auth_data, &ciphertext)
            .ok_or(SealError::SenderAuthData)?;
    let aad = to_bytes(&SenderAuthDataAad {
        group_id,
        epoch,
        recipient_leaf_index: recipient.u32(),
    })
    .ok_or(SealError::Serialize)?;
    let encrypted_sender_auth_data = crypto
        .aead_encrypt(suite.aead, &key, &sender_auth_data, &nonce, &aad)
        .map_err(|_| SealError::SenderAuthData)?;

    let message = to_bytes(&TargetedMessage {
        group_id: VLBytes::new(group_id.to_vec()),
        epoch,
        recipient_leaf_index: recipient.u32(),
        authenticated_data: VLBytes::new(authenticated_data.to_vec()),
        encrypted_sender_auth_data: VLBytes::new(encrypted_sender_auth_data),
        ciphertext: VLBytes::new(ciphertext),
    })
    .ok_or(SealError::Serialize)?;
    to_bytes(&Envelope {
        draft_version: DRAFT_VERSION_01,
        targeted_message: VLBytes::new(message),
    })
    .ok_or(SealError::Serialize)
}

/// Step "decrypt `encrypted_sender_auth_data`" of the recipient validation.
fn decrypt_sender_auth(
    crypto: &impl OpenMlsCrypto,
    suite: &TargetedSuite,
    secrets: &EpochSecrets,
    message: &TargetedMessage,
) -> Result<SenderAuthData, OpenError> {
    let (key, nonce) = sender_auth_key_nonce(
        crypto,
        suite,
        &secrets.sender_auth_data,
        message.ciphertext.as_slice(),
    )
    .ok_or(OpenError::SenderAuthData)?;
    let aad = to_bytes(&SenderAuthDataAad {
        group_id: message.group_id.as_slice(),
        epoch: message.epoch,
        recipient_leaf_index: message.recipient_leaf_index,
    })
    .ok_or(OpenError::Malformed)?;
    let decrypted = Zeroizing::new(
        crypto
            .aead_decrypt(
                suite.aead,
                &key,
                message.encrypted_sender_auth_data.as_slice(),
                &nonce,
                &aad,
            )
            .map_err(|_| OpenError::SenderAuthData)?,
    );
    from_bytes_exact(&decrypted).ok_or(OpenError::SenderAuthData)
}

/// Steps "sender leaf is non-blank" and "verify the signature" of the recipient validation.
fn authenticate_sender(
    crypto: &impl OpenMlsCrypto,
    suite: &TargetedSuite,
    group: &MlsGroup,
    message: &TargetedMessage,
    sender_auth: &SenderAuthData,
) -> Result<(), OpenError> {
    let sender = group
        .member_at(LeafNodeIndex::new(sender_auth.sender_leaf_index))
        .ok_or(OpenError::SenderLeaf)?;
    let ciphertext_hash = crypto
        .hash(suite.hash, message.ciphertext.as_slice())
        .map_err(|_| OpenError::Signature)?;
    let tbs = to_bytes(&Tbs {
        version: PROTOCOL_VERSION_MLS10,
        wire_format: WIRE_FORMAT_TARGETED_MESSAGE,
        group_id: message.group_id.as_slice(),
        epoch: message.epoch,
        recipient_leaf_index: message.recipient_leaf_index,
        authenticated_data: message.authenticated_data.as_slice(),
        sender_leaf_index: sender_auth.sender_leaf_index,
        kem_output: sender_auth.kem_output.as_slice(),
        ciphertext_hash: &ciphertext_hash,
    })
    .ok_or(OpenError::Malformed)?;
    if labels::verify_with_label(
        crypto,
        suite.signature,
        &sender.signature_key,
        SIGN_LABEL,
        &tbs,
        sender_auth.signature.as_slice(),
    ) {
        Ok(())
    } else {
        Err(OpenError::Signature)
    }
}

/// Step "decrypt `ciphertext`" of the recipient validation; called only after the signature
/// verified.
fn decrypt_content<P: OpenMlsProvider>(
    provider: &P,
    group: &MlsGroup,
    suite: &TargetedSuite,
    secrets: &EpochSecrets,
    message: &TargetedMessage,
    sender_auth: &SenderAuthData,
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    let private_key = leaf_key::own_leaf_private_key(provider, group).ok_or(OpenError::LeafKey)?;
    let group_id = message.group_id.as_slice();
    let tbm = to_bytes(&Tbm {
        group_id,
        epoch: message.epoch,
        recipient_leaf_index: message.recipient_leaf_index,
        authenticated_data: message.authenticated_data.as_slice(),
        sender_leaf_index: sender_auth.sender_leaf_index,
        kem_output: sender_auth.kem_output.as_slice(),
    })
    .ok_or(OpenError::Malformed)?;
    let psk_id = psk_id(group_id, message.epoch).ok_or(OpenError::Malformed)?;
    let info = hpke_info().ok_or(OpenError::Malformed)?;
    hpke::open(
        suite,
        &hpke::OpenInput {
            kem_output: sender_auth.kem_output.as_slice(),
            recipient_private_key: &private_key,
            info: &info,
            aad: &tbm,
            ciphertext: message.ciphertext.as_slice(),
            psk: &secrets.psk,
            psk_id: &psk_id,
        },
    )
    .map_err(|_| OpenError::Decrypt)
}

/// Validate and open a targeted message addressed to this member of `group`.
///
/// The steps run in the order of draft section 7 and the first failure is returned. The signature
/// is verified before the content is decrypted, and the content is released only after the padding
/// check.
pub fn open<P: OpenMlsProvider>(
    provider: &P,
    group: &MlsGroup,
    envelope: &[u8],
) -> Result<Opened, OpenError> {
    let suite = targeted_message_suite(group.ciphersuite()).map_err(|_| OpenError::Suite)?;
    if envelope.len() > MAX_MLS_WIRE_BYTES {
        return Err(OpenError::TooLarge);
    }
    let envelope: Envelope = from_bytes_exact(envelope).ok_or(OpenError::Malformed)?;
    if envelope.draft_version != DRAFT_VERSION_01 {
        return Err(OpenError::UnsupportedVersion);
    }
    let message: TargetedMessage =
        from_bytes_exact(envelope.targeted_message.as_slice()).ok_or(OpenError::Malformed)?;

    if message.group_id.as_slice() != group.group_id().as_slice() {
        return Err(OpenError::GroupMismatch);
    }
    if message.epoch != group.epoch().as_u64() {
        return Err(OpenError::EpochNotCurrent);
    }
    if message.recipient_leaf_index != group.own_leaf_index().u32() {
        return Err(OpenError::NotForThisMember);
    }

    let crypto = provider.crypto();
    let secrets = epoch_secrets(crypto, group, &suite).ok_or(OpenError::Export)?;
    let sender_auth = decrypt_sender_auth(crypto, &suite, &secrets, &message)?;
    authenticate_sender(crypto, &suite, group, &message, &sender_auth)?;
    let content = decrypt_content(provider, group, &suite, &secrets, &message, &sender_auth)?;

    let mut rest: &[u8] = &content;
    let application_data = VLBytes::tls_deserialize(&mut rest).map_err(|_| OpenError::Malformed)?;
    if rest.iter().any(|byte| *byte != 0) {
        return Err(OpenError::Padding);
    }

    Ok(Opened {
        sender_leaf_index: sender_auth.sender_leaf_index,
        authenticated_data: message.authenticated_data.as_slice().to_vec(),
        application_data: Zeroizing::new(application_data.as_slice().to_vec()),
    })
}
