//! Wire structures of `draft-ietf-mls-targeted-messages-01`, section 3, plus the versioned
//! envelope this crate puts around a serialized `TargetedMessage`.
//!
//! Every struct is TLS-serialised with `tls_codec` in exactly the field order and integer widths
//! the draft gives. The draft's `mls_targeted_message` `WireFormat` codepoint is only "suggested"
//! (not assigned), so no `MLSMessage` is emitted: the serialized `TargetedMessage` travels inside
//! [`Envelope`], whose `draft_version` names the draft revision. A later revision, or an assigned
//! codepoint, is a new `draft_version` and never a silent change to this one.

use tls_codec::{Deserialize, Serialize, TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

/// `draft_version` for `draft-ietf-mls-targeted-messages-01`.
pub const DRAFT_VERSION_01: u16 = 1;

/// The draft's suggested `mls_targeted_message` `WireFormat` value. It is part of the signed
/// `TargetedMessageTBS` bytes, so it is fixed per envelope version.
pub(super) const WIRE_FORMAT_TARGETED_MESSAGE: u16 = 0x0006;

/// `ProtocolVersion mls10`.
pub(super) const PROTOCOL_VERSION_MLS10: u16 = 1;

/// Label of the `PSKId` struct.
pub(super) const PSK_LABEL: &[u8] = b"MLS 1.0 targeted message psk";

/// Label of the HPKE `TargetedMessageContext`.
pub(super) const HPKE_CONTEXT_LABEL: &[u8] = b"MLS 1.0 TargetedMessageData";

/// The versioned outer layer: which draft the inner bytes follow, then those bytes.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct Envelope {
    pub draft_version: u16,
    pub targeted_message: VLBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct TargetedMessage {
    pub group_id: VLBytes,
    pub epoch: u64,
    pub recipient_leaf_index: u32,
    pub authenticated_data: VLBytes,
    pub encrypted_sender_auth_data: VLBytes,
    pub ciphertext: VLBytes,
}

#[derive(TlsSerialize, TlsDeserialize, TlsSize)]
pub(super) struct SenderAuthData {
    pub sender_leaf_index: u32,
    pub signature: VLBytes,
    pub kem_output: VLBytes,
}

#[derive(TlsSerialize, TlsSize)]
pub(super) struct Tbm<'a> {
    pub group_id: &'a [u8],
    pub epoch: u64,
    pub recipient_leaf_index: u32,
    pub authenticated_data: &'a [u8],
    pub sender_leaf_index: u32,
    pub kem_output: &'a [u8],
}

#[derive(TlsSerialize, TlsSize)]
pub(super) struct Tbs<'a> {
    pub version: u16,
    pub wire_format: u16,
    pub group_id: &'a [u8],
    pub epoch: u64,
    pub recipient_leaf_index: u32,
    pub authenticated_data: &'a [u8],
    pub sender_leaf_index: u32,
    pub kem_output: &'a [u8],
    pub ciphertext_hash: &'a [u8],
}

#[derive(TlsSerialize, TlsSize)]
pub(super) struct PskId<'a> {
    pub group_id: &'a [u8],
    pub epoch: u64,
    pub label: &'a [u8],
}

#[derive(TlsSerialize, TlsSize)]
pub(super) struct HpkeContext<'a> {
    pub label: &'a [u8],
    pub context: &'a [u8],
}

#[derive(TlsSerialize, TlsSize)]
pub(super) struct SenderAuthDataAad<'a> {
    pub group_id: &'a [u8],
    pub epoch: u64,
    pub recipient_leaf_index: u32,
}

/// Serialize a wire struct. Serialization of these fixed shapes into memory cannot fail short of
/// an allocation failure, so a failure is reported as the caller's `Malformed`-class error.
pub(super) fn to_bytes<T: Serialize>(value: &T) -> Option<Vec<u8>> {
    value.tls_serialize_detached().ok()
}

/// Parse a whole buffer as one `T`: trailing bytes are an error.
pub(super) fn from_bytes_exact<T: Deserialize>(bytes: &[u8]) -> Option<T> {
    T::tls_deserialize_exact(bytes).ok()
}
