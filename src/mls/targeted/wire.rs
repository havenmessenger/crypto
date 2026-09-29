//! Wire structures of `draft-ietf-mls-targeted-messages-01`, section 3, plus the versioned
//! envelope this crate puts around a serialized `TargetedMessage`.
//!
//! Every struct is TLS-serialised with `tls_codec` in exactly the field order and integer widths
//! the draft gives. The draft's `mls_targeted_message` `WireFormat` codepoint is only "suggested"
//! (not assigned), so no `MLSMessage` is emitted: the serialized `TargetedMessage` travels inside
//! [`Envelope`], whose `draft_version` names the draft revision. A later revision, or an assigned
//! codepoint, is a new `draft_version` and never a silent change to this one.

use tls_codec::{Serialize, TlsSerialize, TlsSize, VLBytes};

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
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsSize)]
pub struct Envelope {
    pub draft_version: u16,
    pub targeted_message: VLBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsSize)]
pub struct TargetedMessage {
    pub group_id: VLBytes,
    pub epoch: u64,
    pub recipient_leaf_index: u32,
    pub authenticated_data: VLBytes,
    pub encrypted_sender_auth_data: VLBytes,
    pub ciphertext: VLBytes,
}

#[derive(TlsSerialize, TlsSize)]
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

/// A cursor over untrusted bytes.
///
/// Every field is read here, never by `tls_codec`'s decoder: that decoder allocates the whole
/// claimed length of a variable-length vector before it reads the bytes, and asserts on a malformed
/// length prefix in debug builds. This reader checks each length prefix against the bytes that
/// remain before it takes anything, so a hostile length can neither allocate nor panic.
pub(super) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    const fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if count > self.0.len() {
            return None;
        }
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Some(head)
    }

    pub(super) fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    pub(super) fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    pub(super) fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    /// A variable-length vector (RFC 9420 section 2.1.2): a prefix of one, two or four bytes whose
    /// top two bits give its width, the shortest width that holds the length, then that many bytes.
    /// The eight-byte form is not used by MLS and is refused, as is a longer-than-needed prefix.
    pub(super) fn vector(&mut self) -> Option<&'a [u8]> {
        let first = *self.0.first()?;
        let width = match first >> 6 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => return None,
        };
        let prefix = self.take(width)?;
        let mut length = usize::from(first & 0x3f);
        for byte in &prefix[1..] {
            length = (length << 8) | usize::from(*byte);
        }
        let shortest = if length <= 0x3f {
            1
        } else if length <= 0x3fff {
            2
        } else {
            4
        };
        if width != shortest {
            return None;
        }
        self.take(length)
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) const fn rest(&self) -> &'a [u8] {
        self.0
    }
}

/// A wire struct that can be read from a [`Reader`].
pub(super) trait Parse: Sized {
    fn parse(reader: &mut Reader<'_>) -> Option<Self>;
}

impl Parse for Envelope {
    fn parse(reader: &mut Reader<'_>) -> Option<Self> {
        Some(Self {
            draft_version: reader.u16()?,
            targeted_message: VLBytes::new(reader.vector()?.to_vec()),
        })
    }
}

impl Parse for TargetedMessage {
    fn parse(reader: &mut Reader<'_>) -> Option<Self> {
        Some(Self {
            group_id: VLBytes::new(reader.vector()?.to_vec()),
            epoch: reader.u64()?,
            recipient_leaf_index: reader.u32()?,
            authenticated_data: VLBytes::new(reader.vector()?.to_vec()),
            encrypted_sender_auth_data: VLBytes::new(reader.vector()?.to_vec()),
            ciphertext: VLBytes::new(reader.vector()?.to_vec()),
        })
    }
}

impl Parse for SenderAuthData {
    fn parse(reader: &mut Reader<'_>) -> Option<Self> {
        Some(Self {
            sender_leaf_index: reader.u32()?,
            signature: VLBytes::new(reader.vector()?.to_vec()),
            kem_output: VLBytes::new(reader.vector()?.to_vec()),
        })
    }
}

/// Serialize a wire struct. Serialization of these fixed shapes into memory cannot fail short of
/// an allocation failure, so a failure is reported as the caller's `Malformed`-class error.
pub(super) fn to_bytes<T: Serialize>(value: &T) -> Option<Vec<u8>> {
    value.tls_serialize_detached().ok()
}

/// Parse a whole buffer as one `T`: trailing bytes are an error.
pub(super) fn from_bytes_exact<T: Parse>(bytes: &[u8]) -> Option<T> {
    let mut reader = Reader::new(bytes);
    let value = T::parse(&mut reader)?;
    reader.is_empty().then_some(value)
}

/// Split a decrypted `TargetedMessageContent` into its application data and the padding that
/// follows it.
pub(super) fn parse_content(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut reader = Reader::new(bytes);
    let application_data = reader.vector()?;
    Some((application_data, reader.rest()))
}
