//! The MLS labelled primitives targeted messages use (RFC 9420 section 5.1): `ExpandWithLabel`,
//! `SignWithLabel` and `VerifyWithLabel`.
//!
//! openmls keeps `ExpandWithLabel` crate-private, so it is written here over the provider's
//! `hkdf_expand` (the KDF of the group's suite) and pinned byte-for-byte to the RFC 9420
//! crypto-basics test vectors. `SignWithLabel` builds openmls's own public `SignContent`, so the
//! signed bytes are the ones openmls itself would sign.

use openmls::ciphersuite::signature::SignContent;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::types::{HashType, SignatureScheme};
use tls_codec::{Serialize, TlsSerialize, TlsSize, VLBytes};
use zeroize::Zeroizing;

const LABEL_PREFIX: &str = "MLS 1.0 ";

#[derive(TlsSerialize, TlsSize)]
struct KdfLabel {
    length: u16,
    label: VLBytes,
    context: VLBytes,
}

/// `ExpandWithLabel(secret, label, context, length)`.
pub(super) fn expand_with_label(
    crypto: &impl OpenMlsCrypto,
    hash: HashType,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Option<Zeroizing<Vec<u8>>> {
    let length_u16 = u16::try_from(length).ok()?;
    let info = KdfLabel {
        length: length_u16,
        label: VLBytes::new(format!("{LABEL_PREFIX}{label}").into_bytes()),
        context: VLBytes::new(context.to_vec()),
    }
    .tls_serialize_detached()
    .ok()?;
    let okm = crypto.hkdf_expand(hash, secret, &info, length).ok()?;
    Some(Zeroizing::new(okm.as_slice().to_vec()))
}

/// `SignWithLabel(signer, label, content)`.
pub(super) fn sign_with_label(
    signer: &impl Signer,
    label: &str,
    content: &[u8],
) -> Option<Vec<u8>> {
    let labelled = SignContent::new(label, VLBytes::new(content.to_vec()))
        .tls_serialize_detached()
        .ok()?;
    signer.sign(&labelled).ok()
}

/// `VerifyWithLabel(public_key, label, content, signature)`.
pub(super) fn verify_with_label(
    crypto: &impl OpenMlsCrypto,
    scheme: SignatureScheme,
    public_key: &[u8],
    label: &str,
    content: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(labelled) =
        SignContent::new(label, VLBytes::new(content.to_vec())).tls_serialize_detached()
    else {
        return false;
    };
    crypto
        .verify_signature(scheme, &labelled, public_key, signature)
        .is_ok()
}
