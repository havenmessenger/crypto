//! Transcript-bound SPAKE2 with explicit confirmation of a server identity key.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const SERVER_CONFIRM: &[u8] = b"server-confirm";
const CLIENT_CONFIRM: &[u8] = b"client-confirm";
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PakeError {
    #[error("the SPAKE2 message is malformed")]
    Malformed,
    #[error("the pairing password, identity key, or channel binding does not match")]
    Confirmation,
}

pub struct Client {
    state: Spake2<Ed25519Group>,
    binding: Vec<u8>,
    domain: Vec<u8>,
}

pub struct Server {
    state: Spake2<Ed25519Group>,
    binding: Vec<u8>,
    domain: Vec<u8>,
}

pub struct ExpectedClientConfirmation([u8; 32]);

impl Client {
    #[must_use]
    pub fn begin(password_bytes: &[u8], binding: &[u8], domain: &[u8]) -> (Self, Vec<u8>) {
        let password = Password::new(Zeroizing::new(password_bytes.to_vec()));
        let (client_id, server_id) = identities(domain, binding);
        let (state, message) = Spake2::<Ed25519Group>::start_a(&password, &client_id, &server_id);
        (
            Self {
                state,
                binding: binding.to_vec(),
                domain: domain.to_vec(),
            },
            message,
        )
    }

    pub fn finish(
        self,
        server_message: &[u8],
        server_confirmation: &[u8; 32],
        server_key: &[u8; 32],
    ) -> Result<[u8; 32], PakeError> {
        let shared = self
            .state
            .finish(server_message)
            .map_err(|_| PakeError::Malformed)?;
        let expected = confirmation(
            &shared,
            &self.binding,
            &self.domain,
            SERVER_CONFIRM,
            server_key,
        );
        if expected.ct_eq(server_confirmation).unwrap_u8() != 1 {
            return Err(PakeError::Confirmation);
        }
        Ok(confirmation(
            &shared,
            &self.binding,
            &self.domain,
            CLIENT_CONFIRM,
            server_key,
        ))
    }
}

impl Server {
    #[must_use]
    pub fn begin(password_bytes: &[u8], binding: &[u8], domain: &[u8]) -> (Self, Vec<u8>) {
        let password = Password::new(Zeroizing::new(password_bytes.to_vec()));
        let (client_id, server_id) = identities(domain, binding);
        let (state, message) = Spake2::<Ed25519Group>::start_b(&password, &client_id, &server_id);
        (
            Self {
                state,
                binding: binding.to_vec(),
                domain: domain.to_vec(),
            },
            message,
        )
    }

    pub fn finish(
        self,
        client_message: &[u8],
        server_key: &[u8; 32],
    ) -> Result<([u8; 32], ExpectedClientConfirmation), PakeError> {
        let shared = self
            .state
            .finish(client_message)
            .map_err(|_| PakeError::Malformed)?;
        let server = confirmation(
            &shared,
            &self.binding,
            &self.domain,
            SERVER_CONFIRM,
            server_key,
        );
        let client = confirmation(
            &shared,
            &self.binding,
            &self.domain,
            CLIENT_CONFIRM,
            server_key,
        );
        Ok((server, ExpectedClientConfirmation(client)))
    }
}

impl ExpectedClientConfirmation {
    pub fn verify(self, confirmation: &[u8; 32]) -> Result<(), PakeError> {
        if self.0.ct_eq(confirmation).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(PakeError::Confirmation)
        }
    }
}

fn identities(domain: &[u8], binding: &[u8]) -> (Identity, Identity) {
    let mut client = Vec::with_capacity(domain.len() + binding.len() + 8);
    client.extend_from_slice(domain);
    client.extend_from_slice(b"\0client\0");
    client.extend_from_slice(binding);
    let mut server = Vec::with_capacity(domain.len() + binding.len() + 8);
    server.extend_from_slice(domain);
    server.extend_from_slice(b"\0daemon\0");
    server.extend_from_slice(binding);
    (Identity::new(&client), Identity::new(&server))
}

fn confirmation(
    shared: &[u8],
    binding: &[u8],
    domain: &[u8],
    label: &[u8],
    server_key: &[u8; 32],
) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(binding), shared);
    let mut key = [0u8; 32];
    hkdf.expand(label, &mut key)
        .expect("SHA-256 confirmation key length is valid");
    let mut mac = HmacSha256::new_from_slice(&key).expect("SHA-256 accepts a 32-byte key");
    mac.update(domain);
    mac.update(binding);
    mac.update(label);
    mac.update(server_key);
    let bytes: [u8; 32] = mac.finalize().into_bytes().into();
    key.zeroize();
    bytes
}

#[cfg(test)]
#[path = "pake_tests.rs"]
mod tests;
