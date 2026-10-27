//! The MLS implementation's refusal of a message, kept as a value a caller can match.

use std::fmt;

pub use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
pub use openmls::prelude::{ProcessMessageError, ValidationError};
use openmls_rust_crypto::MemoryStorageError;

/// The MLS implementation's refusal of a message given to [`crate::mls::groups::decrypt_message`].
///
/// It reads as `Processing error: ` followed by the refusal's Debug, and it keeps the refusal, so a caller holding
/// the `anyhow::Error` can `downcast_ref` to this type and match the variant rather than read the text.
#[derive(Debug)]
pub struct ProcessingError(ProcessMessageError<MemoryStorageError>);

impl ProcessingError {
    pub(crate) const fn new(refusal: ProcessMessageError<MemoryStorageError>) -> Self {
        Self(refusal)
    }

    /// The refusal, as the MLS implementation gave it.
    #[must_use]
    pub const fn refusal(&self) -> &ProcessMessageError<MemoryStorageError> {
        &self.0
    }
}

impl fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Processing error: {:?}", self.0)
    }
}

/// The text is the whole report, as it is for every other error here, so the refusal is not also given as a source.
impl std::error::Error for ProcessingError {}

#[cfg(test)]
#[path = "processing_error_tests.rs"]
mod tests;
