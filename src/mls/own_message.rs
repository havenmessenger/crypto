//! A member's own message, returned to it by the delivery service.
//!
//! A member never reads or stages its own message from the wire. It already holds what it sent: an
//! application message it wrote, or a commit it confirms through [`crate::mls::PendingCommit`]. The MLS
//! implementation reports an own `PrivateMessage` as content it cannot open, and stages an own Commit
//! that carries no `UpdatePath` when it does not match the group's pending commit. Every entry point
//! here refuses both with [`OwnMessage`], so an own commit can never advance the canonical state
//! outside `PendingCommit::confirm`.

use std::fmt;

use openmls::prelude::{
    MlsGroup, ProcessedMessage, ProcessedMessageContent, ProtocolMessage, Sender,
};

/// The message was sent by this member. A caller holding the `anyhow::Error` can `downcast_ref` to
/// this type; the refusal is not one of the MLS implementation's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnMessage;

impl fmt::Display for OwnMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Own message: sent by this member, which does not process its own messages")
    }
}

impl std::error::Error for OwnMessage {}

/// Refuse a `PublicMessage` whose clear sender is this member's leaf, before it is processed.
pub(crate) fn refuse_own_sender(group: &MlsGroup, message: &ProtocolMessage) -> anyhow::Result<()> {
    if let ProtocolMessage::PublicMessage(public) = message {
        if *public.sender() == Sender::Member(group.own_leaf_index()) {
            return Err(anyhow::Error::new(OwnMessage));
        }
    }
    Ok(())
}

/// Refuse a processed message the MLS implementation reports as this member's own.
pub(crate) fn refuse_own_content(processed: &ProcessedMessage) -> anyhow::Result<()> {
    match processed.content() {
        ProcessedMessageContent::OwnPrivateMessage | ProcessedMessageContent::OwnPendingCommit => {
            Err(anyhow::Error::new(OwnMessage))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
#[path = "own_message_tests.rs"]
mod tests;
