use thiserror::Error;

use crate::protocol_transport::protocol_message::ProtocolMessage;

#[derive(Debug, Error)]
pub enum ProtocolExecutionErr {
    #[error("Session Creation Error: {0}")]
    SessionCreationError(synedrion::InitError),
    #[error("Incoming message stream error: {0}")]
    IncomingStream(String),
    #[error("Synedrion session error {0}")]
    SynedrionSession(synedrion::sessions::Error),
    #[error("Broadcast error: {0}")]
    Broadcast(#[from] Box<tokio::sync::broadcast::error::SendError<ProtocolMessage>>),
}
