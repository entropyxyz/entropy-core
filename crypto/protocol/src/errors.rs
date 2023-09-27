use thiserror::Error;

use crate::{
    protocol_message::ProtocolMessage, protocol_transport::errors::EncryptedConnectionErr,
};

/// An error during or while setting up a protocol session
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

/// An error when running a protocol session on the client side
#[derive(Debug, Error)]
pub enum UserRunningProtocolErr {
    #[error("Encrypted Conection Error: ")]
    EncryptedConnection(#[from] EncryptedConnectionErr),
    #[error("Protocol Execution Error {0}")]
    ProtocolExecution(#[from] ProtocolExecutionErr),
    #[error("Serde Json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Bad Subscribe Message: {0}")]
    BadSubscribeMessage(String),
    #[error("Connection Error: {0}")]
    Connection(String),
}
