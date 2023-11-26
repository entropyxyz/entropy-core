use synedrion::{InteractiveSigningResult, KeyRefreshResult, KeygenAndAuxResult};
use thiserror::Error;

use crate::{
    protocol_message::ProtocolMessage, protocol_transport::errors::EncryptedConnectionErr,
    KeyParams, PartyId,
};

/// An error during or while setting up a protocol session
#[derive(Debug, Error)]
pub enum ProtocolExecutionErr {
    #[error("Synedrion usage error: {0}")]
    SynedrionUsageError(synedrion::sessions::LocalError),
    #[error("Unprovable remote party error: {0}")]
    SynedrionRemoteError(synedrion::sessions::RemoteError<PartyId>),
    #[error("Incoming message stream error: {0}")]
    IncomingStream(String),
    #[error("Synedrion signing session error {0}")]
    SigningProtocolError(
        Box<synedrion::sessions::Error<InteractiveSigningResult<KeyParams>, PartyId>>,
    ),
    #[error("Synedrion keygen session error {0}")]
    KeyGenProtocolError(Box<synedrion::sessions::Error<KeygenAndAuxResult<KeyParams>, PartyId>>),
    #[error("Synedrion key refresh session error {0}")]
    KeyRefreshProtocolError(Box<synedrion::sessions::Error<KeyRefreshResult<KeyParams>, PartyId>>),
    #[error("Broadcast error: {0}")]
    Broadcast(#[from] Box<tokio::sync::broadcast::error::SendError<ProtocolMessage>>),
    #[error("Bad keyshare error {0}")]
    BadKeyShare(String),
}

/// An error when running a protocol session on the client side
#[derive(Debug, Error)]
pub enum UserRunningProtocolErr {
    #[error("Encrypted Connection Error: {0}")]
    EncryptedConnection(#[from] EncryptedConnectionErr),
    #[error("Protocol Execution Error {0}")]
    ProtocolExecution(#[from] ProtocolExecutionErr),
    #[error("Serialization Error: {0:?}")]
    Serialization(#[from] bincode::Error),
    #[error("Bad Subscribe Message: {0}")]
    BadSubscribeMessage(String),
    #[error("Connection Error: {0}")]
    Connection(String),
}
