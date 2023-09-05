use std::string::FromUtf8Error;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolMessageErr {
    #[error("Utf8Error: {0:?}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Deserialization Error: {0:?}")]
    Deserialization(#[from] serde_json::Error),
}

/// Errors relating to encrypted WS connections / noise handshaking
#[derive(Debug, Error)]
pub enum EncryptedConnectionError {
    #[error("Noise error: {0}")]
    Noise(#[from] snow::error::Error),
    #[error("Utf8Error: {0:?}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Utf8Error: {0:?}")]
    FromUtf8(#[from] FromUtf8Error),
    #[error("Websocket error: {0}")]
    WebSocket(#[from] WsError),
    #[error("Could not get remote public key")]
    RemotePublicKey,
}
