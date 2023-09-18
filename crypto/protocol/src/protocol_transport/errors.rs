use std::string::FromUtf8Error;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WsError {
    #[error("Ws Connection closed unexpectedly")]
    ConnectionClosed,
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("Message received after signing protocol has finished")]
    MessageAfterProtocolFinish,
    #[error("UTF8 parse error {0}")]
    UTF8Parse(#[from] FromUtf8Error),
    #[error("Cannot get signer from app state")]
    SignerFromAppState,
    #[error("Unexpected message type")]
    UnexpectedMessageType,
    #[error("Encrypted connection error {0}")]
    EncryptedConnection(String),
    #[error("Error parsing Signing Message")]
    ProtocolMessage(#[from] super::errors::ProtocolMessageErr),
    #[error("Serialization Error: {0:?}")]
    Serialization(#[from] serde_json::Error),
    #[error("Received bad subscribe message")]
    BadSubscribeMessage,
}

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
