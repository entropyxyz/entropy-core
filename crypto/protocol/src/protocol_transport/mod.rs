//! Channels for exchanging protocol messages using noise protocol over websockets
mod broadcaster;
pub mod errors;
pub mod noise;
mod subscribe_message;

use async_trait::async_trait;
pub use broadcaster::Broadcaster;
use errors::WsError;
#[cfg(feature = "server")]
use futures::{SinkExt, StreamExt};
use noise::EncryptedWsConnection;
pub use subscribe_message::SubscribeMessage;
use tokio::sync::{broadcast, mpsc};

use crate::{PartyId, ProtocolMessage};

/// Channels between a remote party and the signing or DKG protocol
pub struct WsChannels {
    pub broadcast: broadcast::Receiver<ProtocolMessage>,
    pub tx: mpsc::Sender<ProtocolMessage>,
    /// A flag to show that this is the last connection to be set up, and we can proceed with the
    /// protocol
    pub is_final: bool,
}

/// Represents the functionality of a Websocket connection with binary messages
/// allowing us to generalize over different websocket implementations
#[async_trait]
pub trait WsConnection {
    async fn recv(&mut self) -> Result<Vec<u8>, WsError>;
    async fn send(&mut self, msg: Vec<u8>) -> Result<(), WsError>;
}

#[cfg(feature = "server")]
#[async_trait]
impl WsConnection for axum::extract::ws::WebSocket {
    async fn recv(&mut self) -> Result<Vec<u8>, WsError> {
        if let axum::extract::ws::Message::Binary(msg) = self
            .recv()
            .await
            .ok_or(WsError::ConnectionClosed)?
            .map_err(|e| WsError::ConnectionError(e.to_string()))?
        {
            Ok(msg)
        } else {
            Err(WsError::UnexpectedMessageType)
        }
    }

    async fn send(&mut self, msg: Vec<u8>) -> Result<(), WsError> {
        self.send(axum::extract::ws::Message::Binary(msg))
            .await
            .map_err(|_| WsError::ConnectionClosed)
    }
}

#[cfg(feature = "server")]
use tokio_tungstenite::{tungstenite, MaybeTlsStream};

#[cfg(feature = "server")]
#[async_trait]
impl WsConnection for tokio_tungstenite::WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>> {
    async fn recv(&mut self) -> Result<Vec<u8>, WsError> {
        if let tungstenite::Message::Binary(msg) = self
            .next()
            .await
            .ok_or(WsError::ConnectionClosed)?
            .map_err(|e| WsError::ConnectionError(e.to_string()))?
        {
            Ok(msg)
        } else {
            Err(WsError::UnexpectedMessageType)
        }
    }

    async fn send(&mut self, msg: Vec<u8>) -> Result<(), WsError> {
        SinkExt::send(&mut self, tungstenite::Message::Binary(msg))
            .await
            .map_err(|_| WsError::ConnectionClosed)
    }
}

/// Send protocol messages over websocket, and websocket messages to protocol
pub async fn ws_to_channels<T: WsConnection>(
    mut connection: EncryptedWsConnection<T>,
    mut ws_channels: WsChannels,
    remote_party_id: PartyId,
) -> Result<(), WsError> {
    loop {
        tokio::select! {
            // Incoming message from remote peer
            signing_message_result = connection.recv() => {
                let serialized_signing_message = signing_message_result.map_err(|e| WsError::EncryptedConnection(e.to_string()))?;
                let msg = ProtocolMessage::try_from(&serialized_signing_message)?;
                ws_channels.tx.send(msg).await.map_err(|_| WsError::MessageAfterProtocolFinish)?;
            }
            // Outgoing message (from signing protocol to remote peer)
            Ok(msg) = ws_channels.broadcast.recv() => {
                // Check that the message is for this peer
                if let Some(party_id) = &msg.to {
                    if party_id != &remote_party_id {
                        continue;
                    }
                }
                let message_string = serde_json::to_string(&msg)?;
                // TODO if this fails, the ws connection has been dropped during the protocol
                // we should inform the chain of this.
                connection.send(message_string).await.map_err(|e| WsError::EncryptedConnection(e.to_string()))?;
            }
        }
    }
}
