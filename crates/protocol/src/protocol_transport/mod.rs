// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Channels for exchanging protocol messages using noise protocol over websockets
mod broadcaster;
pub mod errors;
pub mod noise;
mod subscribe_message;

use async_trait::async_trait;
pub use broadcaster::Broadcaster;
use errors::WsError;
#[cfg(any(feature = "server", feature = "wasm"))]
use futures::{SinkExt, StreamExt};
use noise::EncryptedWsConnection;
pub use subscribe_message::SubscribeMessage;
use tokio::sync::{broadcast, mpsc};
#[cfg(feature = "server")]
use tokio_tungstenite::{tungstenite, MaybeTlsStream, WebSocketStream};

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
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait WsConnection {
    async fn recv(&mut self) -> Result<Vec<u8>, WsError>;
    async fn send(&mut self, msg: Vec<u8>) -> Result<(), WsError>;
}

#[cfg(feature = "wasm")]
#[async_trait(?Send)]
impl WsConnection for gloo_net::websocket::futures::WebSocket {
    async fn recv(&mut self) -> Result<Vec<u8>, WsError> {
        if let gloo_net::websocket::Message::Bytes(msg) = self
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
        SinkExt::send(&mut self, gloo_net::websocket::Message::Bytes(msg))
            .await
            .map_err(|_| WsError::ConnectionClosed)
    }
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

// Currently only used in benchmarks - entropy-tss uses the MaybeTlsStream wrapper
#[cfg(feature = "server")]
#[async_trait]
impl WsConnection for tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
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
                let msg = ProtocolMessage::try_from(&serialized_signing_message[..])?;
                ws_channels.tx.send(msg).await.map_err(|_| WsError::MessageAfterProtocolFinish)?;
            }
            // Outgoing message (from signing protocol to remote peer)
            msg_result = ws_channels.broadcast.recv() => {
                if let Ok(msg) = msg_result {
                    // Check that the message is for this peer
                    if msg.to != remote_party_id {
                        continue;
                    }
                    let message_vec = bincode::serialize(&msg)?;
                    // TODO if this fails, the ws connection has been dropped during the protocol
                    // we should inform the chain of this.
                    connection.send(message_vec).await.map_err(|e| WsError::EncryptedConnection(e.to_string()))?;
                } else {
                    return Ok(());
                }
            }
        }
    }
}

// This dummy trait is only needed because we cant add #[cfg] to where clauses
/// Trait only when not using wasm, adding the send marker trait
#[cfg(feature = "server")]
pub trait ThreadSafeWsConnection: WsConnection + std::marker::Send + 'static {}

/// Trait only when using wasm, not adding the send marker trait
#[cfg(feature = "wasm")]
pub trait ThreadSafeWsConnection: WsConnection + 'static {}

#[cfg(feature = "server")]
impl ThreadSafeWsConnection
    for WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
{
}

#[cfg(feature = "wasm")]
impl ThreadSafeWsConnection for gloo_net::websocket::futures::WebSocket {}
