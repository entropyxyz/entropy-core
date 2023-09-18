mod broadcaster;
pub mod errors;
mod message;
pub mod noise;

use async_trait::async_trait;
pub use broadcaster::Broadcaster;
use errors::WsError;
use futures::{SinkExt, StreamExt};
pub use message::SubscribeMessage;

/// Represents the functionality of a Websocket connection with binary messages
/// allowing us to generalize over different websocket implementations
#[async_trait]
pub trait WsConnection {
    async fn recv(&mut self) -> Result<Vec<u8>, WsError>;
    async fn send(&mut self, msg: Vec<u8>) -> Result<(), WsError>;
}

#[cfg(feature = "server")]
use tokio_tungstenite::{tungstenite, MaybeTlsStream};

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
