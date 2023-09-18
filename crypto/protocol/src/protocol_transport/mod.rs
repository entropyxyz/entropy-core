pub mod broadcaster;
pub mod errors;
pub mod noise;
pub mod protocol_message;

use async_trait::async_trait;
use errors::WsError;

/// Represents the functionality of a Websocket connection with binary messages
/// allowing us to generalize over different websocket implementations
#[async_trait]
pub trait WsConnection {
    async fn recv(&mut self) -> Result<Vec<u8>, WsError>;
    async fn send(&mut self, msg: Vec<u8>) -> Result<(), WsError>;
}
