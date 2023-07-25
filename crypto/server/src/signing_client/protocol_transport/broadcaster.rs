//! Listener becomes Broadcaster when all other parties have subscribed.

use tokio::sync::broadcast::{self, error::SendError};

use crate::signing_client::SigningMessage;

#[derive(Debug)]
pub struct Broadcaster(pub broadcast::Sender<SigningMessage>);

impl Broadcaster {
    pub fn send(&self, msg: SigningMessage) -> Result<usize, Box<SendError<SigningMessage>>> {
        Ok(self.0.send(msg)?)
    }
}
