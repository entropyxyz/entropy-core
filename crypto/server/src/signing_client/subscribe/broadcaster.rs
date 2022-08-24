//! Listener becomes Broadcaster when all other parties have subscribed.

use tokio::sync::broadcast::{self, error::SendError};

use super::Listener;
use crate::signing_client::{SigningErr, SigningMessage};

#[derive(Debug)]
pub struct Broadcaster(pub broadcast::Sender<SigningMessage>);

impl Broadcaster {
  pub fn send(&self, msg: SigningMessage) -> Result<usize, SendError<SigningMessage>> {
     self.0.send(msg)
  }
}
