//! Listener becomes Broadcaster when all other parties have subscribed.

use tokio::sync::broadcast;

use super::Listener;
use crate::signing_client::SigningMessage;

#[derive(Debug)]
pub struct Broadcaster(pub broadcast::Sender<SigningMessage>);
