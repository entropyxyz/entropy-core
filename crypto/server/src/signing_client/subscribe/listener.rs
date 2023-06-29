#![allow(dead_code)]

use tokio::sync::{
    broadcast::{self, error::RecvError},
    mpsc, oneshot,
};

use super::Broadcaster;
use crate::{
    signing_client::{SigningMessage, SubscribeErr},
    SIGNING_PARTY_SIZE,
};

pub type ListenerResult = Result<Broadcaster, SubscribeErr>;

#[derive(Debug)]
pub struct Listener {
    // party_id: String,
    /// Endpoint to create subscriptions
    tx: broadcast::Sender<SigningMessage>,
    /// Messages
    tx_to_others: mpsc::Sender<SigningMessage>,
    /// Endpoint to notify protocol execution ready-for-signing
    tx_ready: oneshot::Sender<ListenerResult>,
    /// Count of nodes who've poked `subscribe`
    subscriber_count: usize,
}

pub struct WsChannels {
    pub broadcast: broadcast::Receiver<SigningMessage>,
    pub tx: mpsc::Sender<SigningMessage>,
    pub is_final: bool,
}

impl Listener {
    pub(crate) fn new() -> (oneshot::Receiver<ListenerResult>, mpsc::Receiver<SigningMessage>, Self)
    {
        let (tx_ready, rx_ready) = oneshot::channel();
        let (tx, _rx) = broadcast::channel(1000);
        let (tx_to_others, rx_to_others) = mpsc::channel(1000);
        {
            (rx_ready, rx_to_others, Self { tx, tx_to_others, tx_ready, subscriber_count: 0 })
        }
    }

    pub(crate) fn subscribe(&mut self) -> WsChannels {
        self.subscriber_count += 1;
        let broadcast = self.tx.subscribe();
        let tx = self.tx_to_others.clone();
        WsChannels { broadcast, tx, is_final: self.subscriber_count == SIGNING_PARTY_SIZE }
    }

    pub(crate) fn into_broadcaster(self) -> (oneshot::Sender<ListenerResult>, Broadcaster) {
        (self.tx_ready, Broadcaster(self.tx))
    }
}
