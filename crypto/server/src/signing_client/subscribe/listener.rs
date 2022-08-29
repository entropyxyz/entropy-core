#![allow(dead_code)]

use rocket::{
    response::stream::{Event, EventStream},
    Shutdown,
};
use tokio::{
    select,
    sync::{
        broadcast::{self, error::RecvError},
        oneshot,
    },
};

use super::{Broadcaster, SubscribeMessage};
use crate::{
    signing_client::{SigningMessage, SubscribeErr},
    SIGNING_PARTY_SIZE,
};

pub type ListenerResult = Result<Broadcaster, SubscribeErr>;

#[derive(Debug)]
pub struct Listener {
    // party_id: String,
    /// Endpoint to create subscriptions
    tx:               broadcast::Sender<SigningMessage>,
    /// Endpoint to notify protocol execution ready-for-signing
    tx_ready:         oneshot::Sender<ListenerResult>,
    /// Count of nodes who've poked `subscribe`
    subscriber_count: usize,
}

pub enum Receiver {
    Receiver(broadcast::Receiver<SigningMessage>),
    FinalReceiver(broadcast::Receiver<SigningMessage>),
}

impl Listener {
    pub(crate) fn new() -> (oneshot::Receiver<ListenerResult>, Self) {
        let (tx_ready, rx_ready) = oneshot::channel();
        let (tx, _rx) = broadcast::channel(1000);
        {
            (rx_ready, Self { tx, tx_ready, subscriber_count: 0 })
        }
    }

    pub(crate) fn subscribe(&mut self, msg: &SubscribeMessage) -> Result<Receiver, SubscribeErr> {
        self.subscriber_count += 1;
        let rx = self.tx.subscribe();
        if self.subscriber_count == SIGNING_PARTY_SIZE {
            Ok(Receiver::FinalReceiver(rx))
        } else {
            Ok(Receiver::Receiver(rx))
        }
    }

    /// Yield messages as events in a stream as they arrive. Helper for `subscribe`.
    pub(crate) fn create_event_stream(
        mut rx: broadcast::Receiver<SigningMessage>,
        mut end: Shutdown,
    ) -> EventStream![] {
        EventStream! {
          loop {
            let msg = select! {
              msg = rx.recv() => match msg {
                Ok(msg) => msg,
                Err(RecvError::Closed) => break,
                Err(RecvError::Lagged(_)) => continue,
              },
              _ = &mut end => break,
            };

            yield Event::json(&msg);
          }
        }
    }

    pub(crate) fn into_broadcaster(self) -> (oneshot::Sender<ListenerResult>, Broadcaster) {
        (self.tx_ready, Broadcaster(self.tx))
    }
}
