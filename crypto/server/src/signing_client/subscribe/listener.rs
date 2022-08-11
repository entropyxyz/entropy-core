#![allow(dead_code)]
use std::collections::HashMap;

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
use crate::signing_client::{SigningMessage, SubscribeErr};

pub type ListenerResult = Result<Broadcaster, SubscribeErr>;

#[derive(Debug)]
pub struct Listener {
  // party_id: String,
  /// Endpoint to create subscriptions
  tx:       broadcast::Sender<SigningMessage>,
  /// Endpoint to notify protocol execution ready-for-signing
  tx_ready: oneshot::Sender<ListenerResult>,
}

impl Listener {
  pub(crate) fn new() -> (oneshot::Receiver<ListenerResult>, Self) {
    let (tx_ready, rx_ready) = oneshot::channel();
    let (tx, _rx) = broadcast::channel(1000);
    {
      (rx_ready, Self { tx, tx_ready })
    }
  }

  // #[instrument]
  // pub(crate) async fn subscribe_and_await_subscribers(
  //   &self,
  //   sign_context: &SignContext,
  // ) -> Result<Channels, SigningErr> {
  //   info!("subscribe_and_await_subscribers: {sign_context:?}");

  //   Err(SigningErr::Subscribing("subscribbb"))
  // }

  /// Update Self with a new subscriber.
  /// If this was the final subscriber, send broadcast_tx back to the ProtocolManager.
  // pub(super) fn new_subscriber(&mut self) -> broadcast::Receiver<SigningMessage> {
  //   assert!(!self.done);
  //   self.count += 1;
  //   let rx = self.broadcast_tx.as_ref().unwrap().subscribe();
  //   if self.count == SIGNING_PARTY_SIZE {
  //     self.done = true;
  //     let broadcast_tx = self.broadcast_tx.take().unwrap();
  //     let finalized_tx = self.finalized_tx.take().unwrap();
  //     let _ = finalized_tx.send(broadcast_tx);
  //   }
  //   rx
  // }

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

  /// Retreive the SubscriberManager for this party, update it with a new subscriber.
  pub(crate) fn subscribe(
    &self,
    msg: &SubscribeMessage,
    // map: &mut HashMap<String, Option<Broadcaster>>,
  ) -> Result<broadcast::Receiver<SigningMessage>, SubscribeErr> {
    // let mut subscriber_manager = map.remove(&self.party_id).unwrap().unwrap();
    // let rx = subscriber_manager.new_subscriber();
    // map.insert(self.party_id.to_string(), Some(subscriber_manager));
    // Ok(rx)
    todo!();
  }
}
