//! A `ProtocolManager` is created on a call to `new_party`.
//! `ProtocolManager` is parameterized over three possible states (in order): Subscribing, Signing,
//! and Complete, encoded as PhantomData type tags. If reader is unfamiliar with type-level
//! programming, consult https://willcrichton.net/notes/type-level-programming/ as a resource. We must use the unsafe
//! `transmute` API to update the PhantomData state tag.

use std::{intrinsics::transmute, marker::PhantomData};

use futures::{future, stream::BoxStream, StreamExt};
use non_substrate_common::SignInit;
use reqwest::{self};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, oneshot};
use tracing::instrument;

use crate::{
  signing_client::{errors::SigningMessageError, subscriber::SubscribeMessage},
  PartyUid, SIGNING_PARTY_SIZE,
};

// use super::context::PartyInfo;

/// Type parameterization of the state of protocol execution. See `ProtocolManager::_marker`.
#[tylift::tylift(mod state)]
enum ProtocolState {
  #[derive(Debug)]
  Subscribing,
  #[derive(Debug)]
  Signing,
  #[derive(Debug)]
  Complete,
}

/// Core type of this file, manages execution of each signing protocol.
pub struct ProtocolManager<T: state::ProtocolState> {
  /// Information about the party provided by the Communication Manager
  pub sign_init: SignInit,
  /// Size of the signing party
  pub signing_party_size: usize,
  /// A channel for the `SubscriberManager` to indicate readiness for the Signing phase
  pub finalized_subscribing_rx: Option<oneshot::Receiver<broadcast::Sender<SigningMessage>>>,
  /// A merged stream of messages from all other nodes in the protocol
  pub rx_stream: Option<BoxStream<'static, SigningMessage>>,
  /// The broadcasting sender for the party. `SubscriberUtil` holds onto it until all parties
  /// have subscribed.
  pub broadcast_tx: Option<broadcast::Sender<SigningMessage>>,
  /// Outcome of the signing protocol
  pub result: Option<anyhow::Result<()>>, // TODO(TK): write when signing phase is implemented
  /// Type parameterization of the state of protocol execution
  _marker: PhantomData<T>,
}

/// Exclude rx_stream and Phantomdata.
impl<T: state::ProtocolState> std::fmt::Debug for ProtocolManager<T> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ProtocolManager")
			.field("sign_init", &self.sign_init)
			.field("signing_party_size", &self.signing_party_size)
			.field("finalized_subscribing_rx", &self.finalized_subscribing_rx)
			// .field("rx_stream", &self.rx_stream) // nope
			.field("broadcast_tx", &self.broadcast_tx)
			.field("result", &self.result)
			// .field("_marker", &self._marker) // nope
			.finish() // nice
  }
}

impl<T: state::ProtocolState> ProtocolManager<T> {
  pub fn new(sign_init: SignInit) -> (oneshot::Sender<broadcast::Sender<SigningMessage>>, Self) {
    {
      let (finalized_subscribing_tx, finalized_subscribing_rx) = oneshot::channel();
      (finalized_subscribing_tx, Self {
        sign_init,
        signing_party_size: SIGNING_PARTY_SIZE,
        finalized_subscribing_rx: Some(finalized_subscribing_rx),
        rx_stream: None,
        broadcast_tx: None,
        result: None,
        _marker: PhantomData,
      })
    }
  }
}

impl ProtocolManager<state::Subscribing> {
  /// Subscribe: Call `subscribe` on each other node in the signing party. Get back vector of
  /// receiver streams. Then advance the protocol to the signing phase.
  #[instrument]
  pub(crate) async fn subscribe_and_await_subscribers(
    mut self,
    // subscribed_oneshot_rx: oneshot::Receiver<broadcast::Sender<SigningMessage>>,
  ) -> anyhow::Result<ProtocolManager<state::Signing>> {
    info!("subscribe_and_await_subscribers");
    self.subscribe_to_party().await?;
    self.await_subscribers().await?;
    unsafe { Ok(transmute(self)) }
  }

  /// Call `subscribe` on every other node with a reqwest client. Merge the streamed responses
  /// into a single stream.
  async fn subscribe_to_party(&mut self) -> anyhow::Result<()> {
    let handles: Vec<_> = self // Call subscribe on every other node
      .sign_init
      .ip_addresses
      .iter()
      .map(|ip| {
        reqwest::Client::new()
          .post(format!("http://{}/subscribe", ip))
          .header("Content-Type", "application/json")
          .json(&SubscribeMessage::new(self.sign_init.party_uid))
          .send()
      })
      .collect();
    let responses: Vec<reqwest::Response> = future::try_join_all(handles).await?;

    let streams: Vec<_> = responses // Filter the streams, map them to messages
      .into_iter()
      .map(|resp: reqwest::Response| {
        resp.bytes_stream().filter_map(|result| {
          let bytes = result.unwrap();
          info!("got bytes: {:?}", bytes);
          let msg = SigningMessage::try_from(&*bytes);
          info!("got msg: {:?}", msg);
          future::ready(msg.ok())
        })
      })
      .collect();
    // Merge the streams, pin-box them to handle the opaque types
    let stream: BoxStream<'static, SigningMessage> = Box::pin(futures::stream::select_all(streams));
    self.rx_stream = Some(stream);
    Ok(())
  }

  /// Wait for other nodes to finish subscribing to this node. SubscriberManager sends a broadcast
  /// channel when all other nodes have subscribed.
  async fn await_subscribers(&mut self) -> anyhow::Result<()> {
    let rx = self.finalized_subscribing_rx.take().unwrap();
    let tx = rx.await?;
    self.broadcast_tx = Some(tx);
    Ok(())
  }
}

// beneath this line: todo
impl ProtocolManager<state::Signing> {
  pub(crate) async fn sign(mut self) -> anyhow::Result<ProtocolManager<state::Complete>> {
    self.result = Some(Ok(())); // TODO(TK):  write after implementing subscriber phase
    unsafe { Ok(transmute(self)) }
  }
}

impl ProtocolManager<state::Complete> {
  pub(crate) fn get_result(&self) -> &anyhow::Result<()> {
    // unwrap is safe because of state parameterization
    self.result.as_ref().unwrap()
  }
}
