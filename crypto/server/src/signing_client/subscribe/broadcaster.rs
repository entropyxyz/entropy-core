//! Listener becomes Broadcaster when all other parties have subscribed.
use std::collections::HashMap;

use rocket::{
  response::stream::{Event, EventStream},
  serde::json::Json,
  Shutdown, State,
};
use serde::{Deserialize, Serialize};
use tokio::{
  select,
  sync::{
    broadcast::{self, error::RecvError},
    oneshot,
  },
};
use tracing::instrument;

use super::Listener;
use crate::{
  signing_client::{
    new_party::{Channels, SignContext},
    SigningErr, SigningMessage,
  },
  SIGNING_PARTY_SIZE,
};

#[derive(Debug)]
pub struct Broadcaster(Listener);
//  {
//   /// How many other nodes have subscribed to this node
//   pub count:        usize,
//   /// Marked true when the count matches SIGNING_PARTY_SIZE
//   pub done:         bool,
//   /// When count = party_size, this channel will pass a Ready message, containing the
//   /// fully-subscribed broadcast sender.
//   pub finalized_tx: Option<oneshot::Sender<broadcast::Sender<SigningMessage>>>,
//   /// The broadcast tx, to send other nodes messages. Used to produce receiver channels in the
//   /// Subscribing phase.
//   pub broadcast_tx: Option<broadcast::Sender<SigningMessage>>,
// }
