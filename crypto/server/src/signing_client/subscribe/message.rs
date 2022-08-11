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

use crate::{
  signing_client::{Listener, SigningMessage, SubscribeErr},
  SignerState, SIGNING_PARTY_SIZE,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SubscribeMessage {
  pub party_id: String,
}

/// A message sent by subscribing node. Holder struct for subscription-related methods.
impl SubscribeMessage {
  pub fn new(party_id: String) -> Self { Self { party_id } }

  // todo: unclear what validation should occur
  pub(crate) fn validate_registration(&self) -> Result<(), SubscribeErr> { Ok(()) }
}
