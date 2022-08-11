pub mod api;
mod errors;
mod new_party;
mod subscriber;

use std::{collections::HashMap, sync::Mutex};

pub use self::{
  errors::*,
  new_party::SigningMessage,
  subscriber::{SubscribeMessage, SubscriberManager},
};

/// The state used by this node to create signatures
#[derive(Default, Debug)]
pub struct SignerState {
  /// Mapping of PartyIds to `SubscriberManager`s, one entry per active party.
  // TODO(TK): SubscriberManager to be replaced with None when subscribing phase ends.
  pub subscriber_manager_map: Mutex<HashMap<String, Option<SubscriberManager>>>,
}
