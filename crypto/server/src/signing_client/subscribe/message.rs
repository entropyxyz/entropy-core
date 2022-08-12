use serde::{Deserialize, Serialize};

use crate::signing_client::SubscribeErr;

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
