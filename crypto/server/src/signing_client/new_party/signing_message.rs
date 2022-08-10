use std::{intrinsics::transmute, marker::PhantomData};

use futures::{future, stream::BoxStream, StreamExt};
// use reqwest::{self};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, oneshot};
use tracing::instrument;

use crate::{
  signing_client::{errors::SigningMessageError, subscriber::SubscribeMessage},
  SIGNING_PARTY_SIZE,
};

/// A Message related to the signing protocol.
// TODO(TK): WIP, to be written while fleshing out signing protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SigningMessage {
  pub party_id: String,
}

impl TryFrom<&[u8]> for SigningMessage {
  type Error = SigningMessageError;

  // Reqwest responses come back formatted with an added crud feature:
  // 'data:{<actual_message>}\n'
  // 👆👆👆  this is crud    👆
  fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
    let raw_msg = std::str::from_utf8(value)?;
    let trimmed_msg = raw_msg.split_once(':').ok_or(SigningMessageError::BadSplit)?.1;
    let parsed_msg = serde_json::from_str(trimmed_msg)?;
    Ok(parsed_msg)
  }
}
