#![allow(dead_code)]
//! helpers for the `new_party` api
mod context;
mod sign_init;
mod signing_message;
// mod protocol_manager;

// use kvdb::kv_manager::KvManager;

use kvdb::kv_manager::value::PartyInfo;
use tokio::sync::mpsc;
use tracing::{info, instrument};

pub use self::{
  context::SignContext,
  sign_init::{SignInit, SignInitUnchecked},
  signing_message::SigningMessage,
};
use super::{SignerState, SigningProtocolError, SubscribeError};

pub type Channels = (mpsc::Sender<SigningMessage>, mpsc::Receiver<SigningMessage>);
pub type SigningProtocolResult = Result<Signature, SigningProtocolError>;
type Signature = String; // todo

/// corresponds to https://github.com/axelarnetwork/tofnd/blob/0a70c4bb8c86b26804f59d0921dcd3235e85fdc0/src/gg20/service/mod.rs#L12
/// Thin wrapper around `SignerState`, manages execution of a signing party.
#[derive(Debug, Clone)]
pub struct Gg20Service<'a> {
  pub state: &'a SignerState,
}

impl<'a> Gg20Service<'a> {
  pub fn new(state: &'a SignerState) -> Self {
    {
      Self { state }
    }
  }

  #[instrument]
  pub async fn check_sign_init(
    &self,
    sign_init: SignInitUnchecked,
  ) -> Result<SignContext, SigningProtocolError> {
    info!("check_sign_init: {sign_init:?}");

    // let party_info: PartyInfo =
    //   match self.state.kv_manager.kv().get(&sign_init.key_uid.to_string()).await {
    //     Ok(value) => value.try_into()?,
    //     Err(err) => {
    //       // if no such session id exists, send a message to client that indicates that recovery
    // is       // needed and stop sign
    //       Self::send_kv_store_failure(out_stream)?;
    //       let err = anyhow!(
    //         "Unable to find session-id {} in kv store. Issuing share recovery and exit sign
    // {:?}",         sign_init.key_uid,
    //         err
    //       );
    //       return Err(err);
    //     },
    //   };

    // let info = info.check();

    Err(SigningProtocolError::Init("init"))
  }

  #[instrument]
  pub async fn subscribe_and_await_subscribers(
    &self,
    sign_context: &SignContext,
  ) -> Result<Channels, SigningProtocolError> {
    info!("subscribe_and_await_subscribers: {sign_context:?}");
    Err(SigningProtocolError::Subscribing("subscribbb"))
  }

  #[instrument]
  pub async fn execute_sign(
    &self,
    sign_context: &SignContext,
    channels: Channels,
  ) -> SigningProtocolResult {
    info!("execute_sign: {sign_context:?}");
    Err(SigningProtocolError::Signing("signnnn"))
  }

  // placeholder for any result handling
  #[instrument]
  pub fn handle_result(&self, result: SigningProtocolResult, sign_context: SignContext) {
    info!("good job team");
  }
}
