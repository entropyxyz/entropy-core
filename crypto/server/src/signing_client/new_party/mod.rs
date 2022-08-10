//! helpers for the `new_party` api
mod context;
mod protocol_manager;

// use kvdb::kv_manager::KvManager;

use non_substrate_common::SignInitUnchecked;
use tokio::sync::mpsc;
use tracing::{info, instrument};

pub use self::{
  context::SignContext,
  protocol_manager::{ProtocolManager, SigningMessage},
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
  pub fn check_sign_init(
    &self,
    info: &SignInitUnchecked,
  ) -> Result<SignContext, SigningProtocolError> {
    info!("check_sign_init: {info:?}");
    todo!()
  }

  #[instrument]
  pub async fn subscribe_and_await_subscribers(
    &self,
    sign_context: &SignContext,
  ) -> Result<Channels, SigningProtocolError> {
    info!("subscribe_and_await_subscribers: {sign_context:?}");
    todo!()
  }

  #[instrument]
  pub async fn execute_sign(
    &self,
    sign_context: &SignContext,
    channels: Channels,
  ) -> SigningProtocolResult {
    info!("execute_sign: {sign_context:?}");
    todo!()
  }

  // placeholder for any result handling
  #[instrument]
  pub fn handle_result(&self, result: SigningProtocolResult, sign_context: SignContext) {
    info!("good job team");
  }
}
