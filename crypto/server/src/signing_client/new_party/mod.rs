//! helpers for the `new_party` api
#![allow(dead_code)]
mod context;
mod sign_init;
mod signing_message;

use kvdb::kv_manager::value::PartyInfo;
use tofn::gg20;
use tokio::sync::mpsc;
use tracing::{info, instrument};

pub use self::{context::SignContext, sign_init::SignInit, signing_message::SigningMessage};
use super::{SignerState, SigningProtocolError, SubscribeError};

pub type Channels = (mpsc::Sender<SigningMessage>, mpsc::Receiver<SigningMessage>);
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
  pub async fn get_sign_context(
    &self,
    sign_init: SignInit,
  ) -> Result<SignContext, SigningProtocolError> {
    info!("check_sign_init: {sign_init:?}");

    let party_info: PartyInfo = self
      .state
      .kv_manager
      .kv()
      .get(&sign_init.key_uid)
      .await
      .map_err(|e| SigningProtocolError::KvError(e))?
      .try_into()?;

    Ok(SignContext::new(sign_init, party_info))
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
    ctx: &SignContext,
    channels: Channels,
  ) -> Result<Signature, SigningProtocolError> {
    info!("execute_sign: {ctx:?}");
    let sign = gg20::sign::new_sign(ctx.group(), &ctx.share, &ctx.sign_parties, ctx.msg_to_sign())
      .map_err(|_| anyhow::anyhow!("sign instantiation failed"))?;
    Err(SigningProtocolError::Signing("signnnn"))
  }

  // placeholder for any result handling
  #[instrument]
  pub fn handle_result(&self, signature: Signature, sign_context: SignContext) {
    info!("good job team");
  }
}
