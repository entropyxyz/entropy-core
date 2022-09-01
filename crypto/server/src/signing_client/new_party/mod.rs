//! protocol runner for the `new_party` api
#![allow(dead_code)]
mod context;
mod signing_message;
mod tofn_protocol;
use bincode::Options;
use kvdb::kv_manager::{value::{PartyInfo, KvValue}, KvManager};
use tofn::gg20;
use tokio::sync::mpsc;
use tracing::{info, instrument};
use tofn::{
    gg20::{
        keygen::{KeygenPartyId, SecretKeyShare},
    },
    sdk::api::{PartyShareCounts},
};
pub use self::{context::SignContext, signing_message::SigningMessage, tofn_protocol::Channels};
use crate::{
  sign_init::SignInit,
  signing_client::{SignerState, SigningErr},
};

/// corresponds to https://github.com/axelarnetwork/tofnd/blob/0a70c4bb8c86b26804f59d0921dcd3235e85fdc0/src/gg20/service/mod.rs#L12
/// Thin wrapper around `SignerState`, manages execution of a signing party.
#[derive(Clone)]
pub struct Gg20Service<'a> {
  pub state:      &'a SignerState,
  pub kv_manager: &'a KvManager,
}

impl std::fmt::Debug for Gg20Service<'_> {
  // skip kv_manager
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Gg20Service").field("state", &self.state).finish()
  }
}

impl<'a> Gg20Service<'a> {
  pub fn new(state: &'a SignerState, kv_manager: &'a KvManager) -> Self {
    {
      Self { state, kv_manager }
    }
  }

  /// The Sign Context contains all relevant information for protocol execution, and is mostly
  /// stored in the kvdb, and is otherwise provided by the CM (`SignInit`).
  #[instrument]
  pub async fn get_sign_context(&self, sign_init: SignInit) -> Result<SignContext, SigningErr> {
    info!("check_sign_init: {sign_init:?}");
	let party_vec = self.kv_manager.kv().get(&sign_init.substrate_key).await.unwrap();
	let bincode = bincode::DefaultOptions::new();
	// let party_share_counts: PartyShareCounts<KeygenPartyId> = PartyShareCounts::from_vec(party_vec).unwrap();
	// dbg!(party_share_counts.clone());
	let value: SecretKeyShare = bincode.deserialize(&party_vec).unwrap();
	let party_info = PartyInfo::get_party_info(
		vec![value],
		vec!["test".to_string()],
		vec![0],
		0,
);
    // let party_info: PartyInfo = PartyInfo::try_from(party_vec).unwrap();
    Ok(SignContext::new(sign_init, party_info))
  }

  /// https://github.com/axelarnetwork/tofnd/blob/117a35b808663ceebfdd6e6582a3f0a037151198/src/gg20/sign/execute.rs#L22
  /// handle signing protocol execution.
  #[instrument(skip(channels))]
  pub async fn execute_sign(
    &self,
    ctx: &SignContext,
    channels: Channels,
  ) -> Result<Vec<u8>, SigningErr> {
    info!("execute_sign: {ctx:?}");
    let new_sign =
      gg20::sign::new_sign(ctx.group(), &ctx.share, &ctx.sign_parties, ctx.msg_to_sign())
        .map_err(|e| SigningErr::ProtocolExecution(format!("{e:?}")))?;

    let result =
      tofn_protocol::execute_protocol(new_sign, channels, &ctx.sign_uids(), &ctx.sign_share_counts)
        .await?
        .map_err(|e| SigningErr::ProtocolOutput(format!("{e:?}")))?;

    Ok(result)
  }

  // todo placeholder for any result handling
  #[instrument]
  #[allow(unused_variables)]
  pub fn handle_result(&self, signature: &[u8], sign_context: &SignContext) {
    info!("good job team");
  }
}
