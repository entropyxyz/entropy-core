//! protocol runner for the `new_party` api
#![allow(dead_code)]
mod context;
mod signing_message;

use kvdb::kv_manager::{value::PartyInfo, KvManager};
use tofn::gg20;
use tokio::sync::mpsc;
use tracing::{info, instrument};

pub use self::{context::SignContext, signing_message::SigningMessage};
use crate::{
  sign_init::SignInit,
  signing_client::{SignerState, SigningErr},
};

/// Thin wrapper around message stream in and broadcast channel out
pub struct Channels(
  pub futures::stream::BoxStream<'static, SigningMessage>,
  pub super::subscribe::Broadcaster,
);

/// corresponds to https://github.com/axelarnetwork/tofnd/blob/0a70c4bb8c86b26804f59d0921dcd3235e85fdc0/src/gg20/service/mod.rs#L12
/// Thin wrapper around `SignerState`, manages execution of a signing party.
#[derive(Clone)]
pub struct Gg20Service<'a> {
  pub state: &'a SignerState,
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
    // info!("check_sign_init: {sign_init:?}");
    let party_info: PartyInfo =
      self.kv_manager.kv().get(&sign_init.substrate_key).await?.try_into()?;
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
    // info!("execute_sign: {ctx:?}");
    let new_sign =
      gg20::sign::new_sign(ctx.group(), &ctx.share, &ctx.sign_parties, ctx.msg_to_sign())
        .map_err(|e| SigningErr::TofnFatal(format!("{e:?}")))?;

    let result =
      protocol::execute_protocol(new_sign, channels, ctx.sign_uids(), &ctx.sign_share_counts)
        .await?
        .map_err(|e| SigningErr::ProtocolOutput(format!("{e:?}")))?;

    Ok(result)
  }

  // placeholder for any result handling
  #[instrument]
  #[allow(unused_variables)]
  pub fn handle_result(&self, signature: &[u8], sign_context: &SignContext) {
    info!("good job team");
  }
}

// todo: eventually, move this out, convenient to have it here for now
mod protocol {
  #![allow(dead_code)]
  #![allow(unused_variables)]
  #![allow(unused_imports)]
  #![allow(unused_mut)]
  use anyhow::anyhow;
  use tofn::{
    collections::TypedUsize,
    sdk::api::{Protocol, ProtocolOutput, Round},
  };
  use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
  use tracing::{debug, error, span, warn, Level, Span};

  use crate::signing_client::SigningErr;

  /// https://github.com/axelarnetwork/tofnd/blob/117a35b808663ceebfdd6e6582a3f0a037151198/src/gg20/protocol.rs#L20
  /// execute gg20 protocol
  pub(super) async fn execute_protocol<F, K, P, const MAX_MSG_IN_LEN: usize>(
    mut party: Protocol<F, K, P, MAX_MSG_IN_LEN>,
    mut chans: super::Channels,
    // ProtocolCommunication<
    //   Option<proto::TrafficIn>,
    //   Result<proto::MessageOut, tonic::Status>,
    // >,
    party_uids: Vec<String>,
    party_share_counts: &[usize],
  ) -> Result<ProtocolOutput<F, P>, SigningErr>
  where
    K: Clone,
  {
    // set up counters for logging
    // let total_num_of_shares = party_share_counts.iter().fold(0, |acc, s| acc + *s);
    // let total_round_p2p_msgs = total_num_of_shares * (total_num_of_shares - 1); // total number
    // of messages is n(n-1)

    // let mut round_count = 0;
    // while let Protocol::NotDone(mut round) = party {
    //   round_count += 1;

    //   // handle outgoing traffic
    //   handle_outgoing(&chans.sender, &round, party_uids, round_count, span.clone())?;

    //   // collect incoming traffic
    //   handle_incoming(
    //     &mut chans.receiver,
    //     &mut round,
    //     party_uids,
    //     total_round_p2p_msgs,
    //     total_num_of_shares,
    //     round_count,
    //     span.clone(),
    //   )
    //   .await?;

    //   // check if everything was ok this round
    //   party =
    //     round.execute_next_round().map_err(|_| anyhow!("Error in tofn::execute_next_round"))?;
    // }

    // match party {
    //   Protocol::NotDone(_) => Err(anyhow!("Protocol failed to complete")),
    //   Protocol::Done(result) => Ok(result),
    // };
    Err(SigningErr::ProtocolExecution("boom boom".to_string()))
  }
}
