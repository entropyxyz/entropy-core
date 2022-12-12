//! A wrapper to the `tofn` to handle sending and receiving messages.
use anyhow::anyhow;
use futures::StreamExt;
use tofn::{
    collections::TypedUsize,
    sdk::api::{Protocol, ProtocolOutput, Round, TofnResult},
};
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    time::{sleep, Duration},
};
use tracing::{debug, error, instrument, span, warn, Level, Span};

use crate::signing_client::{SigningErr, SigningMessage};

pub type ChannelIn = futures::stream::BoxStream<'static, super::SigningMessage>;
pub type ChannelOut = crate::signing_client::subscribe::Broadcaster;

/// Thin wrapper broadcasting channel out and messages from other nodes in
pub struct Channels(pub ChannelOut, pub ChannelIn);

/// https://github.com/axelarnetwork/tofnd/blob/117a35b808663ceebfdd6e6582a3f0a037151198/src/gg20/protocol.rs#L20
/// execute gg20 protocol.
#[instrument(skip(party, chans))]
pub(super) async fn execute_protocol<F, K, P, const MAX_MSG_IN_LEN: usize>(
    mut party: Protocol<F, K, P, MAX_MSG_IN_LEN>,
    mut chans: Channels,
    party_uids: &[String],
    party_share_counts: &[usize],
    index: usize,
) -> Result<ProtocolOutput<F, P>, SigningErr>
where
    K: Clone,
{
    info!("entering protocol execution");
    let mut round_count = 0;

    // We can receive messages from the nodes that have already completed this round
    // and started the next one; those will be stored here until we're in the next round too.
    let mut message_cache = Vec::<SigningMessage>::new();

    while let Protocol::NotDone(mut round) = party {
        round_count += 1;

        for message in message_cache.drain(..) {
            let from = party_uids
                .iter()
                .position(|uid| uid == &message.from_party_uid)
                .ok_or_else(|| anyhow!("from uid does not exist in party uids"))?;

            if round.msg_in(TypedUsize::from_usize(from), &message.payload).is_err() {
                return Err(SigningErr::ProtocolOutput(format!(
                    "error calling tofn::msg_in with [from: {from}]"
                )));
            }
        }

        // handle outgoing traffic
        handle_outgoing(&chans.0, &round, party_uids, round_count, index)?;

        // collect incoming traffic
        handle_incoming(
            &mut chans.1,
            &mut round,
            &mut message_cache,
            party_uids,
            round_count,
            index,
        )
        .await?;

        // check if everything was ok this round (note tofn-fatal)
        party =
            round.execute_next_round().map_err(|_| anyhow!("Error in tofn::execute_next_round"))?;
    }

    match party {
        Protocol::NotDone(_) => Err(SigningErr::ProtocolOutput("not done".into())),
        Protocol::Done(result) => Ok(result),
    }
}

fn as_str(v: &[u8]) -> String { format!("{:?}", &v[8..16]) }

fn handle_outgoing<F, K, P, const MAX_MSG_IN_LEN: usize>(
    channel_out: &ChannelOut,
    round: &Round<F, K, P, MAX_MSG_IN_LEN>,
    party_uids: &[String],
    round_count: usize,
    index: usize,
) -> Result<(), SigningErr> {
    // send outgoing bcasts
    if let Some(bcast) = round.bcast_out() {
        // send message to gRPC client
        channel_out.send(SigningMessage::new_bcast(round_count, bcast, index, party_uids))?;
    }

    // send outgoing p2ps
    if let Some(p2ps_out) = round.p2ps_out() {
        for (i, p2p) in p2ps_out.iter() {
            // get tofnd index from tofn
            let tofnd_idx = round
                .info()
                .party_share_counts()
                .share_to_party_id(i)
                .map_err(|_| anyhow!("Unable to get tofnd index for party {}", i))?;

            // send message to gRPC client
            channel_out.send(SigningMessage::new_p2p(round_count, p2p, index, party_uids))?;
        }
    }
    Ok(())
}

async fn handle_incoming<F, K, P, const MAX_MSG_IN_LEN: usize>(
    channel_in: &mut ChannelIn,
    round: &mut Round<F, K, P, MAX_MSG_IN_LEN>,
    message_cache: &mut Vec<SigningMessage>,
    party_uids: &[String],
    round_count: usize,
    index: usize, // span: Span,
) -> Result<(), SigningErr> {
    // loop until no more messages are needed for this round
    while round.expecting_more_msgs_this_round() {
        // get internal message from broadcaster
        let traffic = channel_in
            .next()
            .await
            .ok_or(format!("{round_count}: stream closed by client before protocol has completed"));

        // unpeel TrafficIn
        let traffic = match traffic {
            Ok(traffic_opt) => traffic_opt,
            Err(_) => {
                // if channel is closed, stop
                error!("internal channel closed prematurely");
                break;
            },
        };

        // We have to spawn a new span it in each loop because `async` calls don't work well with
        // tracing See details on how we need to make spans curve around `.await`s here:
        // https://docs.rs/tracing/0.1.25/tracing/span/index.html#entering-a-span
        // let recv_span = span!(parent: &span, Level::DEBUG, "incoming", round = round_count);
        // let _start = recv_span.enter();

        // A message from another node that has already started the next round; stash it.
        if traffic.round == round_count + 1 {
            message_cache.push(traffic);
            continue;
        } else if traffic.round != round_count {
            let msg = format!("Received a message from an unexpected round {}", traffic.round);
            return Err(SigningErr::ProtocolOutput(msg));
        }

        // get sender's party index
        let from = party_uids
            .iter()
            .position(|uid| uid == &traffic.from_party_uid)
            .ok_or_else(|| anyhow!("from uid does not exist in party uids"))?;

        // try to set a message
        if round.msg_in(TypedUsize::from_usize(from), &traffic.payload).is_err() {
            return Err(SigningErr::ProtocolOutput(format!(
                "error calling tofn::msg_in with [from: {from}]"
            )));
        }
    }
    Ok(())
}
