//! A wrapper for the threshold signing library to handle sending and receiving messages.
use cggmp21::{
    sessions::{make_interactive_signing_session, PrehashedMessage, ToSend},
    KeyShare, Signature, TestSchemeParams,
};
use futures::StreamExt;
use kvdb::kv_manager::PartyId;
use rand_core::OsRng;
use tracing::instrument;

use crate::signing_client::{SigningErr, SigningMessage};

pub type ChannelIn = futures::stream::BoxStream<'static, super::SigningMessage>;
pub type ChannelOut = crate::signing_client::subscribe::Broadcaster;

/// Thin wrapper broadcasting channel out and messages from other nodes in
pub struct Channels(pub ChannelOut, pub ChannelIn);

/// execute gg20 protocol.
#[instrument(skip(chans))]
pub(super) async fn execute_protocol(
    mut chans: Channels,
    key_share: &KeyShare<PartyId, TestSchemeParams>,
    prehashed_message: &PrehashedMessage,
) -> Result<Signature, SigningErr> {
    let my_id = key_share.party();

    let tx = &chans.0;
    let rx = &mut chans.1;

    let mut session = make_interactive_signing_session(&mut OsRng, key_share, prehashed_message)
        .map_err(SigningErr::ProtocolExecution)?;

    while !session.is_final_stage() {
        let to_send = session.get_messages(&mut OsRng).map_err(SigningErr::ProtocolExecution)?;

        match to_send {
            ToSend::Broadcast { message, .. } => {
                tx.send(SigningMessage::new_bcast(my_id, &message))?;
            },
            ToSend::Direct(msgs) =>
                for (id_to, message) in msgs.into_iter() {
                    tx.send(SigningMessage::new_p2p(my_id, id_to, &message))?;
                },
        };

        while session.has_cached_messages() {
            session.receive_cached_message().unwrap();
        }

        while !session.is_finished_receiving().unwrap() {
            let signing_message = rx.next().await.ok_or_else(|| {
                SigningErr::IncomingStream(format!("{}", session.current_stage_num()))
            })?;
            // TODO: we shouldn't send broadcasts to ourselves in the first place.
            if signing_message.from == my_id {
                continue;
            }
            session
                .receive(&signing_message.from, &signing_message.payload)
                .map_err(SigningErr::ProtocolExecution)?;
        }

        session.finalize_stage(&mut OsRng).map_err(SigningErr::ProtocolExecution)?;
    }

    session.result().map_err(SigningErr::ProtocolOutput)
}
