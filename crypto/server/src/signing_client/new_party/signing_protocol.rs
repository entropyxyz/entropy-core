//! A wrapper for the threshold signing library to handle sending and receiving messages.
use std::collections::HashMap;

use blake2::{Blake2s256, Digest};
use futures::StreamExt;
use kvdb::kv_manager::PartyInfo;
use rand_core::OsRng;
use sp_core::crypto::{AccountId32, Pair};
use subxt::ext::sp_core::sr25519;
use synedrion::{
    sessions::{make_interactive_signing_session, PrehashedMessage, ToSend},
    PartyIdx, Signature,
};
use tracing::instrument;

use crate::signing_client::{SigningErr, SigningMessage};

pub type ChannelIn = futures::stream::BoxStream<'static, super::SigningMessage>;
pub type ChannelOut = crate::signing_client::subscribe::Broadcaster;

/// Thin wrapper broadcasting channel out and messages from other nodes in
pub struct Channels(pub ChannelOut, pub ChannelIn);

/// execute gg20 protocol.
#[instrument(skip(chans, threshold_signer))]
pub(super) async fn execute_protocol(
    mut chans: Channels,
    party_info: &PartyInfo,
    prehashed_message: &PrehashedMessage,
    threshold_signer: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
) -> Result<Signature, SigningErr> {
    let my_idx = party_info.share.party_index();
    let my_id = &party_info.party_ids[my_idx.as_usize()];

    let id_to_index = party_info
        .party_ids
        .iter()
        .enumerate()
        .map(|(idx, id)| (id, PartyIdx::from_usize(idx)))
        .collect::<HashMap<_, _>>();

    let tx = &chans.0;
    let rx = &mut chans.1;

    let mut session =
        make_interactive_signing_session(&mut OsRng, &party_info.share, prehashed_message)
            .map_err(SigningErr::ProtocolExecution)?;

    while !session.is_final_stage() {
        let to_send = session.get_messages(&mut OsRng).map_err(SigningErr::ProtocolExecution)?;

        match to_send {
            ToSend::Broadcast(message) => {
                let signed_message = create_signed_message(&message, threshold_signer);
                tx.send(SigningMessage::new_bcast(
                    my_id,
                    &message,
                    signed_message,
                    threshold_signer.public(),
                ))?;
            },
            ToSend::Direct(msgs) =>
                for (id_to, message) in msgs.into_iter() {
                    let signed_message = create_signed_message(&message, threshold_signer);
                    tx.send(SigningMessage::new_p2p(
                        my_id,
                        &party_info.party_ids[id_to.as_usize()],
                        &message,
                        signed_message,
                        threshold_signer.public(),
                    ))?;
                },
        };

        while session.has_cached_messages() {
            session
                .receive_cached_message()
                .map_err(|e| SigningErr::SessionError(e.to_string()))?;
        }

        while !session
            .is_finished_receiving()
            .map_err(|e| SigningErr::SessionError(e.to_string()))?
        {
            let signing_message = rx.next().await.ok_or_else(|| {
                SigningErr::IncomingStream(format!("{}", session.current_stage_num()))
            })?;
            let _ = validate_signed_message(
                &signing_message.payload,
                signing_message.signature,
                signing_message.sender_pk,
                &threshold_accounts,
            )
            .map_err(|e| SigningErr::MessageValidation(e.to_string()))?;
            // TODO: we shouldn't send broadcasts to ourselves in the first place.
            if &signing_message.from == my_id {
                continue;
            }
            let from_idx = id_to_index[&signing_message.from];
            session
                .receive(from_idx, &signing_message.payload)
                .map_err(SigningErr::ProtocolExecution)?;
        }

        session.finalize_stage(&mut OsRng).map_err(SigningErr::ProtocolExecution)?;
    }

    session.result().map_err(SigningErr::ProtocolOutput)
}

pub fn create_signed_message(message: &[u8], pair: &sr25519::Pair) -> sr25519::Signature {
    let mut hasher = Blake2s256::new();
    hasher.update(message);
    let hash = hasher.finalize().to_vec();
    pair.sign(&hash)
}

pub fn validate_signed_message(
    message: &Vec<u8>,
    signature: sr25519::Signature,
    sender_pk: sr25519::Public,
    threshold_accounts: &[AccountId32],
) -> Result<(), Box<SigningErr>> {
    let mut hasher = Blake2s256::new();
    hasher.update(message);
    let part_of_signers = threshold_accounts.contains(&AccountId32::new(sender_pk.0));
    if !part_of_signers {
        return Err(Box::new(SigningErr::MessageValidation(
            "Unable to verify sender of message".to_string(),
        )));
    }
    let hash = hasher.finalize().to_vec();
    let signature = <sr25519::Pair as Pair>::verify(&signature, hash, &sender_pk);
    if !signature {
        return Err(Box::new(SigningErr::MessageValidation(
            "Unable to verify origins of message".to_string(),
        )));
    }

    Ok(())
}
