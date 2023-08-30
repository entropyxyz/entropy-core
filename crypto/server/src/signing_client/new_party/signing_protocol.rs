//! A wrapper for the threshold signing library to handle sending and receiving messages.
use std::collections::HashMap;

use kvdb::kv_manager::{KeyParams, PartyId};
use rand_core::{CryptoRngCore, OsRng};
use sp_core::crypto::AccountId32;
use subxt::ext::sp_core::{sr25519, Pair};
use synedrion::{
    sessions::{
        make_interactive_signing_session, make_keygen_and_aux_session, FinalizeOutcome,
        PrehashedMessage, ToSend,
    },
    signature::{
        self,
        hazmat::{PrehashVerifier, RandomizedPrehashSigner},
    },
    KeyShare, PartyIdx, RecoverableSignature,
};
use tokio::sync::mpsc;
use tracing::instrument;

use crate::signing_client::{SigningErr, SigningMessage};

pub type ChannelIn = mpsc::Receiver<super::SigningMessage>;
pub type ChannelOut = crate::signing_client::protocol_transport::Broadcaster;

/// Thin wrapper broadcasting channel out and messages from other nodes in
pub struct Channels(pub ChannelOut, pub ChannelIn);

struct SignerWrapper(sr25519::Pair);

#[derive(Clone)]
struct VerifierWrapper(sr25519::Public);

impl RandomizedPrehashSigner<sr25519::Signature> for SignerWrapper {
    fn sign_prehash_with_rng(
        &self,
        _rng: &mut impl CryptoRngCore,
        prehash: &[u8],
    ) -> Result<sr25519::Signature, signature::Error> {
        // TODO: doesn't seem like there's a way to randomize signing?
        Ok(self.0.sign(prehash))
    }
}

impl PrehashVerifier<sr25519::Signature> for VerifierWrapper {
    fn verify_prehash(
        &self,
        prehash: &[u8],
        signature: &sr25519::Signature,
    ) -> Result<(), signature::Error> {
        if sr25519::Pair::verify(signature, prehash, &self.0) {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}

/// execute threshold signing protocol.
#[instrument(skip(chans, threshold_signer))]
pub(super) async fn execute_protocol(
    mut chans: Channels,
    key_share: &KeyShare<KeyParams>,
    prehashed_message: &PrehashedMessage,
    threshold_signer: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
) -> Result<RecoverableSignature, SigningErr> {
    let party_ids: Vec<PartyId> =
        threshold_accounts.clone().into_iter().map(PartyId::new).collect();
    let my_idx = key_share.party_index();
    let my_id = &party_ids[my_idx.as_usize()];

    let id_to_index = party_ids
        .iter()
        .enumerate()
        .map(|(idx, id)| (id, PartyIdx::from_usize(idx)))
        .collect::<HashMap<_, _>>();

    let tx = &chans.0;
    let rx = &mut chans.1;

    let signer = SignerWrapper(threshold_signer.clone());
    // TODO (#376): while `Public::from_raw` happens to work here, it is not the correct way.
    // We should have `Public` objects at this point, not `AccountId32`.
    let verifiers = threshold_accounts
        .into_iter()
        .map(|acc| VerifierWrapper(sr25519::Public::from_raw(acc.into())))
        .collect::<Vec<_>>();

    // TODO (#375): this should come from whoever initiates the signing process,
    // (or as some deterministic function, e.g. the hash of the last block mined)
    // and be the same for all participants.
    let shared_randomness = b"123456";

    let mut sending = make_interactive_signing_session(
        &mut OsRng,
        shared_randomness,
        signer,
        &verifiers,
        key_share,
        prehashed_message,
    )
    .map_err(SigningErr::SessionCreationError)?;

    loop {
        let (mut receiving, to_send) =
            sending.start_receiving(&mut OsRng).map_err(SigningErr::ProtocolExecution)?;

        match to_send {
            ToSend::Broadcast(message) => {
                tx.send(SigningMessage::new_bcast(my_id, message))?;
            },
            ToSend::Direct(msgs) =>
                for (id_to, message) in msgs.into_iter() {
                    tx.send(SigningMessage::new_p2p(my_id, &party_ids[id_to.as_usize()], message))?;
                },
        };

        while receiving.has_cached_messages() {
            receiving.receive_cached_message().map_err(SigningErr::ProtocolExecution)?;
        }

        while !receiving.can_finalize() {
            let signing_message = rx.recv().await.ok_or_else(|| {
                SigningErr::IncomingStream(format!("{:?}", receiving.current_stage()))
            })?;

            // TODO: we shouldn't send broadcasts to ourselves in the first place.
            if &signing_message.from == my_id {
                continue;
            }
            let from_idx = id_to_index[&signing_message.from];
            receiving
                .receive(from_idx, signing_message.payload)
                .map_err(SigningErr::ProtocolExecution)?;
        }

        match receiving.finalize(&mut OsRng).map_err(SigningErr::ProtocolExecution)? {
            FinalizeOutcome::Result(res) => break Ok(res),
            FinalizeOutcome::AnotherRound(new_sending) => sending = new_sending,
        }
    }
}

/// Execute dkg.
#[instrument(skip(chans, threshold_signer))]
pub async fn execute_dkg(
    mut chans: Channels,
    threshold_signer: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
    my_idx: &u8,
) -> Result<KeyShare<KeyParams>, SigningErr> {
    let party_ids: Vec<PartyId> =
        threshold_accounts.clone().into_iter().map(PartyId::new).collect();
    let my_id = PartyId::new(threshold_accounts[*my_idx as usize].clone());
    let id_to_index = party_ids
        .iter()
        .enumerate()
        .map(|(idx, id)| (id, PartyIdx::from_usize(idx)))
        .collect::<HashMap<_, _>>();

    let tx = &chans.0;
    let rx = &mut chans.1;

    let signer = SignerWrapper(threshold_signer.clone());
    // TODO (#376): while `Public::from_raw` happens to work here, it is not the correct way.
    // We should have `Public` objects at this point, not `AccountId32`.
    let verifiers = threshold_accounts
        .into_iter()
        .map(|acc| VerifierWrapper(sr25519::Public::from_raw(acc.into())))
        .collect::<Vec<_>>();

    // TODO (#375): this should come from whoever initiates the signing process,
    // (or as some deterministic function, e.g. the hash of the last block mined)
    // and be the same for all participants.
    let shared_randomness = b"123456";

    let mut sending = make_keygen_and_aux_session(
        &mut OsRng,
        shared_randomness,
        signer,
        &verifiers,
        PartyIdx::from_usize(*my_idx as usize),
    )
    .map_err(SigningErr::SessionCreationError)?;

    loop {
        let (mut receiving, to_send) =
            sending.start_receiving(&mut OsRng).map_err(SigningErr::ProtocolExecution)?;

        match to_send {
            ToSend::Broadcast(message) => {
                tx.send(SigningMessage::new_bcast(&my_id, message))?;
            },
            ToSend::Direct(msgs) =>
                for (id_to, message) in msgs.into_iter() {
                    tx.send(SigningMessage::new_p2p(
                        &my_id,
                        &party_ids[id_to.as_usize()],
                        message,
                    ))?;
                },
        };

        while receiving.has_cached_messages() {
            receiving.receive_cached_message().map_err(SigningErr::ProtocolExecution)?;
        }

        while !receiving.can_finalize() {
            let signing_message = rx.recv().await.ok_or_else(|| {
                SigningErr::IncomingStream(format!("{:?}", receiving.current_stage()))
            })?;

            // TODO: we shouldn't send broadcasts to ourselves in the first place.
            if signing_message.from == my_id {
                continue;
            }
            let from_idx = id_to_index[&signing_message.from];
            receiving
                .receive(from_idx, signing_message.payload)
                .map_err(SigningErr::ProtocolExecution)?;
        }

        match receiving.finalize(&mut OsRng).map_err(SigningErr::ProtocolExecution)? {
            FinalizeOutcome::Result(res) => break Ok(res),
            FinalizeOutcome::AnotherRound(new_sending) => sending = new_sending,
        }
    }
}
