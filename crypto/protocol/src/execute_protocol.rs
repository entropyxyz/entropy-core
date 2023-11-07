//! A wrapper for the threshold signing library to handle sending and receiving messages.
use std::collections::HashMap;

use rand_core::{CryptoRngCore, OsRng};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use subxt::utils::AccountId32;
use subxt_signer::sr25519;
use synedrion::{
    sessions::{
        make_interactive_signing_session, make_key_refresh_session, make_keygen_and_aux_session,
        FinalizeOutcome, PrehashedMessage, ToSend,
    },
    signature::{
        self,
        hazmat::{PrehashVerifier, RandomizedPrehashSigner},
    },
    KeyShare, PartyIdx, RecoverableSignature,
};
use tokio::sync::mpsc;
use tracing::instrument;

use crate::{
    errors::ProtocolExecutionErr, protocol_message::ProtocolMessage,
    protocol_transport::Broadcaster, KeyParams, PartyId,
};

pub type ChannelIn = mpsc::Receiver<ProtocolMessage>;
pub type ChannelOut = Broadcaster;

/// Thin wrapper broadcasting channel out and messages from other nodes in
pub struct Channels(pub ChannelOut, pub ChannelIn);

struct SignerWrapper(sr25519::Keypair);

struct VerifierWrapper(sr25519::PublicKey);

impl Clone for VerifierWrapper {
    fn clone(&self) -> Self {
        VerifierWrapper(sr25519::PublicKey(self.0 .0))
    }
}

/// This is a raw signature from [sr25519::Signature]
// we cannot use Signature directly because it doesn't implement Serialize
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct SignatureWrapper(#[serde(with = "BigArray")] [u8; 64]);

impl RandomizedPrehashSigner<SignatureWrapper> for SignerWrapper {
    fn sign_prehash_with_rng(
        &self,
        _rng: &mut impl CryptoRngCore,
        prehash: &[u8],
    ) -> Result<SignatureWrapper, signature::Error> {
        // TODO: doesn't seem like there's a way to randomize signing?
        Ok(SignatureWrapper(self.0.sign(prehash).0))
    }
}

impl PrehashVerifier<SignatureWrapper> for VerifierWrapper {
    fn verify_prehash(
        &self,
        prehash: &[u8],
        signature: &SignatureWrapper,
    ) -> Result<(), signature::Error> {
        let sig = sr25519::Signature(signature.0);
        if sr25519::verify(&sig, prehash, &self.0) {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}

/// Execute threshold signing protocol.
#[instrument(skip(chans, threshold_signer))]
pub async fn execute_signing_protocol(
    mut chans: Channels,
    key_share: &KeyShare<KeyParams>,
    prehashed_message: &PrehashedMessage,
    threshold_signer: &sr25519::Keypair,
    threshold_accounts: Vec<AccountId32>,
) -> Result<RecoverableSignature, ProtocolExecutionErr> {
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
        .map(|acc| VerifierWrapper(sr25519::PublicKey(acc.0)))
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
    .map_err(ProtocolExecutionErr::SessionCreationError)?;

    loop {
        let (mut receiving, to_send) =
            sending.start_receiving(&mut OsRng).map_err(ProtocolExecutionErr::SynedrionSession)?;

        match to_send {
            ToSend::Broadcast(message) => {
                tx.send(ProtocolMessage::new_bcast(my_id, message))?;
            },
            ToSend::Direct(msgs) => {
                for (id_to, message) in msgs.into_iter() {
                    tx.send(ProtocolMessage::new_p2p(
                        my_id,
                        &party_ids[id_to.as_usize()],
                        message,
                    ))?;
                }
            },
        };

        while receiving.has_cached_messages() {
            receiving.receive_cached_message().map_err(ProtocolExecutionErr::SynedrionSession)?;
        }

        while !receiving.can_finalize() {
            let signing_message = rx.recv().await.ok_or_else(|| {
                ProtocolExecutionErr::IncomingStream(format!("{:?}", receiving.current_stage()))
            })?;

            // TODO: we shouldn't send broadcasts to ourselves in the first place.
            if &signing_message.from == my_id {
                continue;
            }
            let from_idx = id_to_index[&signing_message.from];
            receiving
                .receive(from_idx, signing_message.payload)
                .map_err(ProtocolExecutionErr::SynedrionSession)?;
        }

        match receiving.finalize(&mut OsRng).map_err(ProtocolExecutionErr::SynedrionSession)? {
            FinalizeOutcome::Result(res) => break Ok(res),
            FinalizeOutcome::AnotherRound(new_sending) => sending = new_sending,
        }
    }
}

/// Execute dkg.
#[instrument(skip(chans, threshold_signer))]
pub async fn execute_dkg(
    mut chans: Channels,
    threshold_signer: &sr25519::Keypair,
    threshold_accounts: Vec<AccountId32>,
    my_idx: &u8,
) -> Result<KeyShare<KeyParams>, ProtocolExecutionErr> {
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
        .map(|acc| VerifierWrapper(sr25519::PublicKey(acc.0)))
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
    .map_err(ProtocolExecutionErr::SessionCreationError)?;

    loop {
        let (mut receiving, to_send) =
            sending.start_receiving(&mut OsRng).map_err(ProtocolExecutionErr::SynedrionSession)?;

        match to_send {
            ToSend::Broadcast(message) => {
                tx.send(ProtocolMessage::new_bcast(&my_id, message))?;
            },
            ToSend::Direct(msgs) => {
                for (id_to, message) in msgs.into_iter() {
                    tx.send(ProtocolMessage::new_p2p(
                        &my_id,
                        &party_ids[id_to.as_usize()],
                        message,
                    ))?;
                }
            },
        };

        while receiving.has_cached_messages() {
            receiving.receive_cached_message().map_err(ProtocolExecutionErr::SynedrionSession)?;
        }

        while !receiving.can_finalize() {
            let signing_message = rx.recv().await.ok_or_else(|| {
                ProtocolExecutionErr::IncomingStream(format!("{:?}", receiving.current_stage()))
            })?;

            // TODO: we shouldn't send broadcasts to ourselves in the first place.
            if signing_message.from == my_id {
                continue;
            }
            let from_idx = id_to_index[&signing_message.from];
            receiving
                .receive(from_idx, signing_message.payload)
                .map_err(ProtocolExecutionErr::SynedrionSession)?;
        }

        match receiving.finalize(&mut OsRng).map_err(ProtocolExecutionErr::SynedrionSession)? {
            FinalizeOutcome::Result(res) => break Ok(res),
            FinalizeOutcome::AnotherRound(new_sending) => sending = new_sending,
        }
    }
}

/// Execute proactive refresh.
#[instrument(skip(chans, threshold_signer))]
pub async fn execute_proactive_refresh(
    mut chans: Channels,
    threshold_signer: &sr25519::Keypair,
    threshold_accounts: Vec<AccountId32>,
    my_idx: &u8,
    old_key: KeyShare<KeyParams>,
) -> Result<KeyShare<KeyParams>, ProtocolExecutionErr> {
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
        .map(|acc| VerifierWrapper(sr25519::PublicKey(acc.0)))
        .collect::<Vec<_>>();

    // TODO (#375): this should come from whoever initiates the signing process,
    // (or as some deterministic function, e.g. the hash of the last block mined)
    // and be the same for all participants.
    let shared_randomness = b"123456";

    let mut sending = make_key_refresh_session(
        &mut OsRng,
        shared_randomness,
        signer,
        &verifiers,
        PartyIdx::from_usize(*my_idx as usize),
    )
    .map_err(ProtocolExecutionErr::SessionCreationError)?;
    let key_change = loop {
        let (mut receiving, to_send) =
            sending.start_receiving(&mut OsRng).map_err(ProtocolExecutionErr::SynedrionSession)?;

        match to_send {
            ToSend::Broadcast(message) => {
                tx.send(ProtocolMessage::new_bcast(&my_id, message))?;
            },
            ToSend::Direct(msgs) => {
                for (id_to, message) in msgs.into_iter() {
                    tx.send(ProtocolMessage::new_p2p(
                        &my_id,
                        &party_ids[id_to.as_usize()],
                        message,
                    ))?;
                }
            },
        };

        while receiving.has_cached_messages() {
            receiving.receive_cached_message().map_err(ProtocolExecutionErr::SynedrionSession)?;
        }

        while !receiving.can_finalize() {
            let signing_message = rx.recv().await.ok_or_else(|| {
                ProtocolExecutionErr::IncomingStream(format!("{:?}", receiving.current_stage()))
            })?;

            // TODO: we shouldn't send broadcasts to ourselves in the first place.
            if signing_message.from == my_id {
                continue;
            }
            let from_idx = id_to_index[&signing_message.from];
            receiving
                .receive(from_idx, signing_message.payload)
                .map_err(ProtocolExecutionErr::SynedrionSession)?;
        }

        match receiving.finalize(&mut OsRng).map_err(ProtocolExecutionErr::SynedrionSession)? {
            FinalizeOutcome::Result(res) => break res,
            FinalizeOutcome::AnotherRound(new_sending) => sending = new_sending,
        }
    };

    Ok(old_key.update(key_change))
}
