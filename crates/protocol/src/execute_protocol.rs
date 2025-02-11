// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! A wrapper for the threshold signing library to handle sending and receiving messages.

use futures::future::try_join_all;
use num::bigint::BigUint;
use rand_core::{CryptoRngCore, OsRng};
use sp_core::{sr25519, Pair};
use std::sync::Arc;
use subxt::utils::AccountId32;
use synedrion::{
    ecdsa::VerifyingKey,
    k256::EncodedPoint,
    make_aux_gen_session, make_interactive_signing_session, make_key_init_session,
    make_key_resharing_session,
    sessions::{FinalizeOutcome, Session, SessionId as SynedrionSessionId},
    signature::{self, hazmat::RandomizedPrehashSigner},
    AuxInfo, KeyResharingInputs, KeyShare, NewHolder, OldHolder, PrehashedMessage,
    RecoverableSignature, ThresholdKeyShare,
};
use tokio::{sync::mpsc, task::spawn_blocking};

use crate::{
    errors::{GenericProtocolError, ProtocolExecutionErr},
    protocol_message::{ProtocolMessage, ProtocolMessagePayload},
    protocol_transport::Broadcaster,
    KeyParams, KeyShareWithAuxInfo, PartyId, SessionId, Subsession,
};

use std::collections::{BTreeSet, VecDeque};

pub type ChannelIn = mpsc::Receiver<ProtocolMessage>;
pub type ChannelOut = Broadcaster;

/// Thin wrapper broadcasting channel out and messages from other nodes in
pub struct Channels(pub ChannelOut, pub ChannelIn);

#[derive(Clone)]
pub struct PairWrapper(pub sr25519::Pair);

impl signature::Keypair for PairWrapper {
    type VerifyingKey = PartyId;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.public().into()
    }
}

impl RandomizedPrehashSigner<sr25519::Signature> for PairWrapper {
    fn sign_prehash_with_rng(
        &self,
        _rng: &mut impl CryptoRngCore,
        prehash: &[u8],
    ) -> Result<sr25519::Signature, signature::Error> {
        // TODO: doesn't seem like there's a way to randomize signing?
        Ok(self.0.sign(prehash))
    }
}

pub async fn execute_protocol_generic<Res: synedrion::ProtocolResult + 'static>(
    chans: &mut Channels,
    session: Session<Res, sr25519::Signature, PairWrapper, PartyId>,
    session_id_hash: [u8; 32],
) -> Result<Res::Success, GenericProtocolError<Res>>
where
    <Res as synedrion::ProtocolResult>::ProvableError: std::marker::Send,
    <Res as synedrion::ProtocolResult>::CorrectnessProof: std::marker::Send,
{
    let session_id = synedrion::SessionId::from_seed(&session_id_hash);
    let tx = &chans.0;
    let rx = &mut chans.1;

    let my_id = session.verifier();

    let mut session = session;
    let mut cached_messages = Vec::new();

    loop {
        let mut accum = session.make_accumulator();
        let current_round = session.current_round();
        let session_arc = Arc::new(session);

        // Send outgoing messages
        let destinations = session_arc.message_destinations();
        let join_handles = destinations.iter().map(|destination| {
            let session_arc = session_arc.clone();
            let tx = tx.clone();
            let my_id = my_id.clone();
            let destination = destination.clone();
            spawn_blocking(move || {
                session_arc
                    .make_message(&mut OsRng, &destination)
                    .map(|(message, artifact)| {
                        tx.send(ProtocolMessage::new(&my_id, &destination, message))
                            .map(|_| artifact)
                            .map_err(|err| {
                                let err: GenericProtocolError<Res> = err.into();
                                err
                            })
                    })
                    .map_err(|err| {
                        let err: GenericProtocolError<Res> = err.into();
                        err
                    })
            })
        });

        for result in try_join_all(join_handles).await? {
            accum.add_artifact(result??)?;
        }

        // Process cached messages
        let join_handles = cached_messages.into_iter().map(|preprocessed| {
            let session_arc = session_arc.clone();
            spawn_blocking(move || session_arc.process_message(&mut OsRng, preprocessed))
        });

        for result in try_join_all(join_handles).await? {
            accum.add_processed_message(result?)??;
        }

        // Receive and process incoming messages
        let (process_tx, mut process_rx) = mpsc::channel(1024);
        let mut messages_for_next_subprotocol = VecDeque::new();
        while !session_arc.can_finalize(&accum)? {
            tokio::select! {
                // Incoming message from remote peer
                maybe_message = rx.recv() => {
                    let message = maybe_message.ok_or_else(|| {
                        GenericProtocolError::IncomingStream(format!("{:?}", current_round))
                    })?;

                    if let ProtocolMessagePayload::MessageBundle(payload) = message.payload.clone() {
                        if payload.session_id() == &session_id {
                            // Perform quick checks before proceeding with the verification.
                            let preprocessed =
                                session_arc.preprocess_message(&mut accum, &message.from, *payload)?;

                            if let Some(preprocessed) = preprocessed {
                                let session_arc = session_arc.clone();
                                let tx = process_tx.clone();
                                tokio::spawn(async move {
                                    let result = session_arc.process_message(&mut OsRng, preprocessed);

                                    if futures::executor::block_on(tx.send(result)).is_err() {
                                        tracing::error!("Protocol finished before message processing result sent");
                                    }
                                });
                            }
                        } else {
                            tracing::warn!("Got protocol message with incorrect session ID - putting back in queue");
                            messages_for_next_subprotocol.push_back(message);
                        }
                    } else {
                        tracing::warn!("Got verifying key during protocol - ignoring");
                    }
                }

                // Result from processing a message
                maybe_result = process_rx.recv() => {
                    if let Some(result) = maybe_result {
                        accum.add_processed_message(result?)??;
                    }
                }
            }
        }

        for message in messages_for_next_subprotocol {
            tx.incoming_sender.send(message).await?;
        }

        // Get session back out of Arc
        let session_inner =
            Arc::try_unwrap(session_arc).map_err(|_| GenericProtocolError::ArcUnwrapError)?;
        match session_inner.finalize_round(&mut OsRng, accum)? {
            FinalizeOutcome::Success(res) => break Ok(res),
            FinalizeOutcome::AnotherRound {
                session: new_session,
                cached_messages: new_cached_messages,
            } => {
                session = new_session;
                cached_messages = new_cached_messages;
            },
        }
    }
}

/// Execute threshold signing protocol.
#[tracing::instrument(
    skip_all,
    fields(prehashed_message, threshold_accounts),
    level = tracing::Level::DEBUG
)]
pub async fn execute_signing_protocol(
    session_id: SessionId,
    mut chans: Channels,
    key_share: &KeyShare<KeyParams, PartyId>,
    aux_info: &AuxInfo<KeyParams, PartyId>,
    prehashed_message: &PrehashedMessage,
    threshold_pair: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
) -> Result<RecoverableSignature, ProtocolExecutionErr> {
    tracing::debug!("Executing signing protocol");
    tracing::trace!("Using key share with verifying key {:?}", &key_share.verifying_key());

    let party_ids: BTreeSet<PartyId> =
        threshold_accounts.iter().cloned().map(PartyId::new).collect();

    let pair = PairWrapper(threshold_pair.clone());

    let session_id_hash = session_id.blake2(None)?;

    let session = make_interactive_signing_session(
        &mut OsRng,
        SynedrionSessionId::from_seed(session_id_hash.as_slice()),
        pair,
        &party_ids,
        key_share,
        aux_info,
        prehashed_message,
    )
    .map_err(ProtocolExecutionErr::SessionCreation)?;

    Ok(execute_protocol_generic(&mut chans, session, session_id_hash).await?)
}

/// Execute dkg.
#[tracing::instrument(
    skip_all,
    fields(threshold_accounts, session_id, threshold),
    level = tracing::Level::DEBUG
)]
pub async fn execute_dkg(
    session_id: SessionId,
    mut chans: Channels,
    threshold_pair: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
    threshold: usize,
) -> Result<KeyShareWithAuxInfo, ProtocolExecutionErr> {
    tracing::debug!("Executing DKG");

    let party_ids: BTreeSet<PartyId> =
        threshold_accounts.iter().cloned().map(PartyId::new).collect();

    let pair = PairWrapper(threshold_pair.clone());

    let my_party_id = PartyId::new(AccountId32(threshold_pair.public().0));

    let session_id_hash = session_id.blake2(Some(Subsession::KeyInit))?;
    let (key_init_parties, includes_me) =
        get_key_init_parties(&my_party_id, threshold, &party_ids, &session_id_hash)?;

    let (verifying_key, old_holder, mut chans) = if includes_me {
        // First run the key init session.
        let session = make_key_init_session(
            &mut OsRng,
            SynedrionSessionId::from_seed(session_id_hash.as_slice()),
            pair.clone(),
            &key_init_parties,
        )
        .map_err(ProtocolExecutionErr::SessionCreation)?;

        let init_keyshare = execute_protocol_generic(&mut chans, session, session_id_hash).await?;

        tracing::info!("Finished key init protocol");

        // Send verifying key
        let verifying_key =
            init_keyshare.verifying_key().ok_or(ProtocolExecutionErr::NoValidatingKey)?;
        for party_id in party_ids.iter() {
            if !key_init_parties.contains(party_id) {
                let message = ProtocolMessage {
                    from: my_party_id.clone(),
                    to: party_id.clone(),
                    payload: ProtocolMessagePayload::VerifyingKey(
                        verifying_key.to_encoded_point(true).as_bytes().to_vec(),
                    ),
                };
                chans.0.send(message)?;
            }
        }
        (
            verifying_key,
            Some(OldHolder { key_share: ThresholdKeyShare::from_key_share(&init_keyshare) }),
            chans,
        )
    } else {
        // Wait to receive verifying_key
        let mut rx = chans.1;
        let broadcaster = chans.0;
        let message = rx.recv().await.ok_or_else(|| {
            ProtocolExecutionErr::IncomingStream("Waiting for validating key".to_string())
        })?;
        if let ProtocolMessagePayload::VerifyingKey(verifying_key_encoded) = message.payload {
            let point = EncodedPoint::from_bytes(verifying_key_encoded).map_err(|_| {
                ProtocolExecutionErr::BadVerifyingKey(
                    "Could not convert to encoded point".to_string(),
                )
            })?;
            let verifying_key = VerifyingKey::from_encoded_point(&point).map_err(|_| {
                ProtocolExecutionErr::BadVerifyingKey(
                    "Could not convert encoded point to verifying key".to_string(),
                )
            })?;

            let chans = Channels(broadcaster.clone(), rx);
            (verifying_key, None, chans)
        } else {
            return Err(ProtocolExecutionErr::UnexpectedMessage);
        }
    };

    // Now reshare to all n parties
    let inputs = KeyResharingInputs {
        old_holder,
        new_holder: Some(NewHolder {
            verifying_key,
            old_threshold: threshold,
            old_holders: key_init_parties.clone(),
        }),
        new_holders: party_ids.clone(),
        new_threshold: threshold,
    };

    let session_id_hash = session_id.blake2(Some(Subsession::Reshare))?;
    let session = make_key_resharing_session(
        &mut OsRng,
        SynedrionSessionId::from_seed(session_id_hash.as_slice()),
        pair.clone(),
        &party_ids,
        inputs,
    )
    .map_err(ProtocolExecutionErr::SessionCreation)?;
    let new_key_share_option =
        execute_protocol_generic(&mut chans, session, session_id_hash).await?;
    let new_key_share =
        new_key_share_option.ok_or(ProtocolExecutionErr::NoOutputFromReshareProtocol)?;
    tracing::info!("Finished reshare protocol");

    // Now run the aux gen protocol to get AuxInfo
    let session_id_hash = session_id.blake2(Some(Subsession::AuxGen))?;
    let session = make_aux_gen_session(
        &mut OsRng,
        SynedrionSessionId::from_seed(session_id_hash.as_slice()),
        pair,
        &party_ids,
    )
    .map_err(ProtocolExecutionErr::SessionCreation)?;
    let aux_info = execute_protocol_generic(&mut chans, session, session_id_hash).await?;
    tracing::info!("Finished aux gen protocol");

    Ok((new_key_share, aux_info))
}

/// Execute proactive refresh.
#[allow(clippy::type_complexity)]
#[tracing::instrument(
    skip_all,
    fields(threshold_accounts, my_idx),
    level = tracing::Level::DEBUG
)]
pub async fn execute_reshare(
    session_id: SessionId,
    mut chans: Channels,
    threshold_pair: &sr25519::Pair,
    inputs: KeyResharingInputs<KeyParams, PartyId>,
    verifiers: &BTreeSet<PartyId>,
    aux_info_option: Option<AuxInfo<KeyParams, PartyId>>,
) -> Result<
    (ThresholdKeyShare<KeyParams, PartyId>, AuxInfo<KeyParams, PartyId>),
    ProtocolExecutionErr,
> {
    tracing::info!("Executing reshare");
    tracing::debug!("Signing with {:?}", &threshold_pair.public());

    let pair = PairWrapper(threshold_pair.clone());

    let session_id_hash = session_id.blake2(None)?;

    let session = make_key_resharing_session(
        &mut OsRng,
        SynedrionSessionId::from_seed(session_id_hash.as_slice()),
        pair,
        verifiers,
        inputs.clone(),
    )
    .map_err(ProtocolExecutionErr::SessionCreation)?;

    let new_key_share = execute_protocol_generic(&mut chans, session, session_id_hash).await?;

    tracing::info!("Completed reshare protocol");

    let aux_info = if let Some(aux_info) = aux_info_option {
        aux_info
    } else {
        tracing::info!("Executing aux gen session as part of reshare");
        // Now run an aux gen session
        let session_id_hash_aux_data = session_id.blake2(Some(Subsession::AuxGen))?;
        let session = make_aux_gen_session(
            &mut OsRng,
            SynedrionSessionId::from_seed(session_id_hash_aux_data.as_slice()),
            PairWrapper(threshold_pair.clone()),
            &inputs.new_holders,
        )
        .map_err(ProtocolExecutionErr::SessionCreation)?;

        execute_protocol_generic(&mut chans, session, session_id_hash_aux_data).await?
    };

    Ok((new_key_share.ok_or(ProtocolExecutionErr::NoOutputFromReshareProtocol)?, aux_info))
}

/// Psuedo-randomly select a subset of the parties of size `threshold`
fn get_key_init_parties(
    my_party_id: &PartyId,
    threshold: usize,
    validators: &BTreeSet<PartyId>,
    session_id_hash: &[u8],
) -> Result<(BTreeSet<PartyId>, bool), ProtocolExecutionErr> {
    let validators = validators.iter().cloned().collect::<Vec<PartyId>>();
    let mut parties = BTreeSet::new();
    let mut includes_self = false;
    let number = BigUint::from_bytes_be(session_id_hash);
    let start_index_big = &number % validators.len();
    let start_index: usize = start_index_big.try_into()?;

    for i in start_index..start_index + threshold {
        let index = i % validators.len();
        let member = validators.get(index).ok_or(ProtocolExecutionErr::IndexOutOfBounds)?;
        if member == my_party_id {
            includes_self = true;
        }
        parties.insert(member.clone());
    }

    Ok((parties, includes_self))
}
