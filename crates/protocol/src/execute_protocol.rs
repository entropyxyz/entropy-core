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

use num::bigint::BigUint;
use rand_core::{CryptoRngCore, OsRng};
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32;
use synedrion::{
    ecdsa::VerifyingKey,
    k256::EncodedPoint,
    make_aux_gen_session, make_interactive_signing_session, make_key_init_session,
    make_key_resharing_session,
    sessions::{FinalizeOutcome, Session},
    signature::{self, hazmat::RandomizedPrehashSigner},
    AuxInfo, KeyResharingInputs, KeyShare, NewHolder, OldHolder, PrehashedMessage,
    RecoverableSignature, ThresholdKeyShare,
};
use tokio::sync::mpsc;

use crate::{
    errors::{GenericProtocolError, ProtocolExecutionErr},
    protocol_message::{ProtocolMessage, ProtocolMessagePayload},
    protocol_transport::Broadcaster,
    KeyParams, KeyShareWithAuxInfo, PartyId, SessionId,
};

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

async fn execute_protocol_generic<Res: synedrion::MappedResult<PartyId>>(
    mut chans: Channels,
    session: Session<Res, sr25519::Signature, PairWrapper, PartyId>,
) -> Result<(Res::MappedSuccess, mpsc::Receiver<ProtocolMessage>), GenericProtocolError<Res>> {
    let tx = &chans.0;
    let rx = &mut chans.1;

    let my_id = session.verifier();

    let mut session = session;
    let mut cached_messages = Vec::new();

    loop {
        let mut accum = session.make_accumulator();

        // Send out messages
        let destinations = session.message_destinations();
        // TODO (#641): this can happen in a spawned task
        for destination in destinations.iter() {
            let (message, artifact) = session.make_message(&mut OsRng, destination)?;
            tx.send(ProtocolMessage::new(&my_id, destination, message))?;

            // This will happen in a host task
            accum.add_artifact(artifact)?;
        }

        for preprocessed in cached_messages {
            // TODO (#641): this may happen in a spawned task.
            let processed = session.process_message(preprocessed)?;

            // This will happen in a host task.
            accum.add_processed_message(processed)??;
        }

        while !session.can_finalize(&accum)? {
            let (from, payload) = loop {
                let message = rx.recv().await.ok_or_else(|| {
                    GenericProtocolError::<Res>::IncomingStream(format!(
                        "{:?}",
                        session.current_round()
                    ))
                })?;

                if let ProtocolMessagePayload::CombinedMessage(payload) = message.payload {
                    break (message.from, *payload);
                } else {
                    tracing::warn!("Got verifying key during protocol - ignoring");
                }
            };

            // Perform quick checks before proceeding with the verification.
            let preprocessed = session.preprocess_message(&mut accum, &from, payload)?;

            if let Some(preprocessed) = preprocessed {
                // TODO (#641): this may happen in a spawned task.
                let result = session.process_message(preprocessed)?;

                // This will happen in a host task.
                accum.add_processed_message(result)??;
            }
        }

        match session.finalize_round(&mut OsRng, accum)? {
            FinalizeOutcome::Success(res) => break Ok((res, chans.1)),
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
    chans: Channels,
    key_share: &KeyShare<KeyParams, PartyId>,
    aux_info: &AuxInfo<KeyParams, PartyId>,
    prehashed_message: &PrehashedMessage,
    threshold_pair: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
) -> Result<RecoverableSignature, ProtocolExecutionErr> {
    tracing::debug!("Executing signing protocol");
    tracing::trace!("Using key share with verifying key {:?}", &key_share.verifying_key());

    let party_ids: Vec<PartyId> = threshold_accounts.iter().cloned().map(PartyId::new).collect();

    let pair = PairWrapper(threshold_pair.clone());

    let shared_randomness = session_id.blake2()?;

    let session = make_interactive_signing_session(
        &mut OsRng,
        &shared_randomness,
        pair,
        &party_ids,
        key_share,
        aux_info,
        prehashed_message,
    )
    .map_err(ProtocolExecutionErr::SessionCreation)?;

    Ok(execute_protocol_generic(chans, session).await?.0)
}

/// Execute dkg.
#[tracing::instrument(
    skip_all,
    fields(threshold_accounts, session_id, threshold),
    level = tracing::Level::DEBUG
)]
pub async fn execute_dkg(
    session_id: SessionId,
    chans: Channels,
    threshold_pair: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
    threshold: usize,
) -> Result<KeyShareWithAuxInfo, ProtocolExecutionErr> {
    tracing::debug!("Executing DKG");
    let broadcaster = chans.0.clone();

    let party_ids: Vec<PartyId> = threshold_accounts.iter().cloned().map(PartyId::new).collect();

    let pair = PairWrapper(threshold_pair.clone());

    let my_party_id = PartyId::new(AccountId32(threshold_pair.public().0));

    let shared_randomness = session_id.blake2()?;
    let (key_init_parties, includes_me) =
        get_key_init_parties(&my_party_id, threshold, &party_ids, &shared_randomness)?;

    let (verifying_key, old_holder, chans) = if includes_me {
        // First run the key init session.
        let session =
            make_key_init_session(&mut OsRng, &shared_randomness, pair.clone(), &key_init_parties)
                .map_err(ProtocolExecutionErr::SessionCreation)?;

        let (init_keyshare, rx) = execute_protocol_generic(chans, session).await?;

        // Setup channels for the next session
        let chans = Channels(broadcaster.clone(), rx);

        // Send verifying key
        let verifying_key = init_keyshare.verifying_key();
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
            Some(OldHolder { key_share: init_keyshare.to_threshold_key_share() }),
            chans,
        )
    } else {
        // Wait to receive verifying_key
        let mut rx = chans.1;
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

            // Setup channels for the next session
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
    let session = make_key_resharing_session(
        &mut OsRng,
        &shared_randomness,
        pair.clone(),
        &party_ids,
        &inputs,
    )
    .map_err(ProtocolExecutionErr::SessionCreation)?;
    let (new_key_share_option, rx) = execute_protocol_generic(chans, session).await?;
    let new_key_share =
        new_key_share_option.ok_or(ProtocolExecutionErr::NoOutputFromReshareProtocol)?;

    // Setup channels for the next session
    let chans = Channels(broadcaster.clone(), rx);

    // Now run the aux gen protocol to get AuxInfo
    let session = make_aux_gen_session(&mut OsRng, &shared_randomness, pair, &party_ids)
        .map_err(ProtocolExecutionErr::SessionCreation)?;
    let aux_info = execute_protocol_generic(chans, session).await?.0;

    Ok((new_key_share, aux_info))
}

/// Execute proactive refresh.
#[tracing::instrument(
    skip_all,
    fields(threshold_accounts, my_idx),
    level = tracing::Level::DEBUG
)]
pub async fn execute_proactive_refresh(
    session_id: SessionId,
    chans: Channels,
    threshold_pair: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
    old_key: ThresholdKeyShare<KeyParams, PartyId>,
) -> Result<ThresholdKeyShare<KeyParams, PartyId>, ProtocolExecutionErr> {
    tracing::debug!("Executing proactive refresh");
    tracing::debug!("Signing with {:?}", &threshold_pair.public());

    let party_ids: Vec<PartyId> = threshold_accounts.iter().cloned().map(PartyId::new).collect();
    let pair = PairWrapper(threshold_pair.clone());
    let verifying_key = old_key.verifying_key();

    let shared_randomness = session_id.blake2()?;
    let inputs = KeyResharingInputs {
        old_holder: Some(OldHolder { key_share: old_key }),
        new_holder: Some(NewHolder {
            verifying_key,
            old_threshold: party_ids.len(),
            old_holders: party_ids.clone(),
        }),
        new_holders: party_ids.clone(),
        new_threshold: party_ids.len(),
    };
    let session =
        make_key_resharing_session(&mut OsRng, &shared_randomness, pair, &party_ids, &inputs)
            .map_err(ProtocolExecutionErr::SessionCreation)?;

    let new_key_share = execute_protocol_generic(chans, session).await?.0;

    new_key_share.ok_or(ProtocolExecutionErr::NoOutputFromReshareProtocol)
}

/// Psuedo-randomly select a subset of the parties of size `threshold`
fn get_key_init_parties(
    my_party_id: &PartyId,
    threshold: usize,
    validators: &[PartyId],
    shared_randomness: &[u8],
) -> Result<(Vec<PartyId>, bool), ProtocolExecutionErr> {
    let mut parties = vec![];
    let mut includes_self = false;
    let number = BigUint::from_bytes_be(shared_randomness);
    let start_index_big = &number % validators.len();
    let start_index: usize = start_index_big.try_into()?;

    for i in start_index..start_index + threshold {
        let index = i % validators.len();
        let member = validators.get(index).ok_or(ProtocolExecutionErr::IndexOutOfBounds)?;
        if member == my_party_id {
            includes_self = true;
        }
        parties.push(member.clone());
    }

    Ok((parties, includes_self))
}
