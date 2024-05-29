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

use rand_core::{CryptoRngCore, OsRng};
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32;
use synedrion::{
    make_interactive_signing_session, make_key_gen_session, make_key_resharing_session,
    sessions::{FinalizeOutcome, Session},
    signature::{self, hazmat::RandomizedPrehashSigner},
    AuxInfo, KeyResharingInputs, NewHolder, OldHolder, PrehashedMessage, RecoverableSignature,
    ThresholdKeyShare,
};
use tokio::sync::mpsc;

use crate::{
    errors::{GenericProtocolError, ProtocolExecutionErr},
    protocol_message::ProtocolMessage,
    protocol_transport::Broadcaster,
    KeyParams, PartyId, SessionId,
};

pub type ChannelIn = mpsc::Receiver<ProtocolMessage>;
pub type ChannelOut = Broadcaster;
type KeyShareWithAuxInfo = (ThresholdKeyShare<KeyParams, PartyId>, AuxInfo<KeyParams, PartyId>);

/// Thin wrapper broadcasting channel out and messages from other nodes in
pub struct Channels(pub ChannelOut, pub ChannelIn);

struct PairWrapper(sr25519::Pair);

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
) -> Result<Res::MappedSuccess, GenericProtocolError<Res>> {
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
            let message = rx.recv().await.ok_or_else(|| {
                GenericProtocolError::IncomingStream(format!("{:?}", session.current_round()))
            })?;

            // Perform quick checks before proceeding with the verification.
            let preprocessed =
                session.preprocess_message(&mut accum, &message.from, message.payload)?;

            if let Some(preprocessed) = preprocessed {
                // TODO (#641): this may happen in a spawned task.
                let result = session.process_message(preprocessed)?;

                // This will happen in a host task.
                accum.add_processed_message(result)??;
            }
        }

        match session.finalize_round(&mut OsRng, accum)? {
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
    chans: Channels,
    key_share: &ThresholdKeyShare<KeyParams, PartyId>,
    aux_info: &AuxInfo<KeyParams, PartyId>,
    prehashed_message: &PrehashedMessage,
    threshold_pair: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
) -> Result<RecoverableSignature, ProtocolExecutionErr> {
    tracing::debug!("Executing signing protocol");
    // tracing::trace!("Using key share {:?}", &key_share);

    let party_ids: Vec<PartyId> = threshold_accounts.iter().cloned().map(PartyId::new).collect();

    let pair = PairWrapper(threshold_pair.clone());

    let shared_randomness = session_id.blake2()?;

    let session = make_interactive_signing_session(
        &mut OsRng,
        &shared_randomness,
        pair,
        &party_ids,
        &key_share.to_key_share(&party_ids),
        aux_info,
        prehashed_message,
    )
    .map_err(ProtocolExecutionErr::SessionCreation)?;

    Ok(execute_protocol_generic(chans, session).await?)
}

/// Execute dkg.
#[tracing::instrument(
    skip_all,
    fields(threshold_accounts, my_idx),
    level = tracing::Level::DEBUG
)]
pub async fn execute_dkg(
    session_id: SessionId,
    chans: Channels,
    threshold_pair: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
) -> Result<KeyShareWithAuxInfo, ProtocolExecutionErr> {
    tracing::debug!("Executing DKG");

    let party_ids: Vec<PartyId> = threshold_accounts.iter().cloned().map(PartyId::new).collect();

    let pair = PairWrapper(threshold_pair.clone());

    let shared_randomness = session_id.blake2()?;

    let session = make_key_gen_session(&mut OsRng, &shared_randomness, pair, &party_ids)
        .map_err(ProtocolExecutionErr::SessionCreation)?;

    let (keyshare, aux_info) = execute_protocol_generic(chans, session).await?;
    Ok((keyshare.to_threshold_key_share(), aux_info))
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

    let new_key_share = execute_protocol_generic(chans, session).await?;

    Ok(new_key_share.ok_or(ProtocolExecutionErr::NoOutputFromReshareProtocol)?)
}
