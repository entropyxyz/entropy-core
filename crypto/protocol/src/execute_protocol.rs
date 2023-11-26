//! A wrapper for the threshold signing library to handle sending and receiving messages.

use rand_core::{CryptoRngCore, OsRng};
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32;
use synedrion::{
    sessions::{
        make_interactive_signing_session, make_key_refresh_session, make_keygen_and_aux_session,
        FinalizeOutcome, PrehashedMessage,
    },
    signature::{self, hazmat::RandomizedPrehashSigner},
    KeyShare, RecoverableSignature,
};
use tokio::sync::mpsc;

use crate::{
    errors::ProtocolExecutionErr, protocol_message::ProtocolMessage,
    protocol_transport::Broadcaster, KeyParams, PartyId,
};

pub type ChannelIn = mpsc::Receiver<ProtocolMessage>;
pub type ChannelOut = Broadcaster;

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

/// Execute threshold signing protocol.
#[tracing::instrument(
    skip_all,
    fields(prehashed_message, threshold_accounts),
    level = tracing::Level::DEBUG
)]
pub async fn execute_signing_protocol(
    mut chans: Channels,
    key_share: &KeyShare<KeyParams>,
    prehashed_message: &PrehashedMessage,
    threshold_pair: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
) -> Result<RecoverableSignature, ProtocolExecutionErr> {
    tracing::debug!("Executing signing protocol");
    tracing::trace!("Using key share {:?}", &key_share);

    let party_ids: Vec<PartyId> = threshold_accounts.iter().cloned().map(PartyId::new).collect();
    let my_idx = key_share.party_index();
    let my_id = party_ids.get(my_idx).ok_or(ProtocolExecutionErr::BadKeyShare(
        "Keyshare index is greater than the number of parties".to_string(),
    ))?;

    let tx = &chans.0;
    let rx = &mut chans.1;

    let pair = PairWrapper(threshold_pair.clone());

    // TODO (#375): this should come from whoever initiates the signing process,
    // (or as some deterministic function, e.g. the hash of the last block mined)
    // and be the same for all participants.
    let shared_randomness = b"123456";

    let mut session = make_interactive_signing_session(
        &mut OsRng,
        shared_randomness,
        pair,
        &party_ids,
        key_share,
        prehashed_message,
    )
    .map_err(ProtocolExecutionErr::SynedrionUsageError)?;

    let mut cached_messages = Vec::new();

    loop {
        let mut accum = session.make_accumulator();

        // Send out broadcasts
        let destinations = session.broadcast_destinations();
        if let Some(destinations) = destinations {
            // TODO: this can happen in a spawned task
            let message = session
                .make_broadcast(&mut OsRng)
                .map_err(ProtocolExecutionErr::SynedrionUsageError)?;
            for destination in destinations.iter() {
                tx.send(ProtocolMessage::new(my_id, destination, message.clone()))?;
            }
        }

        // Send out direct messages
        let destinations = session.direct_message_destinations();
        if let Some(destinations) = destinations {
            for destination in destinations.iter() {
                // TODO: this can happen in a spawned task.
                // The artefact will be sent back to the host task
                // to be added to the accumulator.
                let (message, artefact) = session
                    .make_direct_message(&mut OsRng, destination)
                    .map_err(ProtocolExecutionErr::SynedrionUsageError)?;
                tx.send(ProtocolMessage::new(my_id, destination, message))?;

                // This will happen in a host task
                accum.add_artefact(artefact).map_err(ProtocolExecutionErr::SynedrionUsageError)?;
            }
        }

        for preprocessed in cached_messages {
            // TODO: this may happen in a spawned task.
            let processed = session
                .process_message(preprocessed)
                .map_err(|err| ProtocolExecutionErr::SigningProtocolError(Box::new(err)))?;

            // This will happen in a host task.
            accum
                .add_processed_message(processed)
                .map_err(ProtocolExecutionErr::SynedrionUsageError)?
                .map_err(ProtocolExecutionErr::SynedrionRemoteError)?;
        }

        while !session.can_finalize(&accum).map_err(ProtocolExecutionErr::SynedrionUsageError)? {
            let message = rx.recv().await.ok_or_else(|| {
                ProtocolExecutionErr::IncomingStream(format!("{:?}", session.current_round()))
            })?;

            // Perform quick checks before proceeding with the verification.
            let preprocessed = session
                .preprocess_message(&mut accum, &message.from, message.payload)
                .map_err(|err| ProtocolExecutionErr::SigningProtocolError(Box::new(err)))?;

            if let Some(preprocessed) = preprocessed {
                // TODO: this may happen in a spawned task.
                let result = session
                    .process_message(preprocessed)
                    .map_err(|err| ProtocolExecutionErr::SigningProtocolError(Box::new(err)))?;

                // This will happen in a host task.
                accum
                    .add_processed_message(result)
                    .map_err(ProtocolExecutionErr::SynedrionUsageError)?
                    .map_err(ProtocolExecutionErr::SynedrionRemoteError)?;
            }
        }

        match session
            .finalize_round(&mut OsRng, accum)
            .map_err(|err| ProtocolExecutionErr::SigningProtocolError(Box::new(err)))?
        {
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

/// Execute dkg.
#[tracing::instrument(
    skip_all,
    fields(threshold_accounts, my_idx),
    level = tracing::Level::DEBUG
)]
pub async fn execute_dkg(
    mut chans: Channels,
    threshold_pair: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
    my_idx: &u8,
) -> Result<KeyShare<KeyParams>, ProtocolExecutionErr> {
    tracing::debug!("Executing DKG");

    let party_ids: Vec<PartyId> = threshold_accounts.iter().cloned().map(PartyId::new).collect();
    let my_id = party_ids.get(*my_idx as usize).ok_or(ProtocolExecutionErr::BadKeyShare(
        "Keyshare index is greater than the number of parties".to_string(),
    ))?;

    let tx = &chans.0;
    let rx = &mut chans.1;

    let pair = PairWrapper(threshold_pair.clone());

    // TODO (#375): this should come from whoever initiates the signing process,
    // (or as some deterministic function, e.g. the hash of the last block mined)
    // and be the same for all participants.
    let shared_randomness = b"123456";

    let mut session = make_keygen_and_aux_session(&mut OsRng, shared_randomness, pair, &party_ids)
        .map_err(ProtocolExecutionErr::SynedrionUsageError)?;

    let mut cached_messages = Vec::new();

    loop {
        let mut accum = session.make_accumulator();

        // Send out broadcasts
        let destinations = session.broadcast_destinations();
        if let Some(destinations) = destinations {
            // TODO: this can happen in a spawned task
            let message = session
                .make_broadcast(&mut OsRng)
                .map_err(ProtocolExecutionErr::SynedrionUsageError)?;
            for destination in destinations.iter() {
                tx.send(ProtocolMessage::new(my_id, destination, message.clone()))?;
            }
        }

        // Send out direct messages
        let destinations = session.direct_message_destinations();
        if let Some(destinations) = destinations {
            for destination in destinations.iter() {
                // TODO: this can happen in a spawned task.
                // The artefact will be sent back to the host task
                // to be added to the accumulator.
                let (message, artefact) = session
                    .make_direct_message(&mut OsRng, destination)
                    .map_err(ProtocolExecutionErr::SynedrionUsageError)?;
                tx.send(ProtocolMessage::new(my_id, destination, message))?;

                // This will happen in a host task
                accum.add_artefact(artefact).map_err(ProtocolExecutionErr::SynedrionUsageError)?;
            }
        }

        for preprocessed in cached_messages {
            // TODO: this may happen in a spawned task.
            let processed = session
                .process_message(preprocessed)
                .map_err(|err| ProtocolExecutionErr::KeyGenProtocolError(Box::new(err)))?;

            // This will happen in a host task.
            accum
                .add_processed_message(processed)
                .map_err(ProtocolExecutionErr::SynedrionUsageError)?
                .map_err(ProtocolExecutionErr::SynedrionRemoteError)?;
        }

        while !session.can_finalize(&accum).map_err(ProtocolExecutionErr::SynedrionUsageError)? {
            let message = rx.recv().await.ok_or_else(|| {
                ProtocolExecutionErr::IncomingStream(format!("{:?}", session.current_round()))
            })?;

            // Perform quick checks before proceeding with the verification.
            let preprocessed = session
                .preprocess_message(&mut accum, &message.from, message.payload)
                .map_err(|err| ProtocolExecutionErr::KeyGenProtocolError(Box::new(err)))?;

            if let Some(preprocessed) = preprocessed {
                // TODO: this may happen in a spawned task.
                let result = session
                    .process_message(preprocessed)
                    .map_err(|err| ProtocolExecutionErr::KeyGenProtocolError(Box::new(err)))?;

                // This will happen in a host task.
                accum
                    .add_processed_message(result)
                    .map_err(ProtocolExecutionErr::SynedrionUsageError)?
                    .map_err(ProtocolExecutionErr::SynedrionRemoteError)?;
            }
        }

        match session
            .finalize_round(&mut OsRng, accum)
            .map_err(|err| ProtocolExecutionErr::KeyGenProtocolError(Box::new(err)))?
        {
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

/// Execute proactive refresh.
#[tracing::instrument(
    skip_all,
    fields(threshold_accounts, my_idx),
    level = tracing::Level::DEBUG
)]
pub async fn execute_proactive_refresh(
    mut chans: Channels,
    threshold_pair: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
    my_idx: &u8,
    old_key: KeyShare<KeyParams>,
) -> Result<KeyShare<KeyParams>, ProtocolExecutionErr> {
    tracing::debug!("Executing proactive refresh");
    tracing::debug!("Signing with {:?}", &threshold_pair.public());
    tracing::trace!("Previous key {:?}", &old_key);

    let party_ids: Vec<PartyId> = threshold_accounts.iter().cloned().map(PartyId::new).collect();
    let my_id = party_ids.get(*my_idx as usize).ok_or(ProtocolExecutionErr::BadKeyShare(
        "Keyshare index is greater than the number of parties".to_string(),
    ))?;

    let tx = &chans.0;
    let rx = &mut chans.1;

    let pair = PairWrapper(threshold_pair.clone());

    // TODO (#375): this should come from whoever initiates the signing process,
    // (or as some deterministic function, e.g. the hash of the last block mined)
    // and be the same for all participants.
    let shared_randomness = b"123456";

    let mut session = make_key_refresh_session(&mut OsRng, shared_randomness, pair, &party_ids)
        .map_err(ProtocolExecutionErr::SynedrionUsageError)?;

    let mut cached_messages = Vec::new();

    let key_change = loop {
        let mut accum = session.make_accumulator();

        // Send out broadcasts
        let destinations = session.broadcast_destinations();
        if let Some(destinations) = destinations {
            // TODO: this can happen in a spawned task
            let message = session
                .make_broadcast(&mut OsRng)
                .map_err(ProtocolExecutionErr::SynedrionUsageError)?;
            for destination in destinations.iter() {
                tx.send(ProtocolMessage::new(my_id, destination, message.clone()))?;
            }
        }

        // Send out direct messages
        let destinations = session.direct_message_destinations();
        if let Some(destinations) = destinations {
            for destination in destinations.iter() {
                // TODO: this can happen in a spawned task.
                // The artefact will be sent back to the host task
                // to be added to the accumulator.
                let (message, artefact) = session
                    .make_direct_message(&mut OsRng, destination)
                    .map_err(ProtocolExecutionErr::SynedrionUsageError)?;
                tx.send(ProtocolMessage::new(my_id, destination, message))?;

                // This will happen in a host task
                accum.add_artefact(artefact).map_err(ProtocolExecutionErr::SynedrionUsageError)?;
            }
        }

        for preprocessed in cached_messages {
            // TODO: this may happen in a spawned task.
            let processed = session
                .process_message(preprocessed)
                .map_err(|err| ProtocolExecutionErr::KeyRefreshProtocolError(Box::new(err)))?;

            // This will happen in a host task.
            accum
                .add_processed_message(processed)
                .map_err(ProtocolExecutionErr::SynedrionUsageError)?
                .map_err(ProtocolExecutionErr::SynedrionRemoteError)?;
        }

        while !session.can_finalize(&accum).map_err(ProtocolExecutionErr::SynedrionUsageError)? {
            let message = rx.recv().await.ok_or_else(|| {
                ProtocolExecutionErr::IncomingStream(format!("{:?}", session.current_round()))
            })?;

            // Perform quick checks before proceeding with the verification.
            let preprocessed = session
                .preprocess_message(&mut accum, &message.from, message.payload)
                .map_err(|err| ProtocolExecutionErr::KeyRefreshProtocolError(Box::new(err)))?;

            if let Some(preprocessed) = preprocessed {
                // TODO: this may happen in a spawned task.
                let result = session
                    .process_message(preprocessed)
                    .map_err(|err| ProtocolExecutionErr::KeyRefreshProtocolError(Box::new(err)))?;

                // This will happen in a host task.
                accum
                    .add_processed_message(result)
                    .map_err(ProtocolExecutionErr::SynedrionUsageError)?
                    .map_err(ProtocolExecutionErr::SynedrionRemoteError)?;
            }
        }

        match session
            .finalize_round(&mut OsRng, accum)
            .map_err(|err| ProtocolExecutionErr::KeyRefreshProtocolError(Box::new(err)))?
        {
            FinalizeOutcome::Success(res) => break res,
            FinalizeOutcome::AnotherRound {
                session: new_session,
                cached_messages: new_cached_messages,
            } => {
                session = new_session;
                cached_messages = new_cached_messages;
            },
        }
    };

    Ok(old_key.update(key_change))
}
