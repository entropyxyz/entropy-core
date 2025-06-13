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

//! A wrapper for the threshold signing library to handle sending and receiving messages

use blake2::{Blake2s256, Digest};
use k256::{ecdsa::VerifyingKey, EncodedPoint};
use manul::{
    protocol::Protocol,
    session::{
        tokio::{par_run_session, MessageIn, MessageOut},
        Session, SessionId as ManulSessionId, SessionOutcome,
    },
    signature::RandomizedDigestSigner,
};
use num::bigint::BigUint;
use rand_core::{CryptoRngCore, OsRng};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use subxt::utils::AccountId32;
use synedrion::{
    signature::{self},
    AuxGen, AuxInfo, InteractiveSigning, KeyInit, KeyResharing, KeyShare, NewHolder, OldHolder,
    PrehashedMessage, RecoverableSignature, ThresholdKeyShare,
};
use tokio::sync::mpsc;

use crate::{
    errors::ProtocolExecutionErr,
    protocol_message::{ProtocolMessage, ProtocolMessagePayload},
    protocol_transport::Broadcaster,
    EntropySessionParameters, KeyParams, KeyShareWithAuxInfo, PartyId, SessionId, Subsession,
};

use std::collections::BTreeSet;

/// For incoming protocol messages
pub type ChannelIn = mpsc::Receiver<ProtocolMessage>;
/// For outgoing protocol messages
pub type ChannelOut = Broadcaster;

/// Thin wrapper broadcasting channel out and messages from other nodes in
pub struct Channels(pub ChannelOut, pub ChannelIn);

/// Wraps [sr25519::Pair] with the needed traits to using for signing protocol messages
#[derive(Clone)]
pub struct PairWrapper(pub sr25519::Pair);

impl signature::Keypair for PairWrapper {
    type VerifyingKey = PartyId;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.public().into()
    }
}

impl RandomizedDigestSigner<Blake2s256, sr25519::Signature> for PairWrapper {
    fn try_sign_digest_with_rng(
        &self,
        _rng: &mut impl CryptoRngCore,
        prehash: Blake2s256,
    ) -> Result<sr25519::Signature, signature::Error> {
        // TODO: doesn't seem like there's a way to randomize signing?
        let hash = prehash.finalize();
        Ok(self.0.sign(&hash))
    }
}

impl std::fmt::Debug for PairWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0.public())
    }
}

/// Execute any of the protocols with a given session
pub async fn execute_protocol_generic<P>(
    mut chans: Channels,
    session: Session<P, EntropySessionParameters>,
) -> Result<(P::Result, Channels), ProtocolExecutionErr>
where
    P: Protocol<PartyId>,
    <P as manul::protocol::Protocol<PartyId>>::ProtocolError: std::marker::Send,
    <P as manul::protocol::Protocol<PartyId>>::ProtocolError: Sync,
    <P as manul::protocol::Protocol<PartyId>>::Result: std::marker::Send,
{
    let (tx_in, mut rx_in) = mpsc::channel::<MessageIn<EntropySessionParameters>>(1024);
    let (tx_out, mut rx_out) = mpsc::channel::<MessageOut<EntropySessionParameters>>(1024);

    // Handle outgoing messages
    let broadcast_out = chans.0.clone();
    tokio::spawn(async move {
        while let Some(msg_out) = rx_out.recv().await {
            if let Err(err) = broadcast_out.send(ProtocolMessage::new(
                &msg_out.from,
                &msg_out.to,
                msg_out.message,
            )) {
                tracing::error!("Cannot write outgoing message to channel: {err:?}");
                break;
            }
        }
    });

    // Handle incoming messages
    let (stop_signal_tx, mut stop_signal_rx) = mpsc::channel(1);
    let join_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                protocol_message_option = chans.1.recv() => {
                    if let Some(protocol_message) = protocol_message_option {
                        let from = protocol_message.from;
                        if let ProtocolMessagePayload::Message(message) = protocol_message.payload {
                            if let Err(err) = tx_in.send(MessageIn { from, message: *message }).await {
                                tracing::error!("Cannot write incoming message to channel: {err:?}");
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                }
                _ = stop_signal_rx.recv() => {
                    break;
                }
            }
        }
        chans
    });

    // Run protocol
    let session_report = par_run_session(&mut OsRng, &tx_out, &mut rx_in, session).await?;

    // Send closing signal to incoming message loop so we can get channels back
    stop_signal_tx.send(()).await?;
    let chans = join_handle.await?;

    match session_report.outcome {
        SessionOutcome::Result(output) => Ok((output, chans)),
        SessionOutcome::Terminated => Err(ProtocolExecutionErr::Terminated),
        SessionOutcome::NotEnoughMessages => Err(ProtocolExecutionErr::NotEnoughMessages),
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
    prehashed_message: &PrehashedMessage<k256::Secp256k1>,
    threshold_pair: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
) -> Result<RecoverableSignature<KeyParams>, ProtocolExecutionErr> {
    tracing::debug!("Executing signing protocol");
    tracing::trace!("Using key share with verifying key {:?}", &key_share.verifying_key());

    let party_ids: BTreeSet<PartyId> =
        threshold_accounts.iter().cloned().map(PartyId::new).collect();
    let aux_info = aux_info.clone().subset(&party_ids)?;

    let pair = PairWrapper(threshold_pair.clone());

    let session_id_hash = session_id.blake2(None)?;

    let entry_point =
        InteractiveSigning::new(*prehashed_message, key_share.clone(), aux_info.clone())?;

    let session = Session::<_, EntropySessionParameters>::new(
        &mut OsRng,
        ManulSessionId::from_seed::<EntropySessionParameters>(session_id_hash.as_slice()),
        pair,
        entry_point,
    )?;

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

    let party_ids: BTreeSet<PartyId> =
        threshold_accounts.iter().cloned().map(PartyId::new).collect();

    let pair = PairWrapper(threshold_pair.clone());

    let my_party_id = PartyId::new(AccountId32(threshold_pair.public().0));

    let session_id_hash = session_id.blake2(Some(Subsession::KeyInit))?;
    let (key_init_parties, includes_me) =
        get_key_init_parties(&my_party_id, threshold, &party_ids, &session_id_hash)?;

    let (verifying_key, old_holder, chans) = if includes_me {
        // First run the key init session.
        let entry_point = KeyInit::new(key_init_parties.clone())?;
        let session = Session::<_, EntropySessionParameters>::new(
            &mut OsRng,
            ManulSessionId::from_seed::<EntropySessionParameters>(session_id_hash.as_slice()),
            pair.clone(),
            entry_point,
        )?;

        let (init_keyshare, chans) = execute_protocol_generic(chans, session).await?;

        tracing::info!("Finished key init protocol");

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
    let entry_point = KeyResharing::<KeyParams, PartyId>::new(
        old_holder,
        Some(NewHolder::<KeyParams, PartyId> {
            verifying_key,
            old_threshold: threshold,
            old_holders: key_init_parties,
        }),
        party_ids.clone(),
        threshold,
    );

    let session_id_hash = session_id.blake2(Some(Subsession::Reshare))?;
    let manul_session_id =
        ManulSessionId::from_seed::<EntropySessionParameters>(session_id_hash.as_slice());

    let session = Session::<_, EntropySessionParameters>::new(
        &mut OsRng,
        manul_session_id,
        pair.clone(),
        entry_point,
    )?;

    let (new_key_share_option, chans) = execute_protocol_generic(chans, session).await?;

    let new_key_share =
        new_key_share_option.ok_or(ProtocolExecutionErr::NoOutputFromReshareProtocol)?;
    tracing::info!("Finished reshare protocol");
    tokio::task::yield_now().await;

    // Now run the aux gen protocol to get AuxInfo
    let entry_point = AuxGen::new(party_ids)?;

    let session_id_hash = session_id.blake2(Some(Subsession::AuxGen))?;

    let session = Session::<_, EntropySessionParameters>::new(
        &mut OsRng,
        ManulSessionId::from_seed::<EntropySessionParameters>(session_id_hash.as_slice()),
        pair.clone(),
        entry_point,
    )?;

    let (aux_info, _) = execute_protocol_generic(chans, session).await?;
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
    chans: Channels,
    threshold_pair: &sr25519::Pair,
    entry_point: KeyResharing<KeyParams, PartyId>,
    verifiers: &BTreeSet<PartyId>,
    aux_info_option: Option<AuxInfo<KeyParams, PartyId>>,
) -> Result<
    (ThresholdKeyShare<KeyParams, PartyId>, AuxInfo<KeyParams, PartyId>),
    ProtocolExecutionErr,
> {
    tracing::info!("Executing reshare");

    tracing::debug!("Signing with {:?}", &threshold_pair.public().to_ss58check());

    let pair = PairWrapper(threshold_pair.clone());

    let session_id_hash = session_id.blake2(Some(Subsession::Reshare))?;

    let session = Session::<_, EntropySessionParameters>::new(
        &mut OsRng,
        ManulSessionId::from_seed::<EntropySessionParameters>(session_id_hash.as_slice()),
        pair.clone(),
        entry_point,
    )?;

    let (new_key_share, chans) = execute_protocol_generic(chans, session).await?;

    tracing::info!("Completed reshare protocol");

    let aux_info = if let Some(aux_info) = aux_info_option {
        aux_info
    } else {
        tracing::info!("Executing aux gen session as part of reshare");
        // Now run an aux gen session
        let session_id_hash_aux_data = session_id.blake2(Some(Subsession::AuxGen))?;

        let entry_point = AuxGen::new(verifiers.clone())?;

        let session = Session::<_, EntropySessionParameters>::new(
            &mut OsRng,
            ManulSessionId::from_seed::<EntropySessionParameters>(
                session_id_hash_aux_data.as_slice(),
            ),
            pair.clone(),
            entry_point,
        )?;

        execute_protocol_generic(chans, session).await?.0
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
