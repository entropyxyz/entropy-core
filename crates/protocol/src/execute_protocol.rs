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

use blake2::{Blake2s256, Digest};
use k256::{ecdsa::VerifyingKey, EncodedPoint};
use manul::{
    protocol::{PartyId, Protocol},
    session::{
        tokio::{par_run_session, MessageIn, MessageOut},
        Session, SessionId as ManulSessionId, SessionOutcome, SessionReport,
    },
    signature::RandomizedDigestSigner,
};
use num::bigint::BigUint;
use rand_core::{CryptoRngCore, OsRng};
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32;
use synedrion::{
    signature::{self},
    AuxGen, AuxInfo, InteractiveSigning, KeyInit, KeyResharing, KeyShare, NewHolder, OldHolder,
    PrehashedMessage, RecoverableSignature, ThresholdKeyShare,
};
use tokio::sync::mpsc;
use tracing::debug;

use crate::{
    errors::{GenericProtocolError, ProtocolExecutionErr},
    protocol_message::{ProtocolMessage, ProtocolMessagePayload},
    protocol_transport::Broadcaster,
    EntropySessionParameters, KeyParams, KeyShareWithAuxInfo, PartyId as EntropyPartyId, SessionId,
    Subsession,
};

use std::collections::BTreeSet;

pub type ChannelIn = mpsc::Receiver<ProtocolMessage>;
pub type ChannelOut = Broadcaster;

/// Thin wrapper broadcasting channel out and messages from other nodes in
pub struct Channels(pub ChannelOut, pub ChannelIn);

#[derive(Clone)]
pub struct PairWrapper(pub sr25519::Pair);

impl signature::Keypair for PairWrapper {
    type VerifyingKey = EntropyPartyId;

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
        todo!()
    }
}

pub async fn execute_protocol_generic<P>(
    mut chans: Channels,
    session: Session<P, EntropySessionParameters>,
) -> (P::Result, Channels)
where
    P: Protocol<EntropyPartyId>,
    <P as manul::protocol::Protocol<EntropyPartyId>>::ProtocolError: std::marker::Send,
    <P as manul::protocol::Protocol<EntropyPartyId>>::ProtocolError: Sync,
{
    let (tx_in, mut rx_in) = mpsc::channel::<MessageIn<EntropySessionParameters>>(1024);
    let (tx_out, mut rx_out) = mpsc::channel::<MessageOut<EntropySessionParameters>>(1024);

    let broadcast_out = chans.0.clone();
    tokio::spawn(async move {
        while let Some(msg_out) = rx_out.recv().await {
            broadcast_out
                .send(ProtocolMessage::new(&msg_out.from, &msg_out.to, msg_out.message))
                .unwrap();
        }
    });

    let join_handle = tokio::spawn(async move {
        while let Some(protocol_message) = chans.1.recv().await {
            let from = protocol_message.from;
            if let ProtocolMessagePayload::Message(message) = protocol_message.payload {
                tx_in.send(MessageIn { from, message }).await.unwrap();
            }
        }
        debug!("Channel handling finished");
        chans
    });

    debug!("Session starting");
    let session_report = par_run_session(&mut OsRng, &tx_out, &mut rx_in, session).await.unwrap();
    debug!("session finished");

    if let SessionOutcome::Result(output) = session_report.outcome {
        let chans = join_handle.await.unwrap();
        return (output, chans);
    } else {
        panic!("Session not successful");
    };
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
    key_share: &KeyShare<KeyParams, EntropyPartyId>,
    aux_info: &AuxInfo<KeyParams, EntropyPartyId>,
    prehashed_message: &PrehashedMessage<k256::Secp256k1>,
    threshold_pair: &sr25519::Pair,
    threshold_accounts: Vec<AccountId32>,
) -> Result<RecoverableSignature<KeyParams>, ProtocolExecutionErr> {
    tracing::debug!("Executing signing protocol");
    tracing::trace!("Using key share with verifying key {:?}", &key_share.verifying_key());

    let party_ids: BTreeSet<EntropyPartyId> =
        threshold_accounts.iter().cloned().map(EntropyPartyId::new).collect();

    let pair = PairWrapper(threshold_pair.clone());

    let session_id_hash = session_id.blake2(None)?;

    let entry_point =
        InteractiveSigning::new(prehashed_message.clone(), key_share.clone(), aux_info.clone())
            .unwrap();
    let session = Session::<_, EntropySessionParameters>::new(
        &mut OsRng,
        ManulSessionId::from_seed::<EntropySessionParameters>(session_id_hash.as_slice()),
        pair,
        entry_point,
    )
    .unwrap();

    Ok(execute_protocol_generic(chans, session).await.0)
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

    let party_ids: BTreeSet<EntropyPartyId> =
        threshold_accounts.iter().cloned().map(EntropyPartyId::new).collect();

    let pair = PairWrapper(threshold_pair.clone());

    let my_party_id = EntropyPartyId::new(AccountId32(threshold_pair.public().0));

    let session_id_hash = session_id.blake2(Some(Subsession::KeyInit))?;
    let (key_init_parties, includes_me) =
        get_key_init_parties(&my_party_id, threshold, &party_ids, &session_id_hash)?;

    let (verifying_key, old_holder, chans) = if includes_me {
        // First run the key init session.
        let entry_point = KeyInit::new(key_init_parties.clone()).unwrap();
        let session = Session::<_, EntropySessionParameters>::new(
            &mut OsRng,
            ManulSessionId::from_seed::<EntropySessionParameters>(session_id_hash.as_slice()),
            pair.clone(),
            entry_point,
        )
        .unwrap();
        //.map_err(ProtocolExecutionErr::SessionCreation)?;

        let (init_keyshare, chans) = execute_protocol_generic(chans, session).await;

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
    let entry_point = KeyResharing::<KeyParams, EntropyPartyId>::new(
        old_holder,
        Some(NewHolder::<KeyParams, EntropyPartyId> {
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
    )
    .unwrap();
    //.map_err(ProtocolExecutionErr::SessionCreation)?;

    let (new_key_share_option, chans) = execute_protocol_generic(chans, session).await;

    let new_key_share =
        new_key_share_option.ok_or(ProtocolExecutionErr::NoOutputFromReshareProtocol)?;
    tracing::info!("Finished reshare protocol");

    // Now run the aux gen protocol to get AuxInfo
    let entry_point = AuxGen::new(party_ids).unwrap();

    let session_id_hash = session_id.blake2(Some(Subsession::AuxGen))?;

    let session = Session::<_, EntropySessionParameters>::new(
        &mut OsRng,
        ManulSessionId::from_seed::<EntropySessionParameters>(session_id_hash.as_slice()),
        pair.clone(),
        entry_point,
    )
    .unwrap();
    //.map_err(ProtocolExecutionErr::SessionCreation)?;

    let (aux_info, _) = execute_protocol_generic(chans, session).await;
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
    entry_point: KeyResharing<KeyParams, EntropyPartyId>,
    verifiers: &BTreeSet<EntropyPartyId>,
    aux_info_option: Option<AuxInfo<KeyParams, EntropyPartyId>>,
) -> Result<
    (ThresholdKeyShare<KeyParams, EntropyPartyId>, AuxInfo<KeyParams, EntropyPartyId>),
    ProtocolExecutionErr,
> {
    tracing::info!("Executing reshare");
    tracing::debug!("Signing with {:?}", &threshold_pair.public());

    let pair = PairWrapper(threshold_pair.clone());

    let session_id_hash = session_id.blake2(Some(Subsession::Reshare))?;

    let session = Session::<_, EntropySessionParameters>::new(
        &mut OsRng,
        ManulSessionId::from_seed::<EntropySessionParameters>(session_id_hash.as_slice()),
        pair.clone(),
        entry_point,
    )
    .unwrap();
    //.map_err(ProtocolExecutionErr::SessionCreation)?;

    let (new_key_share, chans) = execute_protocol_generic(chans, session).await;

    tracing::info!("Completed reshare protocol");

    let aux_info = if let Some(aux_info) = aux_info_option {
        aux_info
    } else {
        tracing::info!("Executing aux gen session as part of reshare");
        // Now run an aux gen session
        let session_id_hash_aux_data = session_id.blake2(Some(Subsession::AuxGen))?;

        let entry_point = AuxGen::new(verifiers.clone()).unwrap();

        let session = Session::<_, EntropySessionParameters>::new(
            &mut OsRng,
            ManulSessionId::from_seed::<EntropySessionParameters>(
                session_id_hash_aux_data.as_slice(),
            ),
            pair.clone(),
            entry_point,
        )
        .unwrap();
        //let session = make_aux_gen_session(
        //    &mut OsRng,
        //    SynedrionSessionId::from_seed(session_id_hash_aux_data.as_slice()),
        //    PairWrapper(threshold_pair.clone()),
        //    &inputs.new_holders,
        //)
        //.map_err(ProtocolExecutionErr::SessionCreation)?;

        execute_protocol_generic(chans, session).await.0
    };

    Ok((new_key_share.ok_or(ProtocolExecutionErr::NoOutputFromReshareProtocol)?, aux_info))
}

/// Psuedo-randomly select a subset of the parties of size `threshold`
fn get_key_init_parties(
    my_party_id: &EntropyPartyId,
    threshold: usize,
    validators: &BTreeSet<EntropyPartyId>,
    session_id_hash: &[u8],
) -> Result<(BTreeSet<EntropyPartyId>, bool), ProtocolExecutionErr> {
    let validators = validators.iter().cloned().collect::<Vec<EntropyPartyId>>();
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
