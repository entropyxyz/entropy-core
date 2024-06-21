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

//! Simulates 3 TSS nodes running the reshare protocol in order to create keyshares with a
//! pre-defined distributed keypair for testing entropy-tss
use entropy_protocol::{execute_protocol::PairWrapper, PartyId};
use rand_core::OsRng;
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32;
use synedrion::{
    ecdsa::SigningKey, make_key_resharing_session, AuxInfo, KeyResharingInputs, KeyShare,
    NewHolder, OldHolder, SchemeParams, ThresholdKeyShare,
};
use synedrion_test_environment::run_nodes;

/// Given a secp256k1 secret key and 3 signing keypairs for the TSS parties, generate a set of
/// threshold keyshares with auxiliary info
pub async fn create_test_keyshares<Params>(
    distributed_secret_key_bytes: [u8; 32],
    alice: sr25519::Pair,
    bob: sr25519::Pair,
    charlie: sr25519::Pair,
) -> Vec<(ThresholdKeyShare<Params, PartyId>, AuxInfo<Params, PartyId>)>
where
    Params: SchemeParams,
{
    let signing_key = SigningKey::from_bytes(&(distributed_secret_key_bytes).into()).unwrap();
    let signers = vec![alice, bob, charlie.clone()];
    let shared_randomness = b"12345";
    let all_parties =
        signers.iter().map(|pair| PartyId::new(AccountId32(pair.public().0))).collect::<Vec<_>>();

    let old_holders = all_parties.clone().into_iter().take(2).collect::<Vec<_>>();

    let keyshares =
        KeyShare::<Params, PartyId>::new_centralized(&mut OsRng, &old_holders, Some(&signing_key));
    let aux_infos = AuxInfo::<Params, PartyId>::new_centralized(&mut OsRng, &all_parties);

    let new_holder =
        NewHolder { verifying_key: keyshares[0].verifying_key(), old_threshold: 2, old_holders };

    let mut sessions = (0..2)
        .map(|idx| {
            let inputs = KeyResharingInputs {
                old_holder: Some(OldHolder { key_share: keyshares[idx].to_threshold_key_share() }),
                new_holder: Some(new_holder.clone()),
                new_holders: all_parties.clone(),
                new_threshold: 2,
            };
            make_key_resharing_session(
                &mut OsRng,
                shared_randomness,
                PairWrapper(signers[idx].clone()),
                &all_parties,
                &inputs,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let charlie_session = {
        let inputs = KeyResharingInputs {
            old_holder: None,
            new_holder: Some(new_holder.clone()),
            new_holders: all_parties.clone(),
            new_threshold: 2,
        };
        make_key_resharing_session(
            &mut OsRng,
            shared_randomness,
            PairWrapper(charlie),
            &all_parties,
            &inputs,
        )
        .unwrap()
    };

    sessions.push(charlie_session);

    let new_t_key_shares = run_nodes(sessions).await;

    let mut output = Vec::new();
    for i in 0..3 {
        output.push((new_t_key_shares[i].clone().unwrap(), aux_infos[i].clone()));
    }
    output
}

/// This is used to run the synedrion protocols - it is mostly copied from the synedrion integration
/// tests
mod synedrion_test_environment {
    use entropy_protocol::{execute_protocol::PairWrapper, PartyId};
    use rand::Rng;
    use rand_core::OsRng;
    use sp_core::sr25519;
    use std::collections::BTreeMap;
    use synedrion::{CombinedMessage, FinalizeOutcome, MappedResult, Session};
    use tokio::{
        sync::mpsc,
        time::{sleep, Duration},
    };
    type MessageOut = (PartyId, PartyId, CombinedMessage<sr25519::Signature>);
    type MessageIn = (PartyId, CombinedMessage<sr25519::Signature>);

    fn key_to_str(key: &PartyId) -> String {
        key.to_string()
    }

    /// Run a generic synedrion session
    async fn run_session<Res: MappedResult<PartyId>>(
        tx: mpsc::Sender<MessageOut>,
        rx: mpsc::Receiver<MessageIn>,
        session: Session<Res, sr25519::Signature, PairWrapper, PartyId>,
    ) -> Res::MappedSuccess {
        let mut rx = rx;

        let mut session = session;
        let mut cached_messages = Vec::new();

        let key = session.verifier();
        let key_str = key_to_str(&key);

        loop {
            println!("{key_str}: *** starting round {:?} ***", session.current_round());

            // This is kept in the main task since it's mutable,
            // and we don't want to bother with synchronization.
            let mut accum = session.make_accumulator();

            // Note: generating/sending messages and verifying newly received messages
            // can be done in parallel, with the results being assembled into `accum`
            // sequentially in the host task.

            let destinations = session.message_destinations();
            for destination in destinations.iter() {
                // In production usage, this will happen in a spawned task
                // (since it can take some time to create a message),
                // and the artifact will be sent back to the host task
                // to be added to the accumulator.
                let (message, artifact) = session.make_message(&mut OsRng, destination).unwrap();
                println!("{key_str}: sending a message to {}", key_to_str(destination));
                tx.send((key.clone(), destination.clone(), message)).await.unwrap();

                // This will happen in a host task
                accum.add_artifact(artifact).unwrap();
            }

            for preprocessed in cached_messages {
                // In production usage, this will happen in a spawned task.
                println!("{key_str}: applying a cached message");
                let result = session.process_message(preprocessed).unwrap();

                // This will happen in a host task.
                accum.add_processed_message(result).unwrap().unwrap();
            }

            while !session.can_finalize(&accum).unwrap() {
                // This can be checked if a timeout expired, to see which nodes have not responded yet.
                let unresponsive_parties = session.missing_messages(&accum).unwrap();
                assert!(!unresponsive_parties.is_empty());

                println!("{key_str}: waiting for a message");
                let (from, message) = rx.recv().await.unwrap();

                // Perform quick checks before proceeding with the verification.
                let preprocessed = session.preprocess_message(&mut accum, &from, message).unwrap();

                if let Some(preprocessed) = preprocessed {
                    // In production usage, this will happen in a spawned task.
                    println!("{key_str}: applying a message from {}", key_to_str(&from));
                    let result = session.process_message(preprocessed).unwrap();

                    // This will happen in a host task.
                    accum.add_processed_message(result).unwrap().unwrap();
                }
            }

            println!("{key_str}: finalizing the round");

            match session.finalize_round(&mut OsRng, accum).unwrap() {
                FinalizeOutcome::Success(res) => break res,
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

    async fn message_dispatcher(
        txs: BTreeMap<PartyId, mpsc::Sender<MessageIn>>,
        rx: mpsc::Receiver<MessageOut>,
    ) {
        let mut rx = rx;
        let mut messages = Vec::<MessageOut>::new();
        loop {
            let msg = match rx.recv().await {
                Some(msg) => msg,
                None => break,
            };
            messages.push(msg);

            while let Ok(msg) = rx.try_recv() {
                messages.push(msg)
            }

            while !messages.is_empty() {
                // Pull a random message from the list,
                // to increase the chances that they are delivered out of order.
                let message_idx = rand::thread_rng().gen_range(0..messages.len());
                let (id_from, id_to, message) = messages.swap_remove(message_idx);

                txs[&id_to].send((id_from, message)).await.unwrap();

                // Give up execution so that the tasks could process messages.
                sleep(Duration::from_millis(0)).await;

                if let Ok(msg) = rx.try_recv() {
                    messages.push(msg);
                };
            }
        }
    }

    pub async fn run_nodes<Res>(
        sessions: Vec<Session<Res, sr25519::Signature, PairWrapper, PartyId>>,
    ) -> Vec<Res::MappedSuccess>
    where
        Res: MappedResult<PartyId> + Send + 'static,
        Res::MappedSuccess: Send + 'static,
    {
        let num_parties = sessions.len();

        let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<MessageOut>(100);

        let channels = (0..num_parties).map(|_| mpsc::channel::<MessageIn>(100));
        let (txs, rxs): (Vec<mpsc::Sender<MessageIn>>, Vec<mpsc::Receiver<MessageIn>>) =
            channels.unzip();
        let tx_map =
            sessions.iter().map(|session| session.verifier()).zip(txs.into_iter()).collect();

        let dispatcher_task = message_dispatcher(tx_map, dispatcher_rx);
        let dispatcher = tokio::spawn(dispatcher_task);

        let handles: Vec<tokio::task::JoinHandle<Res::MappedSuccess>> = rxs
            .into_iter()
            .zip(sessions.into_iter())
            .map(|(rx, session)| {
                let node_task = run_session(dispatcher_tx.clone(), rx, session);
                tokio::spawn(node_task)
            })
            .collect();

        // Drop the last copy of the dispatcher's incoming channel so that it could finish.
        drop(dispatcher_tx);

        let mut results = Vec::with_capacity(num_parties);
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        dispatcher.await.unwrap();

        results
    }
}
