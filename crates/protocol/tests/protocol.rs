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

//! Integration tests which log the time taken to run the protocols with the number of parties set
//! to the number of cpus available. Note that these should be run in release mode to get a realistic
//! idea of how long things take in production.

use entropy_protocol::{KeyParams, PartyId, SessionId, SigningSessionInfo, ValidatorInfo};
use futures::future;
use rand_core::OsRng;
use serial_test::serial;
use sp_core::{sr25519, Pair};
use std::time::Instant;
use subxt::utils::AccountId32;
use synedrion::{ecdsa::VerifyingKey, AuxInfo, KeyShare, ThresholdKeyShare};
use tokio::{net::TcpListener, runtime::Runtime, sync::oneshot};
use x25519_dalek::StaticSecret;

mod helpers;
use helpers::{server, ProtocolOutput};

#[test]
#[serial]
fn sign_protocol_with_time_logged() {
    let cpus = num_cpus::get();
    get_tokio_runtime(cpus).block_on(async {
        test_sign_with_parties(cpus).await;
    })
}

#[test]
#[serial]
fn refresh_protocol_with_time_logged() {
    let cpus = num_cpus::get();
    get_tokio_runtime(cpus).block_on(async {
        test_refresh_with_parties(cpus).await;
    })
}

#[test]
#[serial]
fn dkg_protocol_with_time_logged() {
    let cpus = num_cpus::get();
    get_tokio_runtime(cpus).block_on(async {
        test_dkg_with_parties(cpus).await;
    })
}

#[test]
#[serial]
fn t_of_n_dkg_and_sign() {
    let cpus = num_cpus::get();
    get_tokio_runtime(cpus).block_on(async {
        test_dkg_and_sign_with_parties(cpus).await;
    })
}

async fn test_sign_with_parties(num_parties: usize) {
    let (pairs, ids) = get_keypairs_and_ids(num_parties);
    let keyshares = KeyShare::<KeyParams, PartyId>::new_centralized(&mut OsRng, &ids, None);
    let aux_infos = AuxInfo::<KeyParams, PartyId>::new_centralized(&mut OsRng, &ids);
    let verifying_key = keyshares[0].verifying_key();

    let parties: Vec<_> = pairs
        .iter()
        .enumerate()
        .map(|(i, pair)| ValidatorSecretInfo {
            pair: pair.clone(),
            keyshare: Some(keyshares[i].clone()),
            threshold_keyshare: None,
            aux_info: Some(aux_infos[i].clone()),
        })
        .collect();
    let message_hash = [0u8; 32];
    let session_id = SessionId::Sign(SigningSessionInfo {
        signature_verifying_key: verifying_key.to_encoded_point(true).as_bytes().to_vec(),
        message_hash,
        request_author: AccountId32([0u8; 32]),
    });
    let threshold = parties.len();
    let mut outputs = test_protocol_with_parties(parties, session_id, threshold).await;
    if let ProtocolOutput::Sign(recoverable_signature) = outputs.pop().unwrap() {
        // Check signature
        let recovery_key_from_sig = VerifyingKey::recover_from_prehash(
            &message_hash,
            &recoverable_signature.signature,
            recoverable_signature.recovery_id,
        )
        .unwrap();
        assert_eq!(verifying_key, recovery_key_from_sig);
    } else {
        panic!("Unexpected protocol output");
    }
}

async fn test_refresh_with_parties(num_parties: usize) {
    let (pairs, ids) = get_keypairs_and_ids(num_parties);
    let keyshares = KeyShare::<KeyParams, PartyId>::new_centralized(&mut OsRng, &ids, None);
    let verifying_key = keyshares[0].verifying_key();

    let session_id = SessionId::ProactiveRefresh {
        verifying_key: verifying_key.to_encoded_point(true).as_bytes().to_vec(),
        block_number: 0,
    };

    let parties: Vec<_> = pairs
        .iter()
        .enumerate()
        .map(|(i, pair)| ValidatorSecretInfo {
            pair: pair.clone(),
            keyshare: None,
            threshold_keyshare: Some(keyshares[i].to_threshold_key_share()),
            aux_info: None,
        })
        .collect();
    let threshold = parties.len();
    let mut outputs = test_protocol_with_parties(parties, session_id, threshold).await;
    if let ProtocolOutput::ProactiveRefresh(keyshare) = outputs.pop().unwrap() {
        assert!(keyshare.verifying_key() == verifying_key);
    } else {
        panic!("Unexpected protocol output");
    }
}

async fn test_dkg_with_parties(num_parties: usize) {
    let (pairs, _ids) = get_keypairs_and_ids(num_parties);
    let parties: Vec<_> =
        pairs.iter().map(|pair| ValidatorSecretInfo::pair_only(pair.clone())).collect();
    let threshold = parties.len();
    let session_id = SessionId::Dkg { user: AccountId32([0; 32]), block_number: 0 };
    let mut outputs = test_protocol_with_parties(parties, session_id, threshold).await;
    if let ProtocolOutput::Dkg(_keyshare) = outputs.pop().unwrap() {
    } else {
        panic!("Unexpected protocol output");
    }
}

async fn test_dkg_and_sign_with_parties(num_parties: usize) {
    let threshold = num_parties - 1;
    if threshold < 2 {
        panic!("Not enought parties to test threshold signing");
    }
    let (pairs, ids) = get_keypairs_and_ids(num_parties);
    let dkg_parties =
        pairs.iter().map(|pair| ValidatorSecretInfo::pair_only(pair.clone())).collect();
    let session_id = SessionId::Dkg { user: AccountId32([0; 32]), block_number: 0 };
    let outputs = test_protocol_with_parties(dkg_parties, session_id, threshold).await;
    println!("Finished DKG");
    let signing_committee = &ids[..threshold];

    println!("signing committee {:?}", signing_committee);
    let parties: Vec<ValidatorSecretInfo> = outputs
        .clone()
        .into_iter()
        .filter_map(|output| {
            if let ProtocolOutput::Dkg((threshold_keyshare, aux_info)) = output {
                println!("Threshold {}", threshold_keyshare.threshold());
                let keyshare = threshold_keyshare.to_key_share(&signing_committee);
                if signing_committee.contains(keyshare.owner()) {
                    let pair = pairs
                        .iter()
                        .find(|p| keyshare.owner() == &PartyId::new(AccountId32(p.public().0)))
                        .unwrap();
                    Some(ValidatorSecretInfo {
                        pair: pair.clone(),
                        keyshare: Some(keyshare),
                        threshold_keyshare: None,
                        aux_info: Some(aux_info),
                    })
                } else {
                    None
                }
            } else {
                panic!("Unexpected protocol output");
            }
        })
        .collect();

    let verifying_key = parties[0].keyshare.clone().unwrap().verifying_key();

    let message_hash = [0u8; 32];
    let session_id = SessionId::Sign(SigningSessionInfo {
        signature_verifying_key: verifying_key.to_encoded_point(true).as_bytes().to_vec(),
        message_hash,
        request_author: AccountId32([0u8; 32]),
    });
    let mut outputs = test_protocol_with_parties(parties, session_id, threshold).await;
    if let ProtocolOutput::Sign(recoverable_signature) = outputs.pop().unwrap() {
        // Check signature
        let recovery_key_from_sig = VerifyingKey::recover_from_prehash(
            &message_hash,
            &recoverable_signature.signature,
            recoverable_signature.recovery_id,
        )
        .unwrap();
        assert_eq!(verifying_key, recovery_key_from_sig);
    } else {
        panic!("Unexpected protocol output");
    }
}

/// Generic test for any of the 3 protocols
async fn test_protocol_with_parties(
    parties: Vec<ValidatorSecretInfo>,
    session_id: SessionId,
    threshold: usize,
) -> Vec<ProtocolOutput> {
    // Prepare information about each node
    let mut validator_secrets = Vec::new();
    let mut validators_info = Vec::new();
    for i in 0..parties.len() {
        // Start a TCP listener and get its socket address
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        let x25519_secret_key = StaticSecret::random_from_rng(OsRng);
        let x25519_public_key = x25519_dalek::PublicKey::from(&x25519_secret_key).to_bytes();

        validator_secrets.push(ValidatorSecretInfoWithSocket::new(
            parties[i].clone(),
            x25519_secret_key,
            socket,
        ));

        // Public contact information that all parties know
        validators_info.push(ValidatorInfo {
            tss_account: AccountId32(parties[i].pair.public().0),
            x25519_public_key,
            ip_address: addr.to_string(),
        })
    }

    let now = Instant::now();
    // Spawn tasks for each party
    let mut results_rx = Vec::new();
    for _ in 0..parties.len() {
        // Channel used to return the resulting signature
        let (tx, rx) = oneshot::channel();
        results_rx.push(rx);
        let secret = validator_secrets.pop().unwrap();
        let validators_info_clone = validators_info.clone();
        let session_id_clone = session_id.clone();
        tokio::spawn(async move {
            let result = server(
                secret.socket,
                validators_info_clone,
                secret.pair,
                secret.x25519_secret_key,
                session_id_clone,
                secret.keyshare,
                secret.threshold_keyshare,
                secret.aux_info,
                threshold,
            )
            .await;
            if !tx.is_closed() {
                tx.send(result).unwrap();
            }
        });
    }
    let results =
        future::join_all(results_rx).await.into_iter().map(|r| r.unwrap().unwrap()).collect();
    println!("Got protocol results with {} parties in {:?}", parties.len(), now.elapsed());

    results
}

/// Details of an individual party
#[derive(Clone)]
struct ValidatorSecretInfo {
    pair: sr25519::Pair,
    keyshare: Option<KeyShare<KeyParams, PartyId>>,
    threshold_keyshare: Option<ThresholdKeyShare<KeyParams, PartyId>>,
    aux_info: Option<AuxInfo<KeyParams, PartyId>>,
}

impl ValidatorSecretInfo {
    fn pair_only(pair: sr25519::Pair) -> Self {
        ValidatorSecretInfo { pair, keyshare: None, threshold_keyshare: None, aux_info: None }
    }
}

/// Full details of an individual party, with a socket
struct ValidatorSecretInfoWithSocket {
    pair: sr25519::Pair,
    keyshare: Option<KeyShare<KeyParams, PartyId>>,
    threshold_keyshare: Option<ThresholdKeyShare<KeyParams, PartyId>>,
    aux_info: Option<AuxInfo<KeyParams, PartyId>>,
    x25519_secret_key: StaticSecret,
    socket: TcpListener,
}

impl ValidatorSecretInfoWithSocket {
    fn new(
        secret_info: ValidatorSecretInfo,
        x25519_secret_key: StaticSecret,
        socket: TcpListener,
    ) -> Self {
        Self {
            pair: secret_info.pair,
            keyshare: secret_info.keyshare,
            threshold_keyshare: secret_info.threshold_keyshare,
            aux_info: secret_info.aux_info,
            x25519_secret_key,
            socket,
        }
    }
}

/// Helper to get the async runtime used for these tests
fn get_tokio_runtime(num_cpus: usize) -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus)
        .enable_all()
        .build()
        .unwrap()
}

/// Generate keypair and make PartyId from public key
fn get_keypairs_and_ids(num_parties: usize) -> (Vec<sr25519::Pair>, Vec<PartyId>) {
    let pairs = (0..num_parties).map(|_| sr25519::Pair::generate().0).collect::<Vec<_>>();
    let ids =
        pairs.iter().map(|pair| PartyId::new(AccountId32(pair.public().0))).collect::<Vec<_>>();
    (pairs, ids)
}
