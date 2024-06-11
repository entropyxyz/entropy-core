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

//! Utilities used in unit tests

// only compile when testing
#![cfg(test)]

use std::time::Duration;

use crate::{
    app,
    chain_api::{
        entropy::{self, runtime_types::bounded_collections::bounded_vec::BoundedVec},
        EntropyConfig,
    },
    get_signer,
    helpers::{
        launch::{
            setup_latest_block_number, setup_mnemonic, Configuration, ValidatorName,
            DEFAULT_ENDPOINT,
        },
        logger::Instrumentation,
        logger::Logger,
        substrate::{query_chain, submit_transaction},
    },
    signing_client::ListenerState,
    AppState,
};
use axum::{routing::IntoMakeService, Router};
use entropy_kvdb::{encrypted_sled::PasswordMethod, get_db_path, kv_manager::KvManager};
use entropy_protocol::{KeyParams, KeyShareWithAuxInfo, PartyId};
use entropy_shared::DETERMINISTIC_KEY_SHARE_EVE;
use rand_core::OsRng;
use sp_core::Pair;
use subxt::{
    backend::legacy::LegacyRpcMethods, ext::sp_core::sr25519, tx::PairSigner,
    utils::AccountId32 as SubxtAccountId32, Config, OnlineClient,
};
use synedrion::{k256::ecdsa::SigningKey, AuxInfo, KeyShare};
use tokio::sync::OnceCell;

/// A shared reference to the logger used for tests.
///
/// Since this only needs to be initialized once for the whole test suite we define it as a
/// async-friendly static.
pub static LOGGER: OnceCell<()> = OnceCell::const_new();

/// Initialize the global logger used in tests.
///
/// The logger will only be initialized once, even if this function is called multiple times.
pub async fn initialize_test_logger() {
    let mut instrumentation = Instrumentation::default();
    instrumentation.logger = Logger::Pretty;

    *LOGGER.get_or_init(|| instrumentation.setup()).await
}

pub async fn setup_client() -> KvManager {
    let kv_store =
        KvManager::new(get_db_path(true).into(), PasswordMethod::NoPassword.execute().unwrap())
            .unwrap();
    let _ = setup_mnemonic(&kv_store, &Some(ValidatorName::Alice)).await;
    let _ = setup_latest_block_number(&kv_store).await;
    let listener_state = ListenerState::default();
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());
    let app_state = AppState { listener_state, configuration, kv_store: kv_store.clone() };
    let app = app(app_state).into_make_service();

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:3001"))
        .await
        .expect("Unable to bind to given server address.");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    kv_store
}

pub async fn create_clients(
    key_number: String,
    values: Vec<Vec<u8>>,
    keys: Vec<String>,
    validator_name: &Option<ValidatorName>,
) -> (IntoMakeService<Router>, KvManager) {
    let listener_state = ListenerState::default();
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());

    let path = format!(".entropy/testing/test_db_{key_number}");
    let _ = std::fs::remove_dir_all(path.clone());

    let kv_store =
        KvManager::new(path.into(), PasswordMethod::NoPassword.execute().unwrap()).unwrap();
    let _ = setup_mnemonic(&kv_store, validator_name).await;
    let _ = setup_latest_block_number(&kv_store).await;

    for (i, value) in values.into_iter().enumerate() {
        let reservation = kv_store.clone().kv().reserve_key(keys[i].to_string()).await.unwrap();
        let _ = kv_store.clone().kv().put(reservation, value).await;
    }

    let app_state = AppState { listener_state, configuration, kv_store: kv_store.clone() };

    let app = app(app_state).into_make_service();

    (app, kv_store)
}

pub async fn spawn_testing_validators(
    passed_verifying_key: Option<Vec<u8>>,
    // If this is given a keyshare for the user will be generated and returned
    extra_private_key: Option<sr25519::Pair>,
    // If true keyshare and verifying key is deterministic
    deterministic_key_share: bool,
) -> (Vec<String>, Vec<PartyId>, Option<KeyShareWithAuxInfo>) {
    // spawn threshold servers
    let ports = [3001i64, 3002];

    let (alice_axum, alice_kv) =
        create_clients("validator1".to_string(), vec![], vec![], &Some(ValidatorName::Alice)).await;
    let alice_id = PartyId::new(SubxtAccountId32(
        *get_signer(&alice_kv).await.unwrap().account_id().clone().as_ref(),
    ));

    let (bob_axum, bob_kv) =
        create_clients("validator2".to_string(), vec![], vec![], &Some(ValidatorName::Bob)).await;
    let bob_id = PartyId::new(SubxtAccountId32(
        *get_signer(&bob_kv).await.unwrap().account_id().clone().as_ref(),
    ));

    let mut ids = vec![alice_id, bob_id];
    if let Some(pair) = extra_private_key {
        ids.push(PartyId::new(SubxtAccountId32(pair.public().0)));
    }

    let user_keyshare_option = if passed_verifying_key.is_some() {
        // creates a deterministic keyshare if requiered
        let signing_key = if deterministic_key_share {
            Some(SigningKey::from_bytes((&*DETERMINISTIC_KEY_SHARE_EVE).into()).unwrap())
        } else {
            None
        };

        let shares =
            KeyShare::<KeyParams, PartyId>::new_centralized(&mut OsRng, &ids, signing_key.as_ref());
        let aux_infos = AuxInfo::<KeyParams, PartyId>::new_centralized(&mut OsRng, &ids);

        let validator_1_threshold_keyshare: Vec<u8> = entropy_kvdb::kv_manager::helpers::serialize(
            &(shares[0].to_threshold_key_share(), &aux_infos[0]),
        )
        .unwrap();
        let validator_2_threshold_keyshare: Vec<u8> = entropy_kvdb::kv_manager::helpers::serialize(
            &(shares[1].to_threshold_key_share(), &aux_infos[1]),
        )
        .unwrap();
        // uses the deterministic verifying key if requested
        let verifying_key = if deterministic_key_share {
            hex::encode(shares[0].verifying_key().to_encoded_point(true).as_bytes().to_vec())
        } else {
            hex::encode(passed_verifying_key.unwrap())
        };

        // add key share to kvdbs
        let alice_reservation = alice_kv.kv().reserve_key(verifying_key.clone()).await.unwrap();
        alice_kv.kv().put(alice_reservation, validator_1_threshold_keyshare).await.unwrap();

        let bob_reservation = bob_kv.kv().reserve_key(verifying_key.clone()).await.unwrap();
        bob_kv.kv().put(bob_reservation, validator_2_threshold_keyshare).await.unwrap();

        Some((
            shares[shares.len() - 1].to_threshold_key_share(),
            aux_infos[aux_infos.len() - 1].clone(),
        ))
    } else {
        None
    };

    let listener_alice = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", ports[0]))
        .await
        .expect("Unable to bind to given server address.");
    tokio::spawn(async move {
        axum::serve(listener_alice, alice_axum).await.unwrap();
    });

    let listener_bob = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", ports[1]))
        .await
        .expect("Unable to bind to given server address.");
    tokio::spawn(async move {
        axum::serve(listener_bob, bob_axum).await.unwrap();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let ips = ports.iter().map(|port| format!("127.0.0.1:{port}")).collect();
    (ips, ids, user_keyshare_option)
}

/// Removes the program at the program hash
pub async fn remove_program(
    entropy_api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    deployer: &sr25519::Pair,
    program_hash: <EntropyConfig as Config>::Hash,
) {
    // update/set their programs
    let remove_program_tx = entropy::tx().programs().remove_program(program_hash);
    let deployer = PairSigner::<EntropyConfig, sr25519::Pair>::new(deployer.clone());

    submit_transaction(entropy_api, rpc, &deployer, &remove_program_tx, None).await.unwrap();
}

/// Verify that a Registering account has all confirmation, and that it is registered.
pub async fn check_if_confirmation(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    key: &sr25519::Pair,
    verifying_key: Vec<u8>,
) {
    let signer = PairSigner::<EntropyConfig, sr25519::Pair>::new(key.clone());
    let registering_query = entropy::storage().registry().registering(signer.account_id());
    let registered_query = entropy::storage().registry().registered(BoundedVec(verifying_key));
    let block_hash = rpc.chain_get_block_hash(None).await.unwrap();
    let is_registering = query_chain(api, rpc, registering_query, block_hash).await;
    // cleared from is_registering state
    assert!(is_registering.unwrap().is_none());
    let is_registered = query_chain(api, rpc, registered_query, block_hash).await.unwrap();
    //TODO assert something here
    assert_eq!(is_registered.unwrap().version_number, 1);
}

/// Verify that an account got one confirmation.
pub async fn check_has_confirmation(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    key: &sr25519::Pair,
) {
    let signer = PairSigner::<EntropyConfig, sr25519::Pair>::new(key.clone());
    let registering_query = entropy::storage().registry().registering(signer.account_id());
    // cleared from is_registering state
    let is_registering = query_chain(api, rpc, registering_query, None).await.unwrap();
    assert_eq!(is_registering.unwrap().confirmations.len(), 1);
}

pub async fn run_to_block(rpc: &LegacyRpcMethods<EntropyConfig>, block_run: u32) {
    let mut current_block = 0;
    while current_block < block_run {
        current_block = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    }
}
