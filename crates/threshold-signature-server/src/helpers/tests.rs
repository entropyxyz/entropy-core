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

// only compile when testing or when the test_helpers feature is enabled
#![cfg(any(test, feature = "test_helpers"))]

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
use entropy_protocol::PartyId;
use entropy_shared::{DAVE_VERIFYING_KEY, EVE_VERIFYING_KEY};
use std::time::Duration;
use subxt::{
    backend::legacy::LegacyRpcMethods, ext::sp_core::sr25519, tx::PairSigner,
    utils::AccountId32 as SubxtAccountId32, Config, OnlineClient,
};
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
    let instrumentation = Instrumentation { logger: Logger::Pretty, ..Default::default() };
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

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001")
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

/// Spawn 3 TSS nodes with pre-stored keyshares
pub async fn spawn_testing_validators() -> (Vec<String>, Vec<PartyId>) {
    // spawn threshold servers
    let ports = [3001i64, 3002, 3003];

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

    let (charlie_axum, charlie_kv) =
        create_clients("validator3".to_string(), vec![], vec![], &Some(ValidatorName::Charlie))
            .await;
    let charlie_id = PartyId::new(SubxtAccountId32(
        *get_signer(&charlie_kv).await.unwrap().account_id().clone().as_ref(),
    ));

    let ids = vec![alice_id, bob_id, charlie_id];

    put_keyshares_in_db("alice", alice_kv).await;
    put_keyshares_in_db("bob", bob_kv).await;
    put_keyshares_in_db("charlie", charlie_kv).await;

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

    let listener_charlie = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", ports[2]))
        .await
        .expect("Unable to bind to given server address.");
    tokio::spawn(async move {
        axum::serve(listener_charlie, charlie_axum).await.unwrap();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let ips = ports.iter().map(|port| format!("127.0.0.1:{port}")).collect();
    (ips, ids)
}

/// Add the pre-generated test keyshares to a kvdb
async fn put_keyshares_in_db(holder_name: &str, kvdb: KvManager) {
    let user_names_and_verifying_keys = [("eve", EVE_VERIFYING_KEY), ("dave", DAVE_VERIFYING_KEY)];

    for (user_name, user_verifying_key) in user_names_and_verifying_keys {
        let keyshare_bytes = {
            let project_root =
                project_root::get_project_root().expect("Error obtaining project root.");
            let file_path = project_root.join(format!(
                "crates/testing-utils/keyshares/production/{}-keyshare-held-by-{}.keyshare",
                user_name, holder_name
            ));
            std::fs::read(file_path).unwrap()
        };
        let reservation = kvdb.kv().reserve_key(hex::encode(user_verifying_key)).await.unwrap();
        kvdb.kv().put(reservation, keyshare_bytes).await.unwrap();
    }
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
