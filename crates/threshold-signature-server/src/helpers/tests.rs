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

#[cfg(test)]
use crate::helpers::tests::entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec;
use crate::{
    app,
    chain_api::{
        entropy::{
            self,
            runtime_types::entropy_runtime::RuntimeCall,
            runtime_types::pallet_staking_extension::pallet::{JumpStartStatus, ServerInfo},
        },
        EntropyConfig,
    },
    helpers::{
        launch::{
            setup_kv_store, setup_latest_block_number, Configuration, ValidatorName,
            DEFAULT_ENDPOINT,
        },
        logger::{Instrumentation, Logger},
        substrate::submit_transaction,
    },
    AppState,
};
use axum::{routing::IntoMakeService, Router};
use entropy_client::substrate::query_chain;
use entropy_kvdb::{get_db_path, kv_manager::KvManager};
use entropy_protocol::PartyId;
#[cfg(test)]
use entropy_shared::EncodedVerifyingKey;
use entropy_shared::NETWORK_PARENT_KEY;
use sp_keyring::AccountKeyring;
use std::{fmt, net::SocketAddr, path::PathBuf, str, time::Duration};
use subxt::{
    backend::legacy::LegacyRpcMethods, ext::sp_core::sr25519, tx::PairSigner,
    utils::AccountId32 as SubxtAccountId32, Config, OnlineClient,
};
use tokio::sync::{mpsc, OnceCell};

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
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());

    let storage_path: PathBuf = get_db_path(true).into();
    let (kv_store, sr25519_pair, x25519_secret, _should_backup) =
        setup_kv_store(&Some(ValidatorName::Alice), Some(storage_path.clone())).await.unwrap();

    let _ = setup_latest_block_number(&kv_store).await;

    let (shutdown_tx, _shutdown_rx) = mpsc::channel::<()>(1);
    let app_state =
        AppState::new(configuration, kv_store.clone(), sr25519_pair, x25519_secret, shutdown_tx);

    // Mock making the pre-requisite checks by setting the application state to ready
    app_state.make_ready();

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
) -> (IntoMakeService<Router>, KvManager, SubxtAccountId32) {
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());

    let path = format!(".entropy/testing/test_db_{key_number}");
    let _ = std::fs::remove_dir_all(path.clone());

    let (kv_store, sr25519_pair, x25519_secret, _should_backup) =
        setup_kv_store(validator_name, Some(path.into())).await.unwrap();

    let _ = setup_latest_block_number(&kv_store).await;
    let (shutdown_tx, _shutdown_rx) = mpsc::channel::<()>(1);
    let app_state =
        AppState::new(configuration, kv_store.clone(), sr25519_pair, x25519_secret, shutdown_tx);

    let _ = setup_latest_block_number(&kv_store).await;

    for (i, value) in values.into_iter().enumerate() {
        let reservation = kv_store.clone().kv().reserve_key(keys[i].to_string()).await.unwrap();
        let _ = kv_store.clone().kv().put(reservation, value).await;
    }

    // Mock making the pre-requisite checks by setting the application state to ready
    app_state.make_ready();

    let account_id = app_state.subxt_account_id();

    let app = app(app_state).into_make_service();

    (app, kv_store, account_id)
}

/// A way to specify which chainspec to use in testing
#[derive(Copy, Clone, PartialEq)]
pub enum ChainSpecType {
    /// The integration test chainspec, which has 4 TSS nodes
    Integration,
    /// The integration test chainspec, starting in a pre-jumpstarted state
    IntegrationJumpStarted,
}

impl fmt::Display for ChainSpecType {
    /// This is used when specifying the chainspec type as a command line argument when starting the
    /// Entropy chain for testing
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ChainSpecType::Integration => "integration-tests",
                ChainSpecType::IntegrationJumpStarted => "integration-tests-jumpstarted",
            },
        )
    }
}

/// Spawn 4 TSS nodes depending on chain configuration, adding pre-stored keyshares if
/// desired
pub async fn spawn_testing_validators(
    chain_spec_type: ChainSpecType,
) -> (Vec<String>, Vec<PartyId>) {
    let ports = [3001i64, 3002, 3003, 3004];

    let (alice_axum, alice_kv, alice_id) =
        create_clients("validator1".to_string(), vec![], vec![], &Some(ValidatorName::Alice)).await;
    let alice_id = PartyId::new(alice_id);

    let (bob_axum, bob_kv, bob_id) =
        create_clients("validator2".to_string(), vec![], vec![], &Some(ValidatorName::Bob)).await;
    let bob_id = PartyId::new(bob_id);

    let (charlie_axum, charlie_kv, charlie_id) =
        create_clients("validator3".to_string(), vec![], vec![], &Some(ValidatorName::Charlie))
            .await;
    let charlie_id = PartyId::new(charlie_id);

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

    let (dave_axum, _dave_kv, dave_id) =
        create_clients("validator4".to_string(), vec![], vec![], &Some(ValidatorName::Dave)).await;

    let listener_dave = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", ports[3]))
        .await
        .expect("Unable to bind to given server address.");
    tokio::spawn(async move {
        axum::serve(listener_dave, dave_axum).await.unwrap();
    });
    let dave_id = PartyId::new(dave_id);
    let ids = vec![alice_id, bob_id, charlie_id, dave_id];

    if chain_spec_type == ChainSpecType::IntegrationJumpStarted {
        put_keyshares_in_db(ValidatorName::Alice, alice_kv).await;
        put_keyshares_in_db(ValidatorName::Bob, bob_kv).await;
        put_keyshares_in_db(ValidatorName::Charlie, charlie_kv).await;
        // Dave does not get a keyshare as there are only 3 parties in the signing group
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    let ips = ports.iter().map(|port| format!("127.0.0.1:{port}")).collect();
    (ips, ids)
}

/// Add the pre-generated test keyshares to a kvdb
pub async fn put_keyshares_in_db(validator_name: ValidatorName, kvdb: KvManager) {
    let keyshare_bytes = {
        let project_root = project_root::get_project_root().expect("Error obtaining project root.");
        let file_path = project_root.join(format!(
            "crates/testing-utils/keyshares/production/keyshare-held-by-{}.keyshare",
            validator_name
        ));
        std::fs::read(file_path).unwrap()
    };

    let reservation = kvdb.kv().reserve_key(hex::encode(NETWORK_PARENT_KEY)).await.unwrap();
    kvdb.kv().put(reservation, keyshare_bytes).await.unwrap();
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

pub async fn run_to_block(rpc: &LegacyRpcMethods<EntropyConfig>, block_run: u32) {
    let mut current_block = 0;
    while current_block < block_run {
        current_block = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    }
}

/// Get a value from a kvdb using unsafe get
#[cfg(test)]
pub async fn unsafe_get(client: &reqwest::Client, query_key: String, port: u32) -> Vec<u8> {
    let get_query = crate::r#unsafe::api::UnsafeQuery::new(query_key, vec![]).to_json();
    let get_result = client
        .post(format!("http://127.0.0.1:{}/unsafe/get", port))
        .header("Content-Type", "application/json")
        .body(get_query)
        .send()
        .await
        .unwrap();

    get_result.bytes().await.unwrap().into()
}

/// Helper to store a program and register a user. Returns the verify key and program hash.
#[cfg(test)]
pub async fn store_program_and_register(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    user: &sr25519::Pair,
    deployer: &sr25519::Pair,
) -> (EncodedVerifyingKey, sp_core::H256) {
    use entropy_client::{
        self as test_client,
        chain_api::entropy::runtime_types::pallet_registry::pallet::ProgramInstance,
    };
    use entropy_testing_utils::constants::TEST_PROGRAM_WASM_BYTECODE;
    use sp_core::Pair;

    let program_hash = test_client::store_program(
        api,
        rpc,
        deployer,
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
        0u8,
    )
    .await
    .unwrap();

    let (verifying_key, _registered_info) = test_client::register(
        api,
        rpc,
        user.clone(),
        SubxtAccountId32(deployer.public().0), // Program modification account
        BoundedVec(vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }]),
    )
    .await
    .unwrap();

    (verifying_key, program_hash)
}

/// Do a network jumpstart DKG
pub async fn do_jump_start(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    pair: sr25519::Pair,
) {
    run_to_block(rpc, 2).await;
    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    put_jumpstart_request_on_chain(api, rpc, pair).await;

    run_to_block(rpc, block_number + 1).await;

    let jump_start_status_query = entropy::storage().staking_extension().jump_start_progress();
    let mut jump_start_status = query_chain(api, rpc, jump_start_status_query.clone(), None)
        .await
        .unwrap()
        .unwrap()
        .jump_start_status;
    let mut i = 0;
    while format!("{:?}", jump_start_status) != format!("{:?}", JumpStartStatus::Done) {
        tokio::time::sleep(Duration::from_secs(1)).await;
        jump_start_status = query_chain(api, rpc, jump_start_status_query.clone(), None)
            .await
            .unwrap()
            .unwrap()
            .jump_start_status;
        i += 1;
        if i > 75 {
            panic!("Jump start failed");
        }
    }

    assert_eq!(format!("{:?}", jump_start_status), format!("{:?}", JumpStartStatus::Done));
}

/// Submit a jumpstart extrinsic
async fn put_jumpstart_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    pair: sr25519::Pair,
) {
    let account = PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(pair);

    let registering_tx = entropy::tx().registry().jump_start_network();
    submit_transaction(api, rpc, &account, &registering_tx, None).await.unwrap();
}

/// Given a ServerInfo, get the port number
pub fn get_port(server_info: &ServerInfo<SubxtAccountId32>) -> u32 {
    let socket_address: SocketAddr =
        str::from_utf8(&server_info.endpoint).unwrap().parse().unwrap();
    socket_address.port().into()
}

/// Calls set storage from sudo for testing, allows use to manipulate chain storage.
pub async fn call_set_storage(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    call: RuntimeCall,
) {
    let set_storage = entropy::tx().sudo().sudo(call);
    let alice = AccountKeyring::Alice;

    let signature_request_pair_signer =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(alice.into());

    submit_transaction(api, rpc, &signature_request_pair_signer, &set_storage, None).await.unwrap();
}
