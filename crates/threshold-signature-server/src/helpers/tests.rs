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
        entropy::{
            self, runtime_types::bounded_collections::bounded_vec::BoundedVec,
            runtime_types::pallet_staking_extension::pallet::JumpStartStatus,
        },
        EntropyConfig,
    },
    get_signer,
    helpers::{
        launch::{
            development_mnemonic, setup_latest_block_number, setup_mnemonic, Configuration,
            ValidatorName, DEFAULT_ENDPOINT,
        },
        logger::{Instrumentation, Logger},
        substrate::submit_transaction,
        validator::get_signer_and_x25519_secret_from_mnemonic,
    },
    r#unsafe::api::UnsafeQuery,
    signing_client::ListenerState,
    AppState,
};
use axum::{routing::IntoMakeService, Router};
use entropy_client::substrate::query_chain;
use entropy_kvdb::{encrypted_sled::PasswordMethod, get_db_path, kv_manager::KvManager};
use entropy_protocol::PartyId;
#[cfg(test)]
use entropy_shared::EncodedVerifyingKey;
use entropy_shared::{OcwMessageDkg, EVE_VERIFYING_KEY, NETWORK_PARENT_KEY};
use futures::future::join_all;
use parity_scale_codec::Encode;
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

    let mnemonic = development_mnemonic(&Some(ValidatorName::Alice));
    setup_mnemonic(&kv_store, mnemonic).await;

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

    let mnemonic = development_mnemonic(validator_name);
    crate::launch::setup_mnemonic(&kv_store, mnemonic).await;

    let _ = setup_latest_block_number(&kv_store).await;

    for (i, value) in values.into_iter().enumerate() {
        let reservation = kv_store.clone().kv().reserve_key(keys[i].to_string()).await.unwrap();
        let _ = kv_store.clone().kv().put(reservation, value).await;
    }

    let app_state = AppState { listener_state, configuration, kv_store: kv_store.clone() };

    let app = app(app_state).into_make_service();

    (app, kv_store)
}

/// A way to specify which chainspec to use in testing
#[derive(Copy, Clone, PartialEq)]
pub enum ChainSpecType {
    /// The development chainspec, which has 3 TSS nodes
    Development,
    /// The integration test chainspec, which has 4 TSS nodes
    Integration,
}

/// Spawn either 3 or 4 TSS nodes depending on chain configuration, adding pre-stored keyshares if
/// desired
pub async fn spawn_testing_validators(
    chain_spec_type: ChainSpecType,
) -> (Vec<String>, Vec<PartyId>) {
    let add_fourth_server = chain_spec_type == ChainSpecType::Integration;

    // spawn threshold servers
    let mut ports = vec![3001i64, 3002, 3003];

    if add_fourth_server {
        ports.push(3004);
    }

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

    let mut ids = vec![alice_id, bob_id, charlie_id];

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

    if add_fourth_server {
        let (dave_axum, dave_kv) =
            create_clients("validator4".to_string(), vec![], vec![], &Some(ValidatorName::Dave))
                .await;

        let listener_dave = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", ports[3]))
            .await
            .expect("Unable to bind to given server address.");
        tokio::spawn(async move {
            axum::serve(listener_dave, dave_axum).await.unwrap();
        });
        let dave_id = PartyId::new(SubxtAccountId32(
            *get_signer(&dave_kv).await.unwrap().account_id().clone().as_ref(),
        ));
        ids.push(dave_id);
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    let ips = ports.iter().map(|port| format!("127.0.0.1:{port}")).collect();
    (ips, ids)
}

/// Add the pre-generated test keyshares to a kvdb
async fn put_keyshares_in_db(non_signer_name: ValidatorName, validator_name: ValidatorName) {
    let keyshare_bytes = {
        let project_root = project_root::get_project_root().expect("Error obtaining project root.");
        let file_path = project_root.join(format!(
            "crates/testing-utils/keyshares/production/{}/keyshare-held-by-{}.keyshare",
            non_signer_name, validator_name
        ));
        println!("File path {:?}", file_path);
        std::fs::read(file_path).unwrap()
    };

    let unsafe_put = UnsafeQuery { key: hex::encode(NETWORK_PARENT_KEY), value: keyshare_bytes };
    let unsafe_put = serde_json::to_string(&unsafe_put).unwrap();

    let port = 3001 + (validator_name as usize);
    let http_client = reqwest::Client::new();
    http_client
        .post(format!("http://127.0.0.1:{port}/unsafe/put"))
        .header("Content-Type", "application/json")
        .body(unsafe_put.clone())
        .send()
        .await
        .unwrap();
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

/// Mock the network being jump started by confirming a jump start even though no DKG took place,
/// so that we can use pre-store parent keyshares for testing
pub async fn jump_start_network_with_signer(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
) -> Option<ValidatorName> {
    let jump_start_request = entropy::tx().registry().jump_start_network();
    let _result = submit_transaction(api, rpc, signer, &jump_start_request, None).await.unwrap();

    let validators_names =
        vec![ValidatorName::Alice, ValidatorName::Bob, ValidatorName::Charlie, ValidatorName::Dave];
    let mut non_signer = None;
    for validator_name in validators_names.clone() {
        let mnemonic = development_mnemonic(&Some(validator_name));
        let (tss_signer, _static_secret) =
            get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();
        let jump_start_confirm_request =
            entropy::tx().registry().confirm_jump_start(BoundedVec(EVE_VERIFYING_KEY.to_vec()));

        // Ignore the error as one confirmation will fail
        if submit_transaction(api, rpc, &tss_signer, &jump_start_confirm_request, None)
            .await
            .is_err()
        {
            non_signer = Some(validator_name);
        }
    }
    if let Some(non_signer) = non_signer {
        for validator_name in validators_names {
            if non_signer != validator_name {
                put_keyshares_in_db(non_signer, validator_name).await;
            }
        }
    } else {
        tracing::error!("Missing non-signer - not storing pre-generated keyshares");
    }

    non_signer
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

    let selected_validators_query = entropy::storage().registry().jumpstart_dkg(block_number);
    let validators_info =
        query_chain(api, rpc, selected_validators_query, None).await.unwrap().unwrap();
    let validators_info: Vec<_> = validators_info.into_iter().map(|v| v.0).collect();
    let onchain_user_request =
        OcwMessageDkg { block_number, validators_info: validators_info.clone() };

    let client = reqwest::Client::new();

    let mut results = vec![];
    for validator_info in validators_info {
        let url = format!(
            "http://{}/generate_network_key",
            std::str::from_utf8(&validator_info.ip_address.clone()).unwrap()
        );
        if url != *"http://127.0.0.1:3001/generate_network_key" {
            results.push(client.post(url).body(onchain_user_request.clone().encode()).send())
        }
    }

    let response_results = join_all(results).await;

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
    for response_result in response_results {
        assert_eq!(response_result.unwrap().text().await.unwrap(), "");
    }
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
