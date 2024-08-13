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
use super::api::{check_balance_for_fees, check_forbidden_key};
use crate::{
    chain_api::{
        entropy::{self, runtime_types::bounded_collections::bounded_vec},
        get_api, get_rpc, EntropyConfig,
    },
    helpers::{
        launch::{
            development_mnemonic, ValidatorName, FORBIDDEN_KEYS, LATEST_BLOCK_NUMBER_RESHARE,
        },
        substrate::submit_transaction,
        tests::{
            initialize_test_logger, run_to_block, setup_client, spawn_testing_validators,
            unsafe_get,
        },
        validator::get_signer_and_x25519_secret_from_mnemonic,
    },
    validator::{
        api::{prune_old_holders, validate_new_reshare},
        errors::ValidatorErr,
    },
};
use entropy_kvdb::{
    clean_tests,
    kv_manager::helpers::{deserialize, serialize},
};
use entropy_protocol::KeyShareWithAuxInfo;
use entropy_shared::{
    OcwMessageReshare, QuoteInputData, EVE_VERIFYING_KEY, MIN_BALANCE, NETWORK_PARENT_KEY,
    TEST_RESHARE_BLOCK_NUMBER,
};
use entropy_testing_utils::{
    constants::{ALICE_STASH_ADDRESS, RANDOM_ACCOUNT, TSS_ACCOUNTS, X25519_PUBLIC_KEYS},
    substrate_context::{test_node_process_testing_state, testing_context},
    test_context_stationary,
};
use futures::future::join_all;
use parity_scale_codec::Encode;
use serial_test::serial;
use sp_keyring::AccountKeyring;
use subxt::{
    backend::legacy::LegacyRpcMethods, ext::sp_core::sr25519, tx::PairSigner, OnlineClient,
};

#[tokio::test]
#[serial]
async fn test_reshare() {
    initialize_test_logger().await;
    clean_tests();

    let alice = AccountKeyring::AliceStash;

    let cxt = test_node_process_testing_state(true).await;
    let (_validator_ips, _validator_ids) = spawn_testing_validators(true).await;
    let validator_ports = vec![3001, 3002, 3003];
    let api = get_api(&cxt.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.ws_url).await.unwrap();

    let client = reqwest::Client::new();
    let mut key_shares_before = vec![];
    for port in &validator_ports {
        key_shares_before.push(unsafe_get(&client, hex::encode(NETWORK_PARENT_KEY), *port).await);
    }

    setup_for_reshare(&api, &rpc).await;

    let block_number = TEST_RESHARE_BLOCK_NUMBER;
    let onchain_reshare_request =
        OcwMessageReshare { new_signer: alice.public().encode(), block_number };

    run_to_block(&rpc, block_number + 1).await;

    let response_results = join_all(
        validator_ports
            .iter()
            .map(|port| {
                client
                    .post(format!("http://127.0.0.1:{}/validator/reshare", port))
                    .body(onchain_reshare_request.clone().encode())
                    .send()
            })
            .collect::<Vec<_>>(),
    )
    .await;
    for response_result in response_results {
        assert_eq!(response_result.unwrap().text().await.unwrap(), "");
    }

    for i in 0..validator_ports.len() {
        let (key_share_before, aux_info_before): KeyShareWithAuxInfo =
            deserialize(&key_shares_before[i]).unwrap();

        let key_share_and_aux_data_after =
            unsafe_get(&client, hex::encode(NETWORK_PARENT_KEY), validator_ports[i]).await;
        let (key_share_after, aux_info_after): KeyShareWithAuxInfo =
            deserialize(&key_share_and_aux_data_after).unwrap();

        // Check key share has changed
        assert_ne!(serialize(&key_share_before).unwrap(), serialize(&key_share_after).unwrap());
        // Check aux info has changed
        assert_ne!(serialize(&aux_info_before).unwrap(), serialize(&aux_info_after).unwrap());
    }
    // TODO #981 - test signing a message with the new keyshare set
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_reshare_validation_fail() {
    initialize_test_logger().await;
    clean_tests();

    let dave = AccountKeyring::Dave;
    let cxt = test_node_process_testing_state(true).await;
    let api = get_api(&cxt.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.ws_url).await.unwrap();
    let kv = setup_client().await;

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    let mut ocw_message = OcwMessageReshare { new_signer: dave.public().encode(), block_number };

    let err_stale_data =
        validate_new_reshare(&api, &rpc, &ocw_message, &kv).await.map_err(|e| e.to_string());
    assert_eq!(err_stale_data, Err("Data is stale".to_string()));

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    ocw_message.block_number = block_number;
    run_to_block(&rpc, block_number + 1).await;

    let err_incorrect_data =
        validate_new_reshare(&api, &rpc, &ocw_message, &kv).await.map_err(|e| e.to_string());
    assert_eq!(err_incorrect_data, Err("Data is not verifiable".to_string()));

    // manipulates kvdb to get to repeated data error
    kv.kv().delete(LATEST_BLOCK_NUMBER_RESHARE).await.unwrap();
    let reservation = kv.kv().reserve_key(LATEST_BLOCK_NUMBER_RESHARE.to_string()).await.unwrap();
    kv.kv().put(reservation, (block_number + 5).to_be_bytes().to_vec()).await.unwrap();

    let err_stale_data =
        validate_new_reshare(&api, &rpc, &ocw_message, &kv).await.map_err(|e| e.to_string());
    assert_eq!(err_stale_data, Err("Data is repeated".to_string()));
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_reshare_validation_fail_not_in_reshare() {
    initialize_test_logger().await;
    clean_tests();

    let alice = AccountKeyring::Alice;
    let cxt = test_context_stationary().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();
    let kv = setup_client().await;

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    let ocw_message = OcwMessageReshare { new_signer: alice.public().encode(), block_number };

    run_to_block(&rpc, block_number + 1).await;

    let err_not_in_reshare =
        validate_new_reshare(&api, &rpc, &ocw_message, &kv).await.map_err(|e| e.to_string());
    assert_eq!(err_not_in_reshare, Err("Chain Fetch: Not Currently in a reshare".to_string()));

    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_empty_next_signer() {
    initialize_test_logger().await;
    clean_tests();

    let cxt = test_context_stationary().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();

    assert!(prune_old_holders(&api, &rpc, vec![], vec![]).await.is_ok());

    clean_tests();
}

async fn setup_for_reshare(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) {
    let alice = AccountKeyring::Alice;
    let signer = PairSigner::<EntropyConfig, sr25519::Pair>::new(alice.clone().into());

    let jump_start_request = entropy::tx().registry().jump_start_network();
    let _result = submit_transaction(api, rpc, &signer, &jump_start_request, None).await.unwrap();

    let validators_names = vec![ValidatorName::Bob, ValidatorName::Charlie, ValidatorName::Dave];
    for validator_name in validators_names {
        let mnemonic = development_mnemonic(&Some(validator_name));
        let (tss_signer, _static_secret) =
            get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();
        let jump_start_confirm_request = entropy::tx()
            .registry()
            .confirm_jump_start(bounded_vec::BoundedVec(EVE_VERIFYING_KEY.to_vec()));

        submit_transaction(api, rpc, &tss_signer, &jump_start_confirm_request, None).await.unwrap();
    }
}
#[tokio::test]
#[should_panic = "Account does not exist, add balance"]
async fn test_check_balance_for_fees() {
    initialize_test_logger().await;
    let cxt = testing_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();

    let result = check_balance_for_fees(&api, &rpc, ALICE_STASH_ADDRESS.to_string(), MIN_BALANCE)
        .await
        .unwrap();

    assert!(result);

    let result_2 = check_balance_for_fees(
        &api,
        &rpc,
        ALICE_STASH_ADDRESS.to_string(),
        10000000000000000000000u128,
    )
    .await
    .unwrap();
    assert!(!result_2);

    let _ = check_balance_for_fees(&api, &rpc, (&RANDOM_ACCOUNT).to_string(), MIN_BALANCE)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_forbidden_keys() {
    initialize_test_logger().await;
    let should_fail = check_forbidden_key(FORBIDDEN_KEYS[0]);
    assert_eq!(should_fail.unwrap_err().to_string(), ValidatorErr::ForbiddenKey.to_string());

    let should_pass = check_forbidden_key("test");
    assert_eq!(should_pass.unwrap(), ());
}

#[tokio::test]
#[serial]
async fn test_attest() {
    initialize_test_logger().await;
    clean_tests();

    let _cxt = test_node_process_testing_state(false).await;
    let (_validator_ips, _validator_ids) = spawn_testing_validators(false).await;

    let nonce = [0; 32];
    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://127.0.0.1:3001/attest"))
        .body(nonce.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let quote = res.bytes().await.unwrap();

    // This internally verifies the signature in the quote
    let quote = tdx_quote::Quote::from_bytes(&quote).unwrap();

    // Check the input data of the quote
    let expected_input_data =
        QuoteInputData::new(TSS_ACCOUNTS[0].0, X25519_PUBLIC_KEYS[0], nonce, 0);
    assert_eq!(quote.report_input_data(), expected_input_data.0);
}
