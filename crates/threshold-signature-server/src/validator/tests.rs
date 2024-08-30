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
    helpers::{
        launch::{FORBIDDEN_KEYS, LATEST_BLOCK_NUMBER_RESHARE},
        tests::{
            initialize_test_logger, run_to_block, setup_client, spawn_testing_validators,
            unsafe_get, ChainSpecType,
        },
    },
    user::tests::jump_start_network,
    validator::{
        api::{is_signer_or_delete_parent_key, prune_old_holders, validate_new_reshare},
        errors::ValidatorErr,
    },
};
use entropy_client as test_client;
use entropy_client::{
    chain_api::{
        entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec,
        entropy::runtime_types::pallet_registry::pallet::ProgramInstance, get_api, get_rpc,
    },
    Hasher,
};
use entropy_kvdb::{
    clean_tests,
    kv_manager::helpers::{deserialize, serialize},
};
use entropy_protocol::KeyShareWithAuxInfo;
use entropy_shared::{
    OcwMessageReshare, MIN_BALANCE, NETWORK_PARENT_KEY, TEST_RESHARE_BLOCK_NUMBER,
};
use entropy_testing_utils::constants::{
    AUXILARY_DATA_SHOULD_SUCCEED, PREIMAGE_SHOULD_SUCCEED, TEST_PROGRAM_WASM_BYTECODE,
};
use entropy_testing_utils::{
    constants::{ALICE_STASH_ADDRESS, RANDOM_ACCOUNT},
    substrate_context::{test_node_process_testing_state, testing_context},
    test_context_stationary,
};
use futures::future::join_all;
use parity_scale_codec::Encode;
use serial_test::serial;
use sp_core::Pair;
use sp_keyring::AccountKeyring;
use subxt::utils::AccountId32;
use synedrion::k256::ecdsa::VerifyingKey;

#[tokio::test]
#[serial]
async fn test_reshare() {
    initialize_test_logger().await;
    clean_tests();

    let dave = AccountKeyring::DaveStash;

    let cxt = test_node_process_testing_state(true).await;

    let add_parent_key_to_kvdb = true;
    let (_validator_ips, _validator_ids) =
        spawn_testing_validators(add_parent_key_to_kvdb, ChainSpecType::Integration).await;

    let validator_ports = vec![3001, 3002, 3003, 3004];
    let api = get_api(&cxt.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.ws_url).await.unwrap();

    let client = reqwest::Client::new();
    let mut key_shares_before = vec![];
    for port in &validator_ports[..3] {
        key_shares_before.push(unsafe_get(&client, hex::encode(NETWORK_PARENT_KEY), *port).await);
    }

    jump_start_network(&api, &rpc).await;

    let block_number = TEST_RESHARE_BLOCK_NUMBER;
    let onchain_reshare_request =
        OcwMessageReshare { new_signer: dave.public().encode(), block_number };

    run_to_block(&rpc, block_number + 1).await;

    let response_results = join_all(
        validator_ports[1..]
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

    for i in 0..3 {
        let (key_share_before, aux_info_before): KeyShareWithAuxInfo =
            deserialize(&key_shares_before[i]).unwrap();

        // We add one to the port number here because after the reshare the siging committee has
        // shifted from alice, bob, charlie to bob, charlie, dave
        let key_share_and_aux_data_after =
            unsafe_get(&client, hex::encode(NETWORK_PARENT_KEY), validator_ports[i + 1]).await;
        let (key_share_after, aux_info_after): KeyShareWithAuxInfo =
            deserialize(&key_share_and_aux_data_after).unwrap();

        // Check key share has changed
        assert_ne!(serialize(&key_share_before).unwrap(), serialize(&key_share_after).unwrap());
        // Check aux info has changed
        assert_ne!(serialize(&aux_info_before).unwrap(), serialize(&aux_info_after).unwrap());
    }

    // Now test signing a message with the new keyshare set
    let account_owner = AccountKeyring::Ferdie.pair();
    let signature_request_author = AccountKeyring::One;
    // Store a program
    let program_pointer = test_client::store_program(
        &api,
        &rpc,
        &account_owner,
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    // Register, using that program
    let (verifying_key, _registered_info) = test_client::register(
        &api,
        &rpc,
        account_owner.clone(),
        AccountId32(account_owner.public().0),
        BoundedVec(vec![ProgramInstance { program_pointer, program_config: vec![] }]),
    )
    .await
    .unwrap();

    // Sign a message
    let recoverable_signature = test_client::sign(
        &api,
        &rpc,
        signature_request_author.pair(),
        verifying_key,
        PREIMAGE_SHOULD_SUCCEED.to_vec(),
        Some(AUXILARY_DATA_SHOULD_SUCCEED.to_vec()),
    )
    .await
    .unwrap();

    // Check the signature
    let message_should_succeed_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);
    let recovery_key_from_sig = VerifyingKey::recover_from_prehash(
        &message_should_succeed_hash,
        &recoverable_signature.signature,
        recoverable_signature.recovery_id,
    )
    .unwrap();
    assert_eq!(
        verifying_key.to_vec(),
        recovery_key_from_sig.to_encoded_point(true).to_bytes().to_vec()
    );
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
async fn test_deletes_key() {
    initialize_test_logger().await;
    clean_tests();

    let dave = AccountKeyring::Dave;
    let kv = setup_client().await;
    let reservation = kv.kv().reserve_key(hex::encode(NETWORK_PARENT_KEY)).await.unwrap();
    kv.kv().put(reservation, vec![10]).await.unwrap();

    let is_proper_signer_result =
        is_signer_or_delete_parent_key(&dave.to_account_id().into(), vec![], &kv).await.unwrap();
    assert!(!is_proper_signer_result);

    let has_key = kv.kv().exists(&hex::encode(NETWORK_PARENT_KEY)).await.unwrap();
    assert!(!has_key);
    clean_tests();
}
