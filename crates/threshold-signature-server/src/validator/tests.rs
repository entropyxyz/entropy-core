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
use super::api::check_balance_for_fees;
use crate::{
    helpers::{
        app_state::BlockNumberFields,
        tests::{
            call_set_storage, get_port, initialize_test_logger, run_to_block, setup_client,
            spawn_testing_validators, unsafe_get,
        },
    },
    validator::api::{is_signer_or_delete_parent_key, prune_old_holders, validate_new_reshare},
    EntropyConfig,
};
use entropy_client::{self as test_client};
use entropy_client::{
    chain_api::{
        entropy,
        entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec,
        entropy::runtime_types::entropy_runtime::RuntimeCall,
        entropy::runtime_types::frame_system::pallet::Call as SystemsCall,
        entropy::runtime_types::pallet_registry::pallet::ProgramInstance,
        entropy::runtime_types::pallet_staking_extension::pallet::{
            NextSignerInfo, ReshareInfo, ServerInfo,
        },
        get_api, get_rpc,
    },
    substrate::query_chain,
    Hasher,
};
use entropy_kvdb::clean_tests;
use entropy_shared::{OcwMessageReshare, MIN_BALANCE, NETWORK_PARENT_KEY};
use entropy_testing_utils::{
    constants::{
        ALICE_STASH_ADDRESS, AUXILARY_DATA_SHOULD_SUCCEED, PREIMAGE_SHOULD_SUCCEED, RANDOM_ACCOUNT,
        TEST_PROGRAM_WASM_BYTECODE,
    },
    substrate_context::{test_node_process_testing_state, testing_context},
    test_context_stationary, ChainSpecType,
};
use parity_scale_codec::Encode;
use serial_test::serial;
use sp_core::Pair;
use sp_keyring::AccountKeyring;
use std::collections::HashSet;
use subxt::{backend::legacy::LegacyRpcMethods, utils::AccountId32, OnlineClient};
use synedrion::k256::ecdsa::VerifyingKey;

#[tokio::test]
#[serial]
async fn test_reshare_basic() {
    initialize_test_logger().await;
    clean_tests();

    let (_validator_ips, _validator_ids) =
        spawn_testing_validators(crate::helpers::tests::ChainSpecType::IntegrationJumpStarted)
            .await;
    let force_authoring = true;
    let context =
        test_node_process_testing_state(ChainSpecType::IntegrationJumpStarted, force_authoring)
            .await;
    let api = get_api(&context[0].ws_url).await.unwrap();
    let rpc = get_rpc(&context[0].ws_url).await.unwrap();
    let alice_stash = AccountKeyring::AliceStash;
    let dave_stash = AccountKeyring::DaveStash;
    let client = reqwest::Client::new();

    // Get current signers
    let signer_query = entropy::storage().staking_extension().signers();
    let signer_stash_accounts = query_chain(&api, &rpc, signer_query, None).await.unwrap().unwrap();
    let old_signer_ids: HashSet<[u8; 32]> =
        HashSet::from_iter(signer_stash_accounts.clone().into_iter().map(|id| id.0));
    let signers = get_current_signers(&api, &rpc).await;
    let mut next_signers = vec![];
    run_to_block(&rpc, 7).await;

    for signer in signer_stash_accounts.iter() {
        next_signers.push(signer);
    }

    for signer in signers.iter() {
        let port = get_port(signer);
        let key_share = unsafe_get(&client, hex::encode(NETWORK_PARENT_KEY), port).await;
        assert!(!key_share.is_empty());
    }
    next_signers.remove(0);
    let binding = dave_stash.to_account_id().into();
    next_signers.push(&binding);

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    let storage_address_next_signers = entropy::storage().staking_extension().next_signers();
    let value_next_signers =
        NextSignerInfo { confirmations: vec![], next_signers: next_signers.clone() };
    // Add reshare
    let call = RuntimeCall::System(SystemsCall::set_storage {
        items: vec![(storage_address_next_signers.to_root_bytes(), value_next_signers.encode())],
    });
    call_set_storage(&api, &rpc, call).await;

    let storage_address_reshare_data = entropy::storage().staking_extension().reshare_data();
    let value_reshare_info =
        ReshareInfo { block_number, new_signers: vec![dave_stash.public().encode()] };
    // Add reshare
    let call = RuntimeCall::System(SystemsCall::set_storage {
        items: vec![(storage_address_reshare_data.to_root_bytes(), value_reshare_info.encode())],
    });
    call_set_storage(&api, &rpc, call).await;

    let key_shares_before = get_all_keys(signers).await;

    let mut i = 0;
    // Wait up to 2min for reshare to complete: check once every second if we have a new set of signers.
    let new_signer_ids = loop {
        let new_signer_ids: HashSet<[u8; 32]> = {
            let signer_query = entropy::storage().staking_extension().signers();
            let signer_ids = query_chain(&api, &rpc, signer_query, None).await.unwrap().unwrap();
            HashSet::from_iter(signer_ids.into_iter().map(|id| id.0))
        };
        if new_signer_ids != old_signer_ids {
            break Ok(new_signer_ids);
        }
        if i > 240 {
            break Err("Timed out waiting for reshare");
        }
        i += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    .unwrap();

    // wait for roatate keyshare
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    let signers = get_current_signers(&api, &rpc).await;
    let key_shares_after = get_all_keys(signers).await;

    assert_ne!(key_shares_before, key_shares_after);

    // At this point the signing set has changed on-chain, but the keyshares haven't been rotated
    // but by the time we have stored a program and registered, the rotation should have happened

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
        0u8,
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

    // Check that the new signers have keyshares
    for signer in new_signer_ids {
        let query = entropy::storage().staking_extension().threshold_servers(AccountId32(signer));
        let server_info = query_chain(&api, &rpc, query, None).await.unwrap().unwrap();
        let port = get_port(&server_info);
        let key_share = unsafe_get(&client, hex::encode(NETWORK_PARENT_KEY), port).await;
        assert!(!key_share.is_empty());
    }

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    let signers = get_current_signers(&api, &rpc).await;
    let key_share_before_2 = get_all_keys(signers).await;

    next_signers.remove(0);
    let binding = alice_stash.to_account_id().into();
    next_signers.push(&binding);

    let storage_address_next_signers = entropy::storage().staking_extension().next_signers();
    let value_next_signers = NextSignerInfo { confirmations: vec![], next_signers };
    // Add another reshare by adding next signer info
    let call = RuntimeCall::System(SystemsCall::set_storage {
        items: vec![(storage_address_next_signers.to_root_bytes(), value_next_signers.encode())],
    });
    call_set_storage(&api, &rpc, call).await;

    let storage_address_reshare_data = entropy::storage().staking_extension().reshare_data();
    let value_reshare_info =
        ReshareInfo { block_number, new_signers: vec![alice_stash.public().encode()] };
    // Same reshare needs reshare data too
    let call = RuntimeCall::System(SystemsCall::set_storage {
        items: vec![(storage_address_reshare_data.to_root_bytes(), value_reshare_info.encode())],
    });
    call_set_storage(&api, &rpc, call).await;

    // wait for roatate keyshare
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;

    let signers = get_current_signers(&api, &rpc).await;
    let key_share_after_2 = get_all_keys(signers).await;

    assert_ne!(key_share_before_2, key_share_after_2);

    clean_tests();
}

#[cfg(feature = "reshare-test")]
#[tokio::test]
#[serial]
async fn test_reshare_e2e() {
    initialize_test_logger().await;
    clean_tests();

    let (_validator_ips, _validator_ids) =
        spawn_testing_validators(crate::helpers::tests::ChainSpecType::IntegrationJumpStarted)
            .await;

    let force_authoring = true;
    let context =
        test_node_process_testing_state(ChainSpecType::IntegrationJumpStarted, force_authoring)
            .await;
    let api = get_api(&context[0].ws_url).await.unwrap();
    let rpc = get_rpc(&context[0].ws_url).await.unwrap();

    run_to_block(&rpc, 7).await;

    // Get current signers
    let signer_query = entropy::storage().staking_extension().signers();
    let signer_stash_accounts = query_chain(&api, &rpc, signer_query, None).await.unwrap().unwrap();
    let old_signer_ids: HashSet<[u8; 32]> =
        HashSet::from_iter(signer_stash_accounts.clone().into_iter().map(|id| id.0));
    let signers = get_current_signers(&api, &rpc).await;
    let key_share_before = get_all_keys(signers).await;

    let mut i = 0;
    // Wait up to 2min for reshare to complete: check once every second if we have a new set of signers.
    let old_signer_ids_2 = loop {
        let new_signer_ids: HashSet<[u8; 32]> = {
            let signer_query = entropy::storage().staking_extension().signers();
            let signer_ids = query_chain(&api, &rpc, signer_query, None).await.unwrap().unwrap();
            HashSet::from_iter(signer_ids.into_iter().map(|id| id.0))
        };
        if new_signer_ids != old_signer_ids {
            break Ok(new_signer_ids);
        }
        if i > 240 {
            break Err("Timed out waiting for reshare");
        }
        i += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    .unwrap();
    // wait for rotate keyshare
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    let signers = get_current_signers(&api, &rpc).await;
    let key_shares_after = get_all_keys(signers).await;

    assert_ne!(key_share_before, key_shares_after);

    let signers = get_current_signers(&api, &rpc).await;
    let key_share_before_2 = get_all_keys(signers).await;

    let _ = loop {
        let new_signer_ids: HashSet<[u8; 32]> = {
            let signer_query = entropy::storage().staking_extension().signers();
            let signer_ids = query_chain(&api, &rpc, signer_query, None).await.unwrap().unwrap();
            HashSet::from_iter(signer_ids.into_iter().map(|id| id.0))
        };
        if new_signer_ids != old_signer_ids_2 {
            break Ok(new_signer_ids);
        }
        if i > 240 {
            break Err("Timed out waiting for second reshare");
        }
        i += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    .unwrap();

    // wait for rotate keyshare 2
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    let signers = get_current_signers(&api, &rpc).await;
    let key_share_after_2 = get_all_keys(signers).await;

    assert_ne!(key_share_before_2, key_share_after_2);
}

#[tokio::test]
#[serial]
async fn test_reshare_none_called() {
    initialize_test_logger().await;
    clean_tests();

    let force_authoring = true;
    let _context =
        test_node_process_testing_state(ChainSpecType::Integration, force_authoring).await;

    let (_validator_ips, _validator_ids) =
        spawn_testing_validators(crate::helpers::tests::ChainSpecType::Integration).await;

    let validator_ports = vec![3001, 3002, 3003, 3004];

    let client = reqwest::Client::new();

    for i in 0..validator_ports.len() {
        let response = client
            .post(format!("http://127.0.0.1:{}/rotate_network_key", validator_ports[i]))
            .send()
            .await
            .unwrap();

        assert_eq!(response.text().await.unwrap(), "Chain Fetch: Rotate Keyshare not in progress");
    }
}

#[tokio::test]
#[serial]
async fn test_reshare_validation_fail() {
    initialize_test_logger().await;
    clean_tests();

    let dave = AccountKeyring::Dave;
    let alice = AccountKeyring::Alice;

    let cxt = &test_node_process_testing_state(ChainSpecType::Integration, true).await[0];
    let api = get_api(&cxt.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.ws_url).await.unwrap();
    let app_state = setup_client().await;

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    let mut ocw_message =
        OcwMessageReshare { new_signers: vec![dave.public().encode()], block_number };

    let err_stale_data = validate_new_reshare(&api, &rpc, &ocw_message, &app_state.cache)
        .await
        .map_err(|e| e.to_string());
    assert_eq!(err_stale_data, Err("Data is stale".to_string()));

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number - 1;
    let storage_address_reshare_data = entropy::storage().staking_extension().reshare_data();
    let value_reshare_info =
        ReshareInfo { block_number: block_number + 1, new_signers: vec![dave.public().encode()] };
    // Add reshare
    let call = RuntimeCall::System(SystemsCall::set_storage {
        items: vec![(storage_address_reshare_data.to_root_bytes(), value_reshare_info.encode())],
    });
    call_set_storage(&api, &rpc, call).await;
    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number - 1;
    ocw_message.block_number = block_number;

    // manipulates cache to get to repeated data error
    app_state.cache.write_to_block_numbers(BlockNumberFields::Reshare, block_number + 5).unwrap();

    let err_stale_data = validate_new_reshare(&api, &rpc, &ocw_message, &app_state.cache)
        .await
        .map_err(|e| e.to_string());
    assert_eq!(err_stale_data, Err("Data is repeated".to_string()));

    let value_reshare_info =
        ReshareInfo { block_number: 25, new_signers: vec![alice.public().encode()] };
    // Add reshare
    let call = RuntimeCall::System(SystemsCall::set_storage {
        items: vec![(storage_address_reshare_data.to_root_bytes(), value_reshare_info.encode())],
    });
    call_set_storage(&api, &rpc, call).await;
    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number - 1;
    ocw_message.block_number = block_number;

    let err_incorrect_data = validate_new_reshare(&api, &rpc, &ocw_message, &app_state.cache)
        .await
        .map_err(|e| e.to_string());
    assert_eq!(err_incorrect_data, Err("Data is not verifiable".to_string()));

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
    let app_state = setup_client().await;

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    let ocw_message =
        OcwMessageReshare { new_signers: vec![alice.public().encode()], block_number };

    run_to_block(&rpc, block_number + 1).await;

    let err_not_in_reshare = validate_new_reshare(&api, &rpc, &ocw_message, &app_state.cache)
        .await
        .map_err(|e| e.to_string());
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
#[serial]
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
#[serial]
async fn test_deletes_key() {
    initialize_test_logger().await;
    clean_tests();

    let dave = AccountKeyring::Dave;
    let kv = setup_client().await.kv_store;
    let reservation = kv.kv().reserve_key(hex::encode(NETWORK_PARENT_KEY)).await.unwrap();
    kv.kv().put(reservation, vec![10]).await.unwrap();

    let is_proper_signer_result =
        is_signer_or_delete_parent_key(&dave.to_account_id().into(), vec![], &kv).await.unwrap();
    assert!(!is_proper_signer_result);

    let has_key = kv.kv().exists(&hex::encode(NETWORK_PARENT_KEY)).await.unwrap();
    assert!(!has_key);
    clean_tests();
}

/// Get all the network keys from the server info provided
pub async fn get_all_keys(servers_info: Vec<ServerInfo<AccountId32>>) -> HashSet<Vec<u8>> {
    let client = reqwest::Client::new();
    let mut key_shares = vec![];
    for server_info in servers_info {
        let port = get_port(&server_info);
        let result = unsafe_get(&client, hex::encode(NETWORK_PARENT_KEY), port).await;
        if !result.is_empty() {
            key_shares.push(result);
        }
    }
    HashSet::from_iter(key_shares)
}

/// Gets the current signers server info
pub async fn get_current_signers(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Vec<ServerInfo<AccountId32>> {
    let signer_query = entropy::storage().staking_extension().signers();
    let signer_stash_accounts = query_chain(&api, &rpc, signer_query, None).await.unwrap().unwrap();
    let mut signers = Vec::new();
    for signer in signer_stash_accounts.iter() {
        let query = entropy::storage().staking_extension().threshold_servers(signer);
        let server_info = query_chain(&api, &rpc, query, None).await.unwrap().unwrap();
        signers.push(server_info);
    }
    signers
}
