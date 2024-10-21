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
use crate::{
    attestation::api::validate_new_attestation,
    chain_api::{entropy, get_api, get_rpc},
    helpers::{
        substrate::query_chain,
        tests::{
            initialize_test_logger, run_to_block, setup_client, spawn_testing_validators,
            ChainSpecType,
        },
    },
    launch::LATEST_BLOCK_NUMBER_ATTEST,
};
use entropy_kvdb::clean_tests;
use entropy_shared::OcwMessageAttestationRequest;
use entropy_testing_utils::{
    constants::TSS_ACCOUNTS,
    substrate_context::{test_context_stationary, test_node_process_stationary},
};
use serial_test::serial;

#[ignore]
#[tokio::test]
#[serial]
async fn test_attest() {
    initialize_test_logger().await;
    clean_tests();

    let cxt = test_node_process_stationary().await;
    let (_validator_ips, _validator_ids) =
        spawn_testing_validators(ChainSpecType::Integration).await;

    let api = get_api(&cxt.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.ws_url).await.unwrap();

    // Check that there is an attestation request at block 3 from the genesis config
    let attestation_requests_query = entropy::storage().attestation().attestation_requests(3);
    query_chain(&api, &rpc, attestation_requests_query, None).await.unwrap().unwrap();

    // Get the nonce from the pending attestation from the genesis config
    let nonce = {
        let pending_attestation_query =
            entropy::storage().attestation().pending_attestations(&TSS_ACCOUNTS[0]);
        query_chain(&api, &rpc, pending_attestation_query, None).await.unwrap().unwrap()
    };
    assert_eq!(nonce, [0; 32]);

    // Wait for the attestation to be handled
    for _ in 0..10 {
        let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
        run_to_block(&rpc, block_number + 1).await;

        // There should be no more pending attestation as the attestation has been handled
        let pending_attestation_query =
            entropy::storage().attestation().pending_attestations(&TSS_ACCOUNTS[0]);
        if query_chain(&api, &rpc, pending_attestation_query, None).await.unwrap().is_none() {
            return;
        }
    }
    panic!("Waited 10 blocks and attestation is still pending");
}

#[ignore]
#[tokio::test]
#[serial]
async fn test_attest_validation_fail() {
    initialize_test_logger().await;
    clean_tests();

    let cxt = test_context_stationary().await;
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();
    let kv = setup_client().await;

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    let ocw_message = OcwMessageAttestationRequest { tss_account_ids: vec![], block_number };
    let err_stale_data =
        validate_new_attestation(block_number, &ocw_message, &kv).await.map_err(|e| e.to_string());
    assert_eq!(err_stale_data, Err("Data is stale".to_string()));
    run_to_block(&rpc, block_number).await;

    // manipulates kvdb to get to repeated data error
    kv.kv().delete(LATEST_BLOCK_NUMBER_ATTEST).await.unwrap();
    let reservation = kv.kv().reserve_key(LATEST_BLOCK_NUMBER_ATTEST.to_string()).await.unwrap();
    kv.kv().put(reservation, (block_number + 5).to_be_bytes().to_vec()).await.unwrap();

    let err_repeated_data =
        validate_new_attestation(block_number, &ocw_message, &kv).await.map_err(|e| e.to_string());
    assert_eq!(err_repeated_data, Err("Data is repeated".to_string()));
    clean_tests();
}
