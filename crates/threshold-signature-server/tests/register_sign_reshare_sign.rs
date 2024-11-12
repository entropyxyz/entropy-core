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

use std::collections::HashSet;

use entropy_client::{
    chain_api::{
        entropy, entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec,
        entropy::runtime_types::pallet_registry::pallet::ProgramInstance, get_api, get_rpc,
        EntropyConfig,
    },
    client as test_client,
    substrate::query_chain,
    Hasher,
};
use entropy_kvdb::clean_tests;
use entropy_shared::TEST_RESHARE_BLOCK_NUMBER;
use entropy_testing_utils::{
    constants::{
        AUXILARY_DATA_SHOULD_SUCCEED, PREIMAGE_SHOULD_SUCCEED, TEST_PROGRAM_WASM_BYTECODE,
    },
    spawn_testing_validators, test_node_process_testing_state, ChainSpecType,
};
use entropy_tss::helpers::tests::{do_jump_start, initialize_test_logger, run_to_block};
use serial_test::serial;
use sp_core::Pair;
use sp_keyring::AccountKeyring;
use subxt::{backend::legacy::LegacyRpcMethods, utils::AccountId32, OnlineClient};
use synedrion::k256::ecdsa::VerifyingKey;

#[tokio::test]
#[serial]
async fn integration_test_register_sign_reshare_sign() {
    initialize_test_logger().await;
    clean_tests();

    let (_validator_ips, _validator_ids) =
        spawn_testing_validators(ChainSpecType::Integration).await;

    let force_authoring = true;
    let substrate_context = &test_node_process_testing_state(force_authoring).await[0];

    let api = get_api(&substrate_context.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.ws_url).await.unwrap();

    // First jumpstart the network
    do_jump_start(&api, &rpc, AccountKeyring::Alice.pair()).await;

    let initial_signers = {
        let signer_query = entropy::storage().staking_extension().signers();
        query_chain(&api, &rpc, signer_query, None).await.unwrap().unwrap()
    };

    // Do a reshare
    wait_for_reshare(&api, &rpc, initial_signers).await;

    // Now register an account
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

    // Sign a message again
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
}

async fn wait_for_reshare(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    initial_signers: Vec<AccountId32>,
) {
    let reshare_data_query = entropy::storage().staking_extension().reshare_data();
    let reshare_data = query_chain(&api, &rpc, reshare_data_query, None).await.unwrap().unwrap();
    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    dbg!(block_number);
    println!("reshare_data {reshare_data:?}");

    // let block_number = TEST_RESHARE_BLOCK_NUMBER + 20;
    // run_to_block(&rpc, block_number).await;

    // let new_signers = {
    //     let signer_query = entropy::storage().staking_extension().signers();
    //     let signer_ids = query_chain(&api, &rpc, signer_query, None).await.unwrap().unwrap();
    //     let mut signers = Vec::new();
    //     for signer in signer_ids {
    //         let query = entropy::storage().staking_extension().threshold_servers(signer);
    //         let server_info = query_chain(&api, &rpc, query, None).await.unwrap().unwrap();
    //         signers.push(server_info);
    //     }
    //     signers
    // };

    // Tell TS servers who do not have an associated chain node to rotate their keyshare.
    // This is called by the chain on getting confirmation of the reshare from all of the new
    // signing group.
    // for signer in new_signers {
    //     let _ = client
    //         .post(format!(
    //             "http://{}/rotate_network_key",
    //             std::str::from_utf8(&signer.endpoint).unwrap()
    //         ))
    //         .send()
    //         .await
    //         .unwrap();
    // }

    let initial_signers_set: HashSet<[u8; 32]> = initial_signers.iter().map(|s| s.0).collect();
    loop {
        // Check that the signers have changed since before the reshare
        let signer_query = entropy::storage().staking_extension().signers();
        let new_signer_stash_accounts =
            query_chain(&api, &rpc, signer_query, None).await.unwrap().unwrap();
        let new_signers_set: HashSet<[u8; 32]> =
            new_signer_stash_accounts.iter().map(|s| s.0).collect();
        // assert_ne!(initial_signers_set, new);
        if initial_signers_set != new_signers_set {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
