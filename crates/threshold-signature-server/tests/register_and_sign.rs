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

use entropy_client::{
    chain_api::{
        entropy, entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec,
        entropy::runtime_types::pallet_registry::pallet::ProgramInstance, get_api, get_rpc,
        EntropyConfig,
    },
    client as test_client,
    substrate::{query_chain, submit_transaction},
    Hasher,
};
use entropy_kvdb::clean_tests;
use entropy_shared::OcwMessageDkg;
use entropy_testing_utils::{
    constants::{
        AUXILARY_DATA_SHOULD_SUCCEED, PREIMAGE_SHOULD_SUCCEED, TEST_PROGRAM_WASM_BYTECODE,
    },
    spawn_testing_validators, test_node_process_testing_state, ChainSpecType,
};
use entropy_tss::helpers::tests::{initialize_test_logger, run_to_block};
use futures::future::join_all;
use serial_test::serial;
use sp_core::{Encode, Pair};
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{
    backend::legacy::LegacyRpcMethods, events::EventsClient, tx::PairSigner, utils::AccountId32,
    OnlineClient,
};
use synedrion::k256::ecdsa::VerifyingKey;

#[tokio::test]
#[serial]
async fn integration_test_register_and_sign() {
    initialize_test_logger().await;
    clean_tests();

    let alice = AccountKeyring::Alice;

    let (_validator_ips, _validator_ids) =
        spawn_testing_validators(ChainSpecType::Integration).await;

    let force_authoring = true;
    let substrate_context = test_node_process_testing_state(force_authoring).await;

    let api = get_api(&substrate_context.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.ws_url).await.unwrap();

    let client = reqwest::Client::new();

    // First jumpstart the network
    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    put_jumpstart_request_on_chain(&api, &rpc, &alice).await;

    run_to_block(&rpc, block_number + 1).await;

    let selected_validators_query = entropy::storage().registry().jumpstart_dkg(block_number);
    let validators_info =
        query_chain(&api, &rpc, selected_validators_query, None).await.unwrap().unwrap();
    let validators_info: Vec<_> = validators_info.into_iter().map(|v| v.0).collect();
    let onchain_user_request = OcwMessageDkg { block_number, validators_info };

    let response_results = join_all(
        vec![3002, 3003, 3004]
            .iter()
            .map(|port| {
                client
                    .post(format!("http://127.0.0.1:{}/generate_network_key", port))
                    .body(onchain_user_request.clone().encode())
                    .send()
            })
            .collect::<Vec<_>>(),
    )
    .await;
    for response_result in response_results {
        assert_eq!(response_result.unwrap().text().await.unwrap(), "");
    }

    // Wait for jump start event
    let mut got_jumpstart_event = false;
    for _ in 0..75 {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let block_hash = rpc.chain_get_block_hash(None).await.unwrap();
        let events = EventsClient::new(api.clone()).at(block_hash.unwrap()).await.unwrap();
        let jump_start_event = events.find::<entropy::registry::events::FinishedNetworkJumpStart>();
        for _event in jump_start_event.flatten() {
            got_jumpstart_event = true;
            break;
        }
    }
    assert!(got_jumpstart_event);

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
}

async fn put_jumpstart_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    keyring: &Sr25519Keyring,
) {
    let account = PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(keyring.pair());

    let registering_tx = entropy::tx().registry().jump_start_network();
    submit_transaction(api, rpc, &account, &registering_tx, None).await.unwrap();
}
