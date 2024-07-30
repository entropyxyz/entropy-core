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
        launch::{development_mnemonic, ValidatorName, FORBIDDEN_KEYS},
        substrate::submit_transaction,
        tests::{initialize_test_logger, run_to_block, spawn_testing_validators, unsafe_get},
        validator::get_signer_and_x25519_secret_from_mnemonic,
    },
    validator::errors::ValidatorErr,
};
use entropy_kvdb::clean_tests;
use entropy_shared::{OcwMessageReshare, EVE_VERIFYING_KEY, MIN_BALANCE, NETWORK_PARENT_KEY};
use entropy_testing_utils::{
    constants::{ALICE_STASH_ADDRESS, RANDOM_ACCOUNT},
    substrate_context::{test_node_process_testing_state, testing_context},
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

    let alice = AccountKeyring::Alice;
    dbg!(alice.public().encode());
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

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
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
        assert_ne!(
            key_shares_before[i],
            unsafe_get(&client, hex::encode(NETWORK_PARENT_KEY), validator_ports[i]).await
        );
    }

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

    let validators_names = vec![ValidatorName::Alice, ValidatorName::Bob];
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
