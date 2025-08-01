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

use super::api::validate_proactive_refresh;
use crate::{
    chain_api::{get_api, get_rpc},
    helpers::tests::{setup_client, spawn_testing_validators, unsafe_get_network_keyshare},
};
use entropy_client::logger::initialize_test_logger;
use entropy_kvdb::{clean_tests, kv_manager::helpers::serialize};
use entropy_shared::{constants::PREGENERATED_NETWORK_VERIFYING_KEY, OcwMessageProactiveRefresh};
use entropy_testing_utils::{
    constants::{TSS_ACCOUNTS, X25519_PUBLIC_KEYS},
    substrate_context::{test_node_process_stationary_local, test_node_process_testing_state},
    ChainSpecType,
};
use futures::future::join_all;
use parity_scale_codec::Encode;
use serial_test::serial;
use sp_keyring::sr25519::Keyring;

#[ignore]
#[tokio::test]
#[serial]
async fn test_proactive_refresh() {
    initialize_test_logger().await;
    clean_tests();
    let _cxt =
        &test_node_process_testing_state(ChainSpecType::IntegrationJumpStarted, false).await[0];

    let (validator_ips, _ids) =
        spawn_testing_validators(crate::helpers::tests::ChainSpecType::IntegrationJumpStarted)
            .await;
    let signing_committee_ips = &validator_ips[..3].to_vec();

    let client = reqwest::Client::new();

    // check get key before proactive refresh
    let key_before_network =
        serialize(&unsafe_get_network_keyshare(&client, 3001).await.unwrap()).unwrap();

    let validators_info = vec![
        entropy_shared::ValidatorInfo {
            ip_address: "127.0.0.1:3001".as_bytes().to_vec(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[0].clone().encode(),
        },
        entropy_shared::ValidatorInfo {
            ip_address: "127.0.0.1:3002".as_bytes().to_vec(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[1].clone().encode(),
        },
        entropy_shared::ValidatorInfo {
            ip_address: "127.0.0.1:3003".as_bytes().to_vec(),
            x25519_public_key: X25519_PUBLIC_KEYS[2],
            tss_account: TSS_ACCOUNTS[2].clone().encode(),
        },
    ];

    let mut ocw_message = OcwMessageProactiveRefresh {
        validators_info,
        proactive_refresh_keys: vec![PREGENERATED_NETWORK_VERIFYING_KEY.to_vec()],
        block_number: 0,
    };

    let test_fail_incorrect_data =
        submit_transaction_requests(signing_committee_ips.clone(), ocw_message.clone()).await;

    for res in test_fail_incorrect_data {
        assert_eq!(res.unwrap().text().await.unwrap(), "Proactive Refresh data incorrect");
    }
    ocw_message.validators_info[0].x25519_public_key = X25519_PUBLIC_KEYS[0];
    let test_user_res =
        submit_transaction_requests(signing_committee_ips.clone(), ocw_message.clone()).await;

    for res in test_user_res {
        assert_eq!(res.unwrap().text().await.unwrap(), "");
    }

    let key_after_network =
        serialize(&unsafe_get_network_keyshare(&client, 3001).await.unwrap()).unwrap();

    // make sure private keyshares are changed
    assert_ne!(key_before_network, key_after_network);

    let alice = Keyring::Alice;
    ocw_message.validators_info[0].tss_account = alice.public().encode();
    ocw_message.validators_info[1].tss_account = alice.public().encode();
    ocw_message.validators_info[2].tss_account = alice.public().encode();

    let test_user_res_not_in_group =
        submit_transaction_requests(signing_committee_ips.clone(), ocw_message.clone()).await;
    for res in test_user_res_not_in_group {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "User Error: Invalid Signer: Invalid Signer in Signing group"
        );
    }

    clean_tests();
}

pub async fn submit_transaction_requests(
    validator_urls: Vec<String>,
    ocw_message: OcwMessageProactiveRefresh,
) -> Vec<std::result::Result<reqwest::Response, reqwest::Error>> {
    let mock_client = reqwest::Client::new();
    join_all(
        validator_urls
            .iter()
            .map(|ip| async {
                let url = format!("http://{}/v1/signer/proactive_refresh", ip.clone());
                mock_client
                    .post(url)
                    .header("Content-Type", "application/json")
                    .body(ocw_message.clone().encode())
                    .send()
                    .await
            })
            .collect::<Vec<_>>(),
    )
    .await
}

#[tokio::test]
#[serial]
async fn test_proactive_refresh_validation_fail() {
    initialize_test_logger().await;
    clean_tests();

    let dave = Keyring::Dave;
    let cxt = test_node_process_stationary_local().await;
    let api = get_api(&cxt.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.ws_url).await.unwrap();
    let app_state = setup_client().await;

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    let mut ocw_message = OcwMessageProactiveRefresh {
        validators_info: vec![],
        proactive_refresh_keys: vec![],
        block_number,
    };

    let err_stale_data = validate_proactive_refresh(&api, &rpc, &app_state.cache, &ocw_message)
        .await
        .map_err(|e| e.to_string());
    assert_eq!(err_stale_data, Err("Data is repeated".to_string()));

    ocw_message.proactive_refresh_keys = vec![dave.to_account_id().encode()];
    let err_stale_data = validate_proactive_refresh(&api, &rpc, &app_state.cache, &ocw_message)
        .await
        .map_err(|e| e.to_string());
    assert_eq!(err_stale_data, Err("Proactive Refresh data incorrect".to_string()));
    clean_tests();
}
