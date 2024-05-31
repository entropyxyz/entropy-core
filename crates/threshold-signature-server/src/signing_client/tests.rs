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
    helpers::{
        launch::LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH,
        tests::{initialize_test_logger, run_to_block, setup_client, spawn_testing_validators},
    },
    r#unsafe::api::UnsafeQuery,
};
use entropy_kvdb::{clean_tests, kv_manager::helpers::serialize};
use entropy_protocol::{KeyParams, PartyId};
use entropy_shared::{
    constants::{DAVE_VERIFYING_KEY, DETERMINISTIC_KEY_SHARE_DAVE, EVE_VERIFYING_KEY},
    OcwMessageProactiveRefresh,
};
use entropy_testing_utils::{
    constants::{TSS_ACCOUNTS, X25519_PUBLIC_KEYS},
    substrate_context::{test_context_stationary, test_node_process_testing_state},
};
use futures::future::join_all;
use parity_scale_codec::Encode;
use rand_core::OsRng;
use serial_test::serial;
use sp_keyring::AccountKeyring;
use synedrion::{ecdsa::SigningKey, AuxInfo, KeyShare};

#[tokio::test]
#[serial]
async fn test_proactive_refresh() {
    initialize_test_logger().await;
    clean_tests();
    let _cxt = test_node_process_testing_state(false).await;

    let (validator_ips, ids, _users_keyshare_option) =
        spawn_testing_validators(Some(EVE_VERIFYING_KEY.to_vec()), None, true).await;

    let dave_signing_key =
        Some(SigningKey::from_bytes((&*DETERMINISTIC_KEY_SHARE_DAVE).into()).unwrap());
    let shares = KeyShare::<KeyParams, PartyId>::new_centralized(
        &mut OsRng,
        &ids,
        dave_signing_key.as_ref(),
    );
    let aux_infos = AuxInfo::<KeyParams, PartyId>::new_centralized(&mut OsRng, &ids);

    let client = reqwest::Client::new();
    let get_query_eve = UnsafeQuery::new(hex::encode(EVE_VERIFYING_KEY.to_vec()), vec![]).to_json();
    let get_query_dave =
        UnsafeQuery::new(hex::encode(DAVE_VERIFYING_KEY.to_vec()), vec![]).to_json();
    let converted_key_share_dave_0 =
        serialize(&(shares[0].to_threshold_key_share(), aux_infos[0].clone())).unwrap();
    let put_query_dave_0 = UnsafeQuery::new(
        hex::encode(DAVE_VERIFYING_KEY.to_vec()),
        converted_key_share_dave_0.clone(),
    )
    .to_json();

    let converted_key_share_dave_1 =
        serialize(&(shares[1].to_threshold_key_share(), aux_infos[1].clone())).unwrap();
    let put_query_dave_1 = UnsafeQuery::new(
        hex::encode(DAVE_VERIFYING_KEY.to_vec()),
        converted_key_share_dave_1.clone(),
    )
    .to_json();

    // check get key before proactive refresh
    let key_before_result_eve = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query_eve.clone())
        .send()
        .await
        .unwrap();

    let key_before_eve = key_before_result_eve.text().await.unwrap();

    // puts dave keyshare into first kvdb
    client
        .post("http://127.0.0.1:3001/unsafe/put")
        .header("Content-Type", "application/json")
        .body(put_query_dave_0)
        .send()
        .await
        .unwrap();
    // puts dave keyshare into second kvdb
    client
        .post("http://127.0.0.1:3002/unsafe/put")
        .header("Content-Type", "application/json")
        .body(put_query_dave_1)
        .send()
        .await
        .unwrap();

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
    ];

    let mut ocw_message = OcwMessageProactiveRefresh {
        validators_info,
        proactive_refresh_keys: vec![EVE_VERIFYING_KEY.to_vec(), DAVE_VERIFYING_KEY.to_vec()],
        block_number: 0,
    };

    let test_fail_incorrect_data =
        submit_transaction_requests(validator_ips.clone(), ocw_message.clone()).await;

    for res in test_fail_incorrect_data {
        assert_eq!(res.unwrap().text().await.unwrap(), "Proactive Refresh data incorrect");
    }
    ocw_message.validators_info[0].x25519_public_key = X25519_PUBLIC_KEYS[0];
    let test_user_res =
        submit_transaction_requests(validator_ips.clone(), ocw_message.clone()).await;

    for res in test_user_res {
        assert_eq!(res.unwrap().text().await.unwrap(), "");
    }
    // check get key after proactive refresh
    let key_after_result_eve = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query_eve.clone())
        .send()
        .await
        .unwrap();

    // check get key before proactive refresh
    let key_after_result_dave = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query_dave.clone())
        .send()
        .await
        .unwrap();

    let key_after_eve = key_after_result_eve.text().await.unwrap();
    let key_after_dave = key_after_result_dave.text().await.unwrap();

    // make sure private keyshares are changed
    assert_ne!(key_before_eve, key_after_eve);
    assert_ne!(converted_key_share_dave_0, serialize(&key_after_dave).unwrap());

    let alice = AccountKeyring::Alice;
    ocw_message.validators_info[0].tss_account = alice.public().encode();
    ocw_message.validators_info[1].tss_account = alice.public().encode();

    let test_user_res_not_in_group =
        submit_transaction_requests(validator_ips.clone(), ocw_message.clone()).await;
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
                let url = format!("http://{}/signer/proactive_refresh", ip.clone());
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

    let dave = AccountKeyring::Dave;
    let eve = AccountKeyring::Eve;
    let cxt = test_context_stationary().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();
    let kv = setup_client().await;
    let validators_info = vec![
        entropy_shared::ValidatorInfo {
            ip_address: "127.0.0.1:3001".as_bytes().to_vec(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            tss_account: TSS_ACCOUNTS[0].clone().encode(),
        },
        entropy_shared::ValidatorInfo {
            ip_address: "127.0.0.1:3002".as_bytes().to_vec(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[1].clone().encode(),
        },
    ];

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    let ocw_message = OcwMessageProactiveRefresh {
        validators_info,
        proactive_refresh_keys: vec![dave.to_account_id().encode(), eve.to_account_id().encode()],
        block_number,
    };
    run_to_block(&rpc, block_number).await;

    // manipulates kvdb to get to repeated data error
    kv.kv().delete(LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH).await.unwrap();
    let reservation =
        kv.kv().reserve_key(LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH.to_string()).await.unwrap();
    kv.kv().put(reservation, (block_number + 5).to_be_bytes().to_vec()).await.unwrap();

    let err_stale_data =
        validate_proactive_refresh(&api, &rpc, &kv, &ocw_message).await.map_err(|e| e.to_string());
    assert_eq!(err_stale_data, Err("Data is repeated".to_string()));
    clean_tests();
}
