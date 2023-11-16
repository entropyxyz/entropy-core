use super::api::{partition_all_keys, validate_proactive_refresh};
use crate::{
    chain_api::{get_api, get_rpc},
    helpers::{
        launch::LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH,
        tests::{initialize_test_logger, run_to_block, setup_client, spawn_testing_validators},
    },
    r#unsafe::api::UnsafeQuery,
};
use entropy_shared::OcwMessageProactiveRefresh;
use futures::future::join_all;
use kvdb::{clean_tests, kv_manager::helpers::serialize};
use parity_scale_codec::Encode;
use serial_test::serial;
use sp_core::crypto::Ss58Codec;
use sp_keyring::AccountKeyring;
use testing_utils::{
    constants::{TSS_ACCOUNTS, X25519_PUBLIC_KEYS},
    substrate_context::{test_context_stationary, test_node_process_testing_state},
};

#[tokio::test]
#[serial]
async fn test_proactive_refresh() {
    initialize_test_logger();
    clean_tests();
    let eve = AccountKeyring::Eve;
    let dave = AccountKeyring::Dave;
    let _cxt = test_node_process_testing_state(false).await;

    let signing_address = eve.to_account_id().to_ss58check();
    let (validator_ips, _validator_ids, users_keyshare_option) =
        spawn_testing_validators(Some(signing_address.clone()), true).await;

    let client = reqwest::Client::new();
    let converted_key_share = serialize(&users_keyshare_option.unwrap()).unwrap();
    let get_query_eve = UnsafeQuery::new(eve.to_account_id().to_string(), vec![]).to_json();
    let get_query_dave =
        UnsafeQuery::new(dave.to_account_id().to_string(), converted_key_share.clone()).to_json();

    // check get key before proactive refresh
    let key_before_result_eve = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query_eve.clone())
        .send()
        .await
        .unwrap();

    let key_before_eve = key_before_result_eve.text().await.unwrap();

    // puts dave key into kvdb
    client
        .post("http://127.0.0.1:3001/unsafe/put")
        .header("Content-Type", "application/json")
        .body(get_query_dave.clone())
        .send()
        .await
        .unwrap();
    // puts dave key into kvdb
    client
        .post("http://127.0.0.1:3002/unsafe/put")
        .header("Content-Type", "application/json")
        .body(get_query_dave.clone())
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

    let mut ocw_message = OcwMessageProactiveRefresh { validators_info };

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
    // check get key before proactive refresh
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

    // eve has private visibility so key does not change
    assert_eq!(key_before_eve, key_after_eve);
    // dave's not private so changes
    assert_ne!(converted_key_share, serialize(&key_after_dave).unwrap());

    let alice = AccountKeyring::Alice;
    ocw_message.validators_info[0].tss_account = alice.encode();
    ocw_message.validators_info[1].tss_account = alice.encode();

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
    initialize_test_logger();
    clean_tests();

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
    let ocw_message = OcwMessageProactiveRefresh { validators_info };
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

#[tokio::test]
async fn test_partition_all_keys() {
    initialize_test_logger();
    let all_keys: Vec<String> = (1..=25).map(|num| num.to_string()).collect();

    let result_normal_10 = partition_all_keys(2u128, all_keys.clone()).await.unwrap();
    assert_eq!(result_normal_10, all_keys[2..12].to_vec());

    let result_next_set = partition_all_keys(12u128, all_keys.clone()).await.unwrap();
    assert_eq!(result_next_set, all_keys[12..22].to_vec());

    let wrap_around_partial = partition_all_keys(23u128, all_keys.clone()).await.unwrap();
    let mut wrap_around_partial_vec = all_keys[23..25].to_vec();
    wrap_around_partial_vec.append(&mut all_keys[0..8].to_vec());
    assert_eq!(wrap_around_partial, wrap_around_partial_vec);

    let result_larger = partition_all_keys(32u128, all_keys.clone()).await.unwrap();
    assert_eq!(result_larger, all_keys[7..17].to_vec());

    let wrap_around_partial_larger = partition_all_keys(42u128, all_keys.clone()).await.unwrap();
    let mut wrap_around_partial_larger_vec = all_keys[17..25].to_vec();
    wrap_around_partial_larger_vec.append(&mut all_keys[0..2].to_vec());
    assert_eq!(wrap_around_partial_larger, wrap_around_partial_larger_vec);
}
