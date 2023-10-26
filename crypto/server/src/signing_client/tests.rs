use axum::http::StatusCode;
use futures::future::join_all;
use kvdb::clean_tests;
use parity_scale_codec::Encode;
use serial_test::serial;
use sp_core::crypto::Ss58Codec;
use sp_keyring::AccountKeyring;
use testing_utils::{
    constants::{TSS_ACCOUNTS, X25519_PUBLIC_KEYS},
    substrate_context::{test_context_stationary, test_node_process_testing_state},
};

use super::{api::validate_proactive_refresh, ProtocolErr};
use crate::{
    chain_api::{get_api, get_rpc},
    helpers::tests::spawn_testing_validators,
    r#unsafe::api::UnsafeQuery,
};

#[tokio::test]
#[serial]
async fn test_proactive_refresh() {
    clean_tests();
    let one = AccountKeyring::Eve;
    let _cxt = test_node_process_testing_state().await;

    let signing_address = one.clone().to_account_id().to_ss58check();
    let (validator_ips, _validator_ids, _users_keyshare_option) =
        spawn_testing_validators(Some(signing_address.clone()), true).await;

    let client = reqwest::Client::new();
    let get_query = UnsafeQuery::new(one.to_account_id().to_string(), "".to_string()).to_json();

    // check get key before proactive refresh
    let response = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query.clone())
        .send()
        .await
        .unwrap();

    let value = response.text().await.unwrap();

    let mut validators_info = vec![
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

    let submit_transaction_requests =
        |validator_urls: Vec<String>, validators_info: Vec<entropy_shared::ValidatorInfo>| async move {
            let mock_client = reqwest::Client::new();
            join_all(
                validator_urls
                    .iter()
                    .map(|ip| async {
                        let url = format!("http://{}/signer/proactive_refresh", ip.clone());
                        mock_client
                            .post(url)
                            .header("Content-Type", "application/json")
                            .body(validators_info.clone().encode())
                            .send()
                            .await
                    })
                    .collect::<Vec<_>>(),
            )
            .await
        };
    let test_user_res =
        submit_transaction_requests(validator_ips.clone(), validators_info.clone()).await;

    for res in test_user_res {
        assert_eq!(res.unwrap().status(), StatusCode::OK);
    }
    // check get key before proactive refresh
    let response_3 = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query.clone())
        .send()
        .await
        .unwrap();

    let value_after = response_3.text().await.unwrap();

    assert_ne!(value, value_after);
    let alice = AccountKeyring::Alice;

    validators_info[0].tss_account = alice.encode();
    validators_info[1].tss_account = alice.encode();

    let test_user_res_not_in_group =
        submit_transaction_requests(validator_ips.clone(), validators_info.clone()).await;
    for res in test_user_res_not_in_group {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "User Error: Invalid Signer: Invalid Signer in Signing group"
        );
    }
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_proactive_refresh_validation_fail() {
    clean_tests();
    let cxt = test_context_stationary().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();
    let err = validate_proactive_refresh(&api, &rpc).await;
    assert!(matches!(err, Err(ProtocolErr::NoProactiveRefresh)));
    clean_tests();
}
