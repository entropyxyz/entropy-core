use axum::http::StatusCode;
use kvdb::clean_tests;
use parity_scale_codec::Encode;
use serial_test::serial;
use sp_core::crypto::Ss58Codec;
use sp_keyring::{AccountKeyring};
use futures::{
    future::{join_all},
};
use testing_utils::{
    constants::{
        TSS_ACCOUNTS, X25519_PUBLIC_KEYS,
    },
    substrate_context::{
        test_context_stationary, test_node_process_testing_state, SubstrateTestingContext,
    },
};

use crate::{helpers::tests::spawn_testing_validators, r#unsafe::api::UnsafeQuery};

#[tokio::test]
#[serial]
async fn test_proactive_refresh() {
    clean_tests();
    let one = AccountKeyring::Eve;
    let _cxt = test_context_stationary().await;

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

let submit_transaction_requests =
    |validator_urls: Vec<String>,
     validators_info: Vec<entropy_shared::ValidatorInfo>| async move {
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
    dbg!(value.clone());
    dbg!(value_after.clone());

    assert_ne!(value, value_after);
    clean_tests();
}
