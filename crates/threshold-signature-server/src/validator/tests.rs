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

use entropy_kvdb::clean_tests;
use entropy_shared::{DAVE_VERIFYING_KEY, EVE_VERIFYING_KEY, FERDIE_VERIFYING_KEY, MIN_BALANCE};
use entropy_testing_utils::{
    constants::{ALICE_STASH_ADDRESS, RANDOM_ACCOUNT},
    substrate_context::{
        test_context_stationary, test_node_process_testing_state, testing_context,
    },
};
use serial_test::serial;
use sp_core::{sr25519, Pair};
use subxt::tx::PairSigner;

use super::api::{
    check_balance_for_fees, get_all_keys, get_and_store_values, get_random_server_info,
    sync_validator, tell_chain_syncing_is_done, Keys,
};
use crate::{
    chain_api::{entropy, get_api, get_rpc, EntropyConfig},
    helpers::{
        launch::{
            ValidatorName, DEFAULT_ALICE_MNEMONIC, DEFAULT_BOB_MNEMONIC, DEFAULT_MNEMONIC,
            FORBIDDEN_KEYS,
        },
        substrate::{get_registered_details, get_stash_address, get_subgroup, query_chain},
        tests::{create_clients, initialize_test_logger},
        validator::get_signer_and_x25519_secret_from_mnemonic,
    },
    validation::{mnemonic_to_pair, new_mnemonic, EncryptedSignedMessage, BLOCK_BUFFER},
    validator::errors::ValidatorErr,
};

#[tokio::test]
async fn test_get_all_keys() {
    initialize_test_logger().await;
    clean_tests();

    let cxt = testing_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();

    let mut result = get_all_keys(&api, &rpc).await.unwrap();
    let mut result_2 = get_all_keys(&api, &rpc).await.unwrap();
    let mut result_3 = get_all_keys(&api, &rpc).await.unwrap();
    let mut result_4 = get_all_keys(&api, &rpc).await.unwrap();

    let mut expected_results = vec![
        hex::encode(DAVE_VERIFYING_KEY.to_vec()),
        hex::encode(EVE_VERIFYING_KEY.to_vec()),
        hex::encode(FERDIE_VERIFYING_KEY.to_vec()),
    ];
    result.sort();
    expected_results.sort();
    result_2.sort();
    result_3.sort();
    result_4.sort();

    assert_eq!(result, expected_results);
    assert_eq!(result_2, expected_results);
    assert_eq!(result_3, expected_results);
    assert_eq!(result_4, expected_results);
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_sync_kvdb() {
    initialize_test_logger().await;
    clean_tests();

    let ctx = test_context_stationary().await;
    let rpc = get_rpc(&ctx.node_proc.ws_url).await.unwrap();
    let addrs = vec![
        hex::encode(DAVE_VERIFYING_KEY.to_vec()),
        hex::encode(EVE_VERIFYING_KEY.to_vec()),
        hex::encode(FERDIE_VERIFYING_KEY.to_vec()),
    ];

    let (a_signer, _) = get_signer_and_x25519_secret_from_mnemonic(DEFAULT_ALICE_MNEMONIC).unwrap();

    let (b_signer, bob_x25519_secret) =
        get_signer_and_x25519_secret_from_mnemonic(DEFAULT_BOB_MNEMONIC).unwrap();
    let recip = x25519_dalek::PublicKey::from(&bob_x25519_secret).to_bytes();

    let a_usr_sk = a_signer.signer();
    let b_usr_sk = b_signer.signer();

    let values = vec![vec![10], vec![11], vec![12]];

    let port = 3001;
    let (bob_axum, _) =
        create_clients("bob".to_string(), values, addrs.clone(), &Some(ValidatorName::Bob)).await;

    let listener_bob = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("Unable to bind to given server address.");
    tokio::spawn(async move {
        axum::serve(listener_bob, bob_axum).await.unwrap();
    });

    let client = reqwest::Client::new();
    let mut keys = Keys {
        keys: addrs,
        block_number: rpc.chain_get_header(None).await.unwrap().unwrap().number,
    };
    let enc_keys =
        EncryptedSignedMessage::new(&b_usr_sk, serde_json::to_vec(&keys).unwrap(), &recip, &[])
            .unwrap();
    let formatted_url = format!("http://127.0.0.1:{port}/validator/sync_kvdb");
    let result = client
        .post(formatted_url.clone())
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&enc_keys).unwrap())
        .send()
        .await
        .unwrap();

    // Validates that keys signed/encrypted to the correct key
    // return no error (status code 200).
    assert_eq!(result.status(), 200);

    let (_, alice_x25519_secret) =
        get_signer_and_x25519_secret_from_mnemonic(DEFAULT_ALICE_MNEMONIC).unwrap();
    let sender = x25519_dalek::PublicKey::from(&alice_x25519_secret).to_bytes();

    let enc_keys_failed_decrypt =
        EncryptedSignedMessage::new(&b_usr_sk, serde_json::to_vec(&keys).unwrap(), &sender, &[])
            .unwrap();
    let formatted_url = format!("http://127.0.0.1:{port}/validator/sync_kvdb");
    let result_2 = client
        .post(formatted_url.clone())
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&enc_keys_failed_decrypt).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(result_2.status(), 500);
    assert_eq!(
        result_2.text().await.unwrap(),
        "Encryption or authentication: Hpke: HPKE Error: OpenError"
    );

    let enc_keys =
        EncryptedSignedMessage::new(&a_usr_sk, serde_json::to_vec(&keys).unwrap(), &recip, &[])
            .unwrap();
    let formatted_url = format!("http://127.0.0.1:{port}/validator/sync_kvdb");
    let result_3 = client
        .post(formatted_url.clone())
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&enc_keys).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(result_3.status(), 500);
    assert_eq!(result_3.text().await.unwrap(), "Validator not in subgroup");

    // check random key fails not in subgroup
    let random_usr_sk = mnemonic_to_pair(&new_mnemonic().unwrap()).unwrap();

    let enc_keys = EncryptedSignedMessage::new(
        &random_usr_sk,
        serde_json::to_vec(&keys).unwrap(),
        &recip,
        &[],
    )
    .unwrap();
    let formatted_url = format!("http://127.0.0.1:{port}/validator/sync_kvdb");
    let result_3 = client
        .post(formatted_url.clone())
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&enc_keys).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(result_3.status(), 500);
    // fails on lookup for stash key
    assert_eq!(result_3.text().await.unwrap(), "User Error: Chain Fetch: Stash Fetch Error");

    keys.keys = vec![FORBIDDEN_KEYS[0].to_string()];
    let enc_forbidden =
        EncryptedSignedMessage::new(&b_usr_sk, serde_json::to_vec(&keys).unwrap(), &recip, &[])
            .unwrap();
    let result_4 = client
        .post(formatted_url.clone())
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&enc_forbidden).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(result_4.status(), 500);
    assert_eq!(result_4.text().await.unwrap(), "Forbidden Key");

    keys.block_number = keys.block_number + BLOCK_BUFFER + 10;
    let enc_stale =
        EncryptedSignedMessage::new(&b_usr_sk, serde_json::to_vec(&keys).unwrap(), &recip, &[])
            .unwrap();
    let result_5 = client
        .post(formatted_url.clone())
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&enc_stale).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(result_5.status(), 500);
    assert_eq!(result_5.text().await.unwrap(), "Validation Error: Message is too old");

    let sig: [u8; 64] = [0; 64];
    let user_input_bad = EncryptedSignedMessage::new_with_given_signature(
        &b_usr_sk,
        serde_json::to_vec(&keys.clone()).unwrap(),
        &recip,
        &[],
        sr25519::Signature::from_raw(sig),
    )
    .unwrap();

    let failed_sign = client
        .post(formatted_url.clone())
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&user_input_bad).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(failed_sign.status(), 500);
    assert_eq!(
        failed_sign.text().await.unwrap(),
        "Encryption or authentication: Cannot verify signature"
    );

    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_get_and_store_values() {
    initialize_test_logger().await;
    clean_tests();

    let cxt = test_node_process_testing_state(false).await;
    let api = get_api(&cxt.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.ws_url).await.unwrap();

    let (signer_alice, x25519_alice) =
        get_signer_and_x25519_secret_from_mnemonic(DEFAULT_MNEMONIC).unwrap();

    let mut recip_server_info = {
        let alice_stash_address =
            get_stash_address(&api, &rpc, &signer_alice.account_id()).await.unwrap();
        let server_info_query =
            entropy::storage().staking_extension().threshold_servers(alice_stash_address);
        query_chain(&api, &rpc, server_info_query, None).await.unwrap().unwrap()
    };
    recip_server_info.endpoint = b"127.0.0.1:3002".to_vec();

    let keys = vec![
        hex::encode(DAVE_VERIFYING_KEY.to_vec()),
        hex::encode(EVE_VERIFYING_KEY.to_vec()),
        hex::encode(FERDIE_VERIFYING_KEY.to_vec()),
    ];
    let port_0 = 3002;
    let port_1 = 3003;
    let values = vec![vec![10], vec![11], vec![12]];
    // Construct a client to use for dispatching requests.
    let (alice_axum, _) = create_clients(
        "alice".to_string(),
        values.clone(),
        keys.clone(),
        &Some(ValidatorName::Alice),
    )
    .await;

    let (bob_axum, bob_kv) =
        create_clients("bob".to_string(), vec![], vec![], &Some(ValidatorName::Bob)).await;

    let listener_alice = tokio::net::TcpListener::bind(format!("0.0.0.0:{port_0}"))
        .await
        .expect("Unable to bind to given server address.");
    tokio::spawn(async move {
        axum::serve(listener_alice, alice_axum).await.unwrap();
    });

    let listener_bob = tokio::net::TcpListener::bind(format!("0.0.0.0:{port_1}"))
        .await
        .expect("Unable to bind to given server address.");
    tokio::spawn(async move {
        axum::serve(listener_bob, bob_axum).await.unwrap();
    });

    // We are 'being' bob (using bob's kv), but we authenticate as alice, because otherwise we will
    // fail the subgroup check. We can't properly test this function because we don't have two tss
    // servers in the same subgroup with only two subgroups.
    get_and_store_values(
        keys.clone(),
        &bob_kv,
        9,
        false,
        recip_server_info,
        &signer_alice,
        &x25519_alice,
        &rpc,
    )
    .await
    .unwrap();
    for (i, key) in keys.iter().enumerate() {
        tracing::info!("!! -> -> RECEIVED KEY at IDX {i} of value {key:?}");
        let val = bob_kv.kv().get(key).await;
        assert!(val.is_ok());
        assert_eq!(val.unwrap(), values[i]);
    }
    clean_tests();
}

#[tokio::test]
async fn test_get_random_server_info() {
    initialize_test_logger().await;
    clean_tests();

    let cxt = testing_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();

    let (signer_alice, _) = get_signer_and_x25519_secret_from_mnemonic(DEFAULT_MNEMONIC).unwrap();
    let my_subgroup = get_subgroup(&api, &rpc, &signer_alice.account_id()).await.unwrap();
    let validator_address =
        get_stash_address(&api, &rpc, &signer_alice.account_id()).await.unwrap();

    let result = get_random_server_info(&api, &rpc, my_subgroup, signer_alice.account_id().clone())
        .await
        .unwrap();
    assert_eq!("127.0.0.1:3001".as_bytes().to_vec(), result.endpoint);
    // Returns error here because no other validators in subgroup
    let error =
        get_random_server_info(&api, &rpc, my_subgroup, validator_address).await.unwrap_err();
    assert_eq!(error.to_string(), ValidatorErr::SubgroupError("Index out of bounds").to_string());

    clean_tests();
}

#[tokio::test]
#[should_panic = "Account does not exist, add balance"]
async fn test_check_balance_for_fees() {
    initialize_test_logger().await;
    clean_tests();

    let cxt = testing_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();

    let result =
        check_balance_for_fees(&api, &rpc, &ALICE_STASH_ADDRESS, MIN_BALANCE).await.unwrap();

    assert!(result);

    let result_2 =
        check_balance_for_fees(&api, &rpc, &ALICE_STASH_ADDRESS, 10000000000000000000000u128)
            .await
            .unwrap();
    assert!(!result_2);

    let _ = check_balance_for_fees(&api, &rpc, &RANDOM_ACCOUNT, MIN_BALANCE).await.unwrap();
    clean_tests();
}

#[tokio::test]
async fn test_tell_chain_syncing_is_done() {
    initialize_test_logger().await;
    clean_tests();

    let cxt = testing_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();
    let p_alice = <sr25519::Pair as Pair>::from_string("//Alice", None).unwrap();
    let signer_alice = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_alice);

    // expect this to fail in the proper way
    let result = tell_chain_syncing_is_done(&api, &rpc, &signer_alice).await;
    assert!(result.is_err());
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_sync_validator() {
    initialize_test_logger().await;
    clean_tests();

    let ctx = test_node_process_testing_state(true).await;
    let api = get_api(&ctx.ws_url).await.unwrap();
    let rpc = get_rpc(&ctx.ws_url).await.unwrap();
    let values = vec![vec![10], vec![11], vec![12]];
    let keys = vec![
        hex::encode(DAVE_VERIFYING_KEY.to_vec()),
        hex::encode(EVE_VERIFYING_KEY.to_vec()),
        hex::encode(FERDIE_VERIFYING_KEY.to_vec()),
    ];

    // sanity check to make sure keys are right size and can get info from chain
    assert_eq!(
        get_registered_details(&api, &rpc, hex::decode(keys[0].clone()).unwrap()).await.is_ok(),
        true
    );
    let (alice_axum, _) = create_clients(
        "alice".to_string(),
        values.clone(),
        keys.clone(),
        &Some(ValidatorName::Alice),
    )
    .await;

    let listener_alice = tokio::net::TcpListener::bind(format!("0.0.0.0:3001"))
        .await
        .expect("Unable to bind to given server address.");
    tokio::spawn(async move {
        axum::serve(listener_alice, alice_axum).await.unwrap();
    });

    // adds only 1 key and 1 value to see if others get filled and no error from already having values (also gets overwritten)
    let (charlie_axum, charlie_kv) = create_clients(
        "charlie".to_string(),
        vec![values[1].clone()],
        vec![keys[0].clone()],
        &Some(ValidatorName::Charlie),
    )
    .await;

    let listener_charlie = tokio::net::TcpListener::bind(format!("0.0.0.0:3002"))
        .await
        .expect("Unable to bind to given server address.");
    tokio::spawn(async move {
        axum::serve(listener_charlie, charlie_axum).await.unwrap();
    });

    sync_validator(false, "ws://127.0.0.1:9944", &charlie_kv).await;

    for (i, key) in keys.iter().enumerate() {
        let val = charlie_kv.kv().get(key).await;
        assert!(val.is_ok());
        assert_eq!(val.unwrap(), values[i]);
    }
    // check if validator is synced
    let p_charlie = <sr25519::Pair as Pair>::from_string("//Charlie//stash", None).unwrap();
    let signer_charlie = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_charlie);
    let synced_query =
        entropy::storage().staking_extension().is_validator_synced(signer_charlie.account_id());
    let is_synced = query_chain(&api, &rpc, synced_query, None).await.unwrap().unwrap();
    assert!(is_synced);

    clean_tests();
}
