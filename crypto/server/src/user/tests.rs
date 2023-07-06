use std::{env, fs, net::SocketAddrV4, path::PathBuf, str::FromStr, sync::Arc};

use axum::http::StatusCode;
use bip39::{Language, Mnemonic, MnemonicType};
use entropy_constraints::{Architecture, Evm, Parse};
use entropy_shared::{Acl, Constraints};
use ethers_core::types::{Address, TransactionRequest};
use futures::{future::join_all, join, Future};
use hex_literal::hex as h;
use kvdb::{clean_tests, encrypted_sled::PasswordMethod, kv_manager::value::KvManager};
use parity_scale_codec::Encode;
use serial_test::serial;
use sp_core::{crypto::Ss58Codec, sr25519, Bytes, Pair, H160};
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{ext::sp_runtime::AccountId32, tx::PairSigner, OnlineClient};
use testing_utils::{
    constants::{TSS_ACCOUNTS, X25519_PUBLIC_KEYS},
    substrate_context::{
        test_context_stationary, test_node_process_testing_state, SubstrateTestingContext,
    },
};
use tokio::task::JoinHandle;
use x25519_dalek::{PublicKey, StaticSecret};

use super::UserInputPartyInfo;
use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    drain, get_signature, get_signer,
    helpers::{
        launch::{
            setup_mnemonic, Configuration, DEFAULT_BOB_MNEMONIC, DEFAULT_ENDPOINT, DEFAULT_MNEMONIC,
        },
        signing::{create_unique_tx_id, SignatureState},
        substrate::make_register,
        tests::{
            check_if_confirmation, create_clients, make_swapping, register_user, setup_client,
            spawn_testing_validators,
        },
    },
    load_kv_store, new_user,
    r#unsafe::api::UnsafeQuery,
    signing_client::SignerState,
    subscribe_to_me,
    user::api::{UserTransactionRequest, ValidatorInfo},
    validation::{derive_static_secret, mnemonic_to_pair, new_mnemonic, SignedMessage},
    validator::api::get_random_server_info,
    Message as SigMessage,
};

#[tokio::test]
#[serial]
async fn test_get_signer_does_not_throw_err() {
    clean_tests();
    let kv_store = load_kv_store(false, false, false).await;
    let mnemonic = setup_mnemonic(&kv_store, false, false).await;
    assert!(mnemonic.is_ok());
    get_signer(&kv_store).await.unwrap();
    clean_tests();
}
#[tokio::test]
#[serial]
async fn test_sign_tx_no_chain() {
    clean_tests();
    let one = AccountKeyring::One;
    let test_user_constraint = AccountKeyring::Charlie;
    let two = AccountKeyring::Two;

    let (validator_ips, _validator_ids) = spawn_testing_validators().await;
    let substrate_context = test_context_stationary().await;
    let entropy_api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let initial_constraints = |address: [u8; 20]| -> Constraints {
        let mut evm_acl = Acl::<[u8; 20]>::default();
        evm_acl.addresses.push(address);

        Constraints { evm_acl: Some(evm_acl), ..Default::default() }
    };

    register_user(
        &entropy_api,
        &validator_ips,
        &one,
        &test_user_constraint,
        initial_constraints([1u8; 20]),
    )
    .await;
    let transaction_request = TransactionRequest::new().to(Address::from([1u8; 20])).value(1);
    let transaction_request_fail = TransactionRequest::new().to(Address::from([3u8; 20])).value(10);

    let sig_hash = transaction_request.sighash();
    let validators_info = vec![
        ValidatorInfo {
            ip_address: SocketAddrV4::from_str("127.0.0.1:3001").unwrap(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            tss_account: TSS_ACCOUNTS[0].clone(),
        },
        ValidatorInfo {
            ip_address: SocketAddrV4::from_str("127.0.0.1:3002").unwrap(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[1].clone(),
        },
    ];
    let converted_transaction_request: String =
        hex::encode(&transaction_request.rlp_unsigned().to_vec());

    let mut generic_msg = UserTransactionRequest {
        arch: "evm".to_string(),
        transaction_request: converted_transaction_request.clone(),
        validators_info,
    };

    let submit_transaction_requests =
        |validator_urls_and_keys: Vec<(String, [u8; 32])>,
         generic_msg: UserTransactionRequest,
         keyring: Sr25519Keyring| async move {
            let mock_client = reqwest::Client::new();
            join_all(
                validator_urls_and_keys
                    .iter()
                    .map(|validator_tuple| async {
                        let server_public_key = PublicKey::from(validator_tuple.1);
                        let signed_message = SignedMessage::new(
                            &keyring.pair(),
                            &Bytes(serde_json::to_vec(&generic_msg.clone()).unwrap()),
                            &server_public_key,
                        )
                        .unwrap();
                        let url = format!("http://{}/user/sign_tx", validator_tuple.0.clone());
                        mock_client
                            .post(url)
                            .header("Content-Type", "application/json")
                            .body(serde_json::to_string(&signed_message).unwrap())
                            .send()
                            .await
                    })
                    .collect::<Vec<_>>(),
            )
            .await
        };
    let validator_ips_and_keys = vec![
        (validator_ips[0].clone(), X25519_PUBLIC_KEYS[0]),
        (validator_ips[1].clone(), X25519_PUBLIC_KEYS[1]),
    ];

    let test_user_res =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    for res in test_user_res {
        let mut res = res.unwrap();
        assert_eq!(res.status(), 200);
        let chunk = res.chunk().await.unwrap().unwrap();
        let signing_result: Result<String, String> = serde_json::from_slice(&chunk).unwrap();
        assert!(matches!(signing_result, Ok(sig) if sig.len() == 88));
    }

    // test failing cases
    let test_user_res_not_registered =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), two).await;

    for res in test_user_res_not_registered {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "Not Registering error: Register Onchain first"
        );
    }

    generic_msg.validators_info[0].x25519_public_key = [0; 32];

    let test_user_failed_x25519_pub_key =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    for res in test_user_failed_x25519_pub_key {
        let mut res = res.unwrap();
        assert_eq!(res.status(), 200);
        let chunk = res.chunk().await.unwrap().unwrap();
        let signing_result: Result<String, String> = serde_json::from_slice(&chunk).unwrap();
        assert_eq!(
            Err("reqwest event error: Invalid status code: 500 Internal Server Error".to_string()),
            signing_result
        );
    }

    generic_msg.transaction_request = hex::encode(&transaction_request_fail.rlp().to_vec());

    let test_user_failed_constraints_res =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    for res in test_user_failed_constraints_res {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "Constraints error: Constraint Evaluation error: Transaction not allowed."
        );
    }

    generic_msg.arch = "btc".to_string();
    let test_user_failed_arch_res =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    for res in test_user_failed_arch_res {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "Parse error: Unknown \"arch\". Must be one of: [\"evm\"]"
        );
    }
    let sig_request = SigMessage { message: hex::encode(sig_hash.clone()) };
    let mock_client = reqwest::Client::new();

    join_all(validator_ips.iter().map(|validator_ip| async {
        let url = format!("http://{}/signer/signature", validator_ip.clone());
        let res = mock_client
            .post(url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&sig_request).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 202);
        assert_eq!(res.content_length().unwrap(), 88);
    }))
    .await;
    // fails verification tests
    // wrong key for wrong validator
    let server_public_key = PublicKey::from(X25519_PUBLIC_KEYS[1]);
    let failed_signed_message = SignedMessage::new(
        &one.pair(),
        &Bytes(serde_json::to_vec(&generic_msg.clone()).unwrap()),
        &server_public_key,
    )
    .unwrap();
    let failed_res = mock_client
        .post("http://127.0.0.1:3001/user/sign_tx")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&failed_signed_message).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(failed_res.status(), 500);
    assert_eq!(
        failed_res.text().await.unwrap(),
        "Validation error: ChaCha20 decryption error: aead::Error"
    );

    let sig: [u8; 64] = [0; 64];
    let slice: [u8; 32] = [0; 32];
    let nonce: [u8; 12] = [0; 12];

    let user_input_bad = SignedMessage::new_test(
        Bytes(serde_json::to_vec(&generic_msg.clone()).unwrap()),
        sr25519::Signature::from_raw(sig),
        slice,
        slice,
        slice,
        nonce,
    );

    let failed_sign = mock_client
        .post("http://127.0.0.1:3001/user/sign_tx")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&user_input_bad).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(failed_sign.status(), 500);
    assert_eq!(failed_sign.text().await.unwrap(), "Invalid Signature: Invalid signature.");
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_fail_signing_group() {
    clean_tests();
    let dave = AccountKeyring::Dave;
    let _ = spawn_testing_validators().await;

    let _substrate_context = test_node_process_testing_state().await;
    let transaction_request = TransactionRequest::new().to(Address::from([1u8; 20])).value(3);
    let validators_info = vec![
        ValidatorInfo {
            ip_address: SocketAddrV4::from_str("127.0.0.1:3001").unwrap(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            tss_account: TSS_ACCOUNTS[0].clone(),
        },
        ValidatorInfo {
            ip_address: SocketAddrV4::from_str("127.0.0.1:3002").unwrap(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[1].clone(),
        },
    ];

    let generic_msg = UserTransactionRequest {
        arch: "evm".to_string(),
        transaction_request: hex::encode(&transaction_request.rlp()),
        validators_info,
    };
    let server_public_key = PublicKey::from(X25519_PUBLIC_KEYS[0]);
    let signed_message = SignedMessage::new(
        &dave.pair(),
        &Bytes(serde_json::to_vec(&generic_msg.clone()).unwrap()),
        &server_public_key,
    )
    .unwrap();

    let mock_client = reqwest::Client::new();
    let response = mock_client
        .post("http://127.0.0.1:3001/user/sign_tx")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&signed_message).unwrap())
        .send()
        .await;
    assert_eq!(
        response.unwrap().text().await.unwrap(),
        "Invalid Signer: Invalid Signer in Signing group"
    );
    clean_tests();
}

// TODO negative validation tests on user/tx

#[tokio::test]
#[serial]
async fn test_store_share() {
    clean_tests();
    let alice = AccountKeyring::Alice;
    let alice_constraint = AccountKeyring::Charlie;

    let value: Vec<u8> = vec![0];

    let cxt = test_context_stationary().await;
    setup_client().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();

    let server_public_key = PublicKey::from(X25519_PUBLIC_KEYS[0]);
    let user_input = SignedMessage::new(&alice.pair(), &Bytes(value.clone()), &server_public_key)
        .unwrap()
        .to_json();
    let client = reqwest::Client::new();

    // fails to add not registering or swapping
    let response = client
        .post("http://127.0.0.1:3001/user/new")
        .header("Content-Type", "application/json")
        .body(user_input.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.text().await.unwrap(), "Not Registering error: Register Onchain first");

    // signal registering
    make_register(&api, &alice, &alice_constraint.to_account_id()).await;

    let response_2 = client
        .post("http://127.0.0.1:3001/user/new")
        .header("Content-Type", "application/json")
        .body(user_input.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response_2.status(), StatusCode::OK);
    assert_eq!(response_2.text().await.unwrap(), "");
    // make sure there is now one confirmation
    check_if_confirmation(&api, &alice).await;

    // fails to add already added share
    let response_3 = client
        .post("http://127.0.0.1:3001/user/new")
        .header("Content-Type", "application/json")
        .body(user_input.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response_3.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_3.text().await.unwrap(), "Kv error: Recv Error: channel closed");

    // fails with wrong node key
    let server_public_key_bob = PublicKey::from(X25519_PUBLIC_KEYS[1]);
    let user_input_bob =
        SignedMessage::new(&alice.pair(), &Bytes(value.clone()), &server_public_key_bob)
            .unwrap()
            .to_json();

    let response_4 = client
        .post("http://127.0.0.1:3001/user/new")
        .header("Content-Type", "application/json")
        .body(user_input_bob.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response_4.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let expected_err = "Validation error: ChaCha20 decryption error: aead::Error";
    assert_eq!(response_4.text().await.unwrap(), expected_err);
    let sig: [u8; 64] = [0; 64];
    let slice: [u8; 32] = [0; 32];
    let nonce: [u8; 12] = [0; 12];
    let user_input_bad = SignedMessage::new_test(
        Bytes(value),
        sr25519::Signature::from_raw(sig),
        slice,
        slice,
        slice,
        nonce,
    )
    .to_json();

    let response_5 = client
        .post("http://127.0.0.1:3001/user/new")
        .header("Content-Type", "application/json")
        .body(user_input_bad.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response_5.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_5.text().await.unwrap(), "Invalid Signature: Invalid signature.");
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_update_keys() {
    clean_tests();
    let dave = AccountKeyring::Dave;

    let key: AccountId32 = dave.to_account_id();
    let value: Vec<u8> = vec![0];
    let new_value: Vec<u8> = vec![1];
    let cxt = test_context_stationary().await;
    setup_client().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();

    let server_public_key = PublicKey::from(X25519_PUBLIC_KEYS[0]);
    let user_input =
        SignedMessage::new(&dave.pair(), &Bytes(new_value.clone()), &server_public_key)
            .unwrap()
            .to_json();

    let put_query =
        UnsafeQuery::new(key.to_string(), serde_json::to_string(&value).unwrap()).to_json();
    let client = reqwest::Client::new();
    // manually add dave's key to replace it
    let response = client
        .post("http://127.0.0.1:3001/unsafe/put")
        .header("Content-Type", "application/json")
        .body(put_query.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // fails to add not registering or swapping
    let response_2 = client
        .post("http://127.0.0.1:3001/user/new")
        .header("Content-Type", "application/json")
        .body(user_input.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response_2.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response_2.text().await.unwrap(),
        "Not Registering error: Register Onchain first" /* "Generic Substrate error:
                                                         * Metadata: Pallet Relayer Storage
                                                         * Relayer has incompatible
                                                         * metadata" */
    );

    // signal registering
    make_swapping(&api, &dave).await;

    let response_3 = client
        .post("http://127.0.0.1:3001/user/new")
        .header("Content-Type", "application/json")
        .body(user_input.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response_3.status(), StatusCode::OK);
    assert_eq!(response_3.text().await.unwrap(), "");
    // make sure there is now one confirmation
    check_if_confirmation(&api, &dave).await;

    // check dave has new key
    let response_4 = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(put_query.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(
        response_4.text().await.unwrap(),
        std::str::from_utf8(&new_value).unwrap().to_string()
    );
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_store_share_fail_wrong_data() {
    clean_tests();
    // Construct a client to use for dispatching requests.
    setup_client().await;
    let client = reqwest::Client::new();
    let response = client
        .post("http://127.0.0.1:3001/user/new")
        .header("Content-Type", "application/json")
        .body(
            r##"{
		"name": "John Doe",
		"email": "j.doe@m.com",
		"password": "123456"
	}"##,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    clean_tests();
}
