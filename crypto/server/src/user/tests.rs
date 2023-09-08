use std::{env, fs, net::SocketAddrV4, path::PathBuf, str::FromStr, sync::Arc, time::Duration};

use axum::http::StatusCode;
use bip39::{Language, Mnemonic, MnemonicType};
use entropy_constraints::{Architecture, Evm, Parse};
use entropy_shared::{Acl, KeyVisibility, OcwMessage};
use ethers_core::types::{Address, TransactionRequest};
use futures::{
    future::{self, join_all},
    join, Future, SinkExt, StreamExt,
};
use hex_literal::hex;
use kvdb::{
    clean_tests,
    encrypted_sled::PasswordMethod,
    kv_manager::{value::KvManager, PartyId},
};
use more_asserts as ma;
use parity_scale_codec::Encode;
use serial_test::serial;
use sp_core::{crypto::Ss58Codec, Pair as OtherPair, H160};
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{
    ext::{
        sp_core::{sr25519, Bytes, Pair},
        sp_runtime::AccountId32,
    },
    tx::PairSigner,
    utils::{AccountId32 as subxtAccountId32, Static},
    OnlineClient,
};
use testing_utils::{
    constants::{ALICE_STASH_ADDRESS, TSS_ACCOUNTS, X25519_PUBLIC_KEYS},
    substrate_context::{
        test_context_stationary, test_node_process_testing_state, SubstrateTestingContext,
    },
};
use tokio::task::JoinHandle;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use x25519_dalek::{PublicKey, StaticSecret};

use super::UserInputPartyInfo;
use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    drain, get_signature, get_signer,
    helpers::{
        launch::{
            setup_mnemonic, Configuration, DEFAULT_BOB_MNEMONIC, DEFAULT_CHARLIE_MNEMONIC,
            DEFAULT_ENDPOINT, DEFAULT_MNEMONIC,
        },
        signing::{create_unique_tx_id, SignatureState},
        substrate::{get_subgroup, make_register, return_all_addresses_of_subgroup},
        tests::{
            check_if_confirmation, create_clients, setup_client, spawn_testing_validators,
            update_constraints, user_connects_to_validators,
        },
        user::send_key,
    },
    load_kv_store, new_user,
    r#unsafe::api::UnsafeQuery,
    signing_client::{
        protocol_transport::{noise::noise_handshake_initiator, WsConnection},
        ListenerState, SubscribeMessage,
    },
    user::{
        api::{recover_key, UserRegistrationInfo, UserTransactionRequest, ValidatorInfo},
        tests::entropy::runtime_types::entropy_shared::constraints::Constraints,
    },
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
    let one = AccountKeyring::Dave;
    let two = AccountKeyring::Two;

    let signing_address = one.clone().to_account_id().to_ss58check();
    let (validator_ips, _validator_ids, _) =
        spawn_testing_validators(Some(signing_address.clone()), false).await;
    let substrate_context = test_context_stationary().await;
    let entropy_api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let initial_constraints = |address: [u8; 20]| -> Constraints {
        let mut evm_acl = Acl::<[u8; 20]>::default();
        evm_acl.addresses.push(address);

        Constraints { evm_acl: Some(Static(evm_acl)), btc_acl: None }
    };

    update_constraints(&entropy_api, &one.pair(), &one.pair(), initial_constraints([1u8; 20]))
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
    let converted_transaction_request: String = hex::encode(&transaction_request.rlp_unsigned());

    let signing_address = one.to_account_id().to_ss58check();
    let sig_uid = create_unique_tx_id(&signing_address, &hex::encode(sig_hash));

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

    let mut generic_msg_bad_validators = generic_msg.clone();
    generic_msg_bad_validators.validators_info[0].x25519_public_key = [0; 32];

    let test_user_failed_x25519_pub_key = submit_transaction_requests(
        validator_ips_and_keys.clone(),
        generic_msg_bad_validators,
        one,
    )
    .await;

    let mut responses = test_user_failed_x25519_pub_key.into_iter();
    assert_eq!(
        responses.next().unwrap().unwrap().text().await.unwrap(),
        "{\"Err\":\"Subscribe message rejected: Decryption(\\\"Public key does not match that \
         given in UserTransactionRequest\\\")\"}"
    );

    assert_eq!(
        responses.next().unwrap().unwrap().text().await.unwrap(),
        "{\"Err\":\"Oneshot timeout error: channel closed\"}"
    );

    // Test attempting to connect over ws by someone who is not in the signing group
    let validator_ip_and_key = validator_ips_and_keys[0].clone();
    let connection_attempt_handle = tokio::spawn(async move {
        // Wait for the "user" to submit the signing request
        tokio::time::sleep(Duration::from_millis(500)).await;
        let ws_endpoint = format!("ws://{}/ws", validator_ip_and_key.0);
        let (ws_stream, _response) = connect_async(ws_endpoint).await.unwrap();

        // create a SubscribeMessage from a party who is not in the signing commitee
        let subscribe_message_vec =
            serde_json::to_vec(&SubscribeMessage::new(&sig_uid, &AccountKeyring::Ferdie.pair()))
                .unwrap();

        // Attempt a noise handshake including the subscribe message in the payload
        let mut encrypted_connection = noise_handshake_initiator(
            ws_stream,
            &AccountKeyring::Ferdie.pair(),
            validator_ip_and_key.1,
            subscribe_message_vec,
        )
        .await
        .unwrap();

        // Check the response as to whether they accepted our SubscribeMessage
        let response_message = encrypted_connection.recv().await.unwrap();
        let subscribe_response: Result<(), String> =
            serde_json::from_str(&response_message).unwrap();

        assert_eq!(
            Err("Decryption(\"Public key does not match that given in UserTransactionRequest\")"
                .to_string()),
            subscribe_response
        );
        // The stream should not continue to send messages
        // returns true if this part of the test passes
        encrypted_connection.recv().await.is_err()
    });

    let test_user_bad_connection_res = submit_transaction_requests(
        vec![validator_ips_and_keys[1].clone()],
        generic_msg.clone(),
        one,
    )
    .await;

    for res in test_user_bad_connection_res {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "{\"Err\":\"Timed out waiting for remote party\"}"
        );
    }

    assert!(connection_attempt_handle.await.unwrap());

    // Bad Account ID - an account ID is given which is not in the signing group
    let mut generic_msg_bad_account_id = generic_msg.clone();
    generic_msg_bad_account_id.validators_info[0].tss_account =
        AccountKeyring::Dave.to_account_id();

    let test_user_failed_tss_account = submit_transaction_requests(
        validator_ips_and_keys.clone(),
        generic_msg_bad_account_id,
        one,
    )
    .await;

    for res in test_user_failed_tss_account {
        let res = res.unwrap();
        assert_eq!(res.status(), 500);
        assert_eq!(res.text().await.unwrap(), "Invalid Signer: Invalid Signer in Signing group");
    }

    // Test a transcation which does not pass constaints
    generic_msg.transaction_request = hex::encode(&transaction_request_fail.rlp());

    let test_user_failed_constraints_res =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    for res in test_user_failed_constraints_res {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "Constraints error: Constraint Evaluation error: Transaction not allowed."
        );
    }

    // Test unsupported transaction type
    generic_msg.arch = "btc".to_string();
    let test_user_failed_arch_res =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    for res in test_user_failed_arch_res {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "Parse error: Unknown \"arch\". Must be one of: [\"evm\"]"
        );
    }

    let sig_request = SigMessage { message: hex::encode(sig_hash) };
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
        AccountKeyring::Eve.pair().public().into(),
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

    // checks that sig not needed with public key visibility
    let user_input_bad = SignedMessage::new_test(
        Bytes(serde_json::to_vec(&generic_msg.clone()).unwrap()),
        sr25519::Signature::from_raw(sig),
        AccountKeyring::Dave.pair().public().into(),
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
    // fails lower down in stack because no sig needed on pub account
    // fails when tries to decode the nonsense message
    assert_ne!(failed_sign.text().await.unwrap(), "Invalid Signature: Invalid signature.");
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_fail_signing_group() {
    clean_tests();
    let dave = AccountKeyring::Dave;
    let _ = spawn_testing_validators(None, false).await;

    let _substrate_context = test_node_process_testing_state().await;
    let transaction_request = TransactionRequest::new().to(Address::from([1u8; 20])).value(4);
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

    let cxt = test_context_stationary().await;
    let (_validator_ips, _validator_ids, _) = spawn_testing_validators(None, false).await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();

    let mut block_number = api.rpc().block(None).await.unwrap().unwrap().block.header.number + 1;
    let validators_info = vec![
        entropy_shared::ValidatorInfo {
            ip_address: b"127.0.0.1:3001".to_vec(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            tss_account: TSS_ACCOUNTS[0].clone().encode(),
        },
        entropy_shared::ValidatorInfo {
            ip_address: b"127.0.0.1:3002".to_vec(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[1].clone().encode(),
        },
    ];
    let mut onchain_user_request =
        OcwMessage { sig_request_accounts: vec![alice.encode()], block_number, validators_info };
    let client = reqwest::Client::new();

    put_register_request_on_chain(&api, &alice, alice_constraint.to_account_id().into()).await;

    run_to_block(&api, block_number + 1).await;

    // succeeds
    let response = client
        .post("http://127.0.0.1:3002/user/new")
        .body(onchain_user_request.clone().encode())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "");

    let get_query = UnsafeQuery::new(alice.to_account_id().to_string(), "".to_string()).to_json();

    // check alice has new key
    let response_2 = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query.clone())
        .send()
        .await
        .unwrap();

    ma::assert_gt!(response_2.text().await.unwrap().len(), 1000);

    // fails repeated data
    let response_3 = client
        .post("http://127.0.0.1:3001/user/new")
        .body(onchain_user_request.clone().encode())
        .send()
        .await
        .unwrap();

    assert_eq!(response_3.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_3.text().await.unwrap(), "Data is repeated");

    run_to_block(&api, block_number + 3).await;
    onchain_user_request.block_number = block_number + 1;
    // fails stale data
    let response_4 = client
        .post("http://127.0.0.1:3001/user/new")
        .body(onchain_user_request.clone().encode())
        .send()
        .await
        .unwrap();

    assert_eq!(response_4.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_4.text().await.unwrap(), "Data is stale");

    block_number = api.rpc().block(None).await.unwrap().unwrap().block.header.number + 1;
    put_register_request_on_chain(&api, &alice_constraint, alice_constraint.to_account_id().into())
        .await;
    onchain_user_request.block_number = block_number;
    run_to_block(&api, block_number + 1).await;

    // fails not verified data
    let response_5 = client
        .post("http://127.0.0.1:3001/user/new")
        .body(onchain_user_request.clone().encode())
        .send()
        .await
        .unwrap();

    assert_eq!(response_5.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_5.text().await.unwrap(), "Data is not verifiable");

    onchain_user_request.validators_info[0].tss_account = TSS_ACCOUNTS[1].clone().encode();
    // fails not in validator group data
    let response_6 = client
        .post("http://127.0.0.1:3001/user/new")
        .body(onchain_user_request.clone().encode())
        .send()
        .await
        .unwrap();

    assert_eq!(response_6.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_6.text().await.unwrap(), "Invalid Signer: Invalid Signer in Signing group");

    check_if_confirmation(&api, &alice.pair()).await;
    // TODO check if key is in other subgroup member
    clean_tests();
}

#[tokio::test]
async fn test_return_addresses_of_subgroup() {
    let cxt = test_context_stationary().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let result = return_all_addresses_of_subgroup(&api, 0u8).await.unwrap();
    assert_eq!(result.len(), 1);
}

#[tokio::test]
#[serial]
async fn test_send_and_receive_keys() {
    clean_tests();
    let alice = AccountKeyring::Alice;

    let cxt = test_context_stationary().await;
    setup_client().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();

    let user_registration_info =
        UserRegistrationInfo { key: alice.to_account_id().to_string(), value: vec![10] };

    let p_alice = <sr25519::Pair as Pair>::from_string(DEFAULT_MNEMONIC, None).unwrap();
    let signer_alice = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_alice);
    let client = reqwest::Client::new();
    // sends key to alice validator, while filtering out own key
    let _ = send_key(
        &api,
        &alice.to_account_id().into(),
        &mut vec![ALICE_STASH_ADDRESS.clone(), alice.to_account_id().into()],
        user_registration_info.clone(),
        &signer_alice,
    )
    .await
    .unwrap();

    let get_query = UnsafeQuery::new(user_registration_info.key.clone(), "".to_string()).to_json();

    // check alice has new key
    let response_2 = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(
        response_2.text().await.unwrap(),
        std::str::from_utf8(&user_registration_info.value.clone()).unwrap().to_string()
    );
    let server_public_key = PublicKey::from(X25519_PUBLIC_KEYS[0]);

    let signed_message = SignedMessage::new(
        &signer_alice.signer(),
        &Bytes(serde_json::to_vec(&user_registration_info.clone()).unwrap()),
        &PublicKey::from(server_public_key),
    )
    .unwrap()
    .to_json();

    // fails key already stored
    let response_3 = client
        .post("http://127.0.0.1:3001/user/receive_key")
        .header("Content-Type", "application/json")
        .body(signed_message.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response_3.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_3.text().await.unwrap(), "User already registered");

    // TODO negative validation tests

    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_recover_key() {
    clean_tests();
    let cxt = test_node_process_testing_state().await;
    setup_client().await;
    let (_, bob_kv) = create_clients("validator2".to_string(), vec![], vec![], false, true).await;

    let api = get_api(&cxt.ws_url).await.unwrap();
    let unsafe_query = UnsafeQuery::new("key".to_string(), "value".to_string());
    let client = reqwest::Client::new();

    let _ = client
        .post("http://127.0.0.1:3001/unsafe/put")
        .header("Content-Type", "application/json")
        .body(unsafe_query.clone().to_json())
        .send()
        .await
        .unwrap();
    let p_alice = <sr25519::Pair as Pair>::from_string(DEFAULT_CHARLIE_MNEMONIC, None).unwrap();
    let signer_alice = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_alice);
    let _ = recover_key(&api, &bob_kv, &signer_alice, unsafe_query.key.clone()).await.unwrap();

    let value = bob_kv.kv().get(&unsafe_query.key).await.unwrap();
    assert_eq!(value, unsafe_query.value.into_bytes());
    clean_tests();
}

pub async fn put_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keyring: &Sr25519Keyring,
    constraint_account: subxtAccountId32,
) {
    let sig_req_account =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(sig_req_keyring.pair());
    let registering_tx = entropy::tx().relayer().register(
        constraint_account,
        Static(KeyVisibility::Public),
        None,
        [0; 32],
    );

    api.tx()
        .sign_and_submit_then_watch_default(&registering_tx, &sig_req_account)
        .await
        .unwrap()
        .wait_for_in_block()
        .await
        .unwrap()
        .wait_for_success()
        .await
        .unwrap();
}

pub async fn run_to_block(api: &OnlineClient<EntropyConfig>, block_run: u32) {
    let mut current_block = 0;
    while current_block < block_run {
        current_block = api.rpc().block(None).await.unwrap().unwrap().block.header.number;
    }
}

#[tokio::test]
#[serial]
async fn test_sign_tx_user_participates() {
    clean_tests();
    let one = AccountKeyring::Eve;
    let two = AccountKeyring::Two;

    let signing_address = one.clone().to_account_id().to_ss58check();
    let (validator_ips, _validator_ids, users_keyshare_option) =
        spawn_testing_validators(Some(signing_address.clone()), true).await;
    let substrate_context = test_context_stationary().await;
    let entropy_api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let initial_constraints = |address: [u8; 20]| -> Constraints {
        let mut evm_acl = Acl::<[u8; 20]>::default();
        evm_acl.addresses.push(address);

        Constraints { evm_acl: Some(Static(evm_acl)), btc_acl: None }
    };

    update_constraints(&entropy_api, &one.pair(), &one.pair(), initial_constraints([1u8; 20]))
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

    let signing_address = one.clone().to_account_id().to_ss58check();
    let sig_uid = create_unique_tx_id(&signing_address, &hex::encode(&sig_hash));

    let mut generic_msg = UserTransactionRequest {
        arch: "evm".to_string(),
        transaction_request: converted_transaction_request.clone(),
        validators_info: validators_info.clone(),
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

    // Submit transaction requests, and connect and participate in signing
    let (test_user_res, sig_result) = future::join(
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one),
        user_connects_to_validators(
            &users_keyshare_option.unwrap(),
            &sig_uid,
            validators_info.clone(),
            &one.pair(),
            &converted_transaction_request,
        ),
    )
    .await;

    let signature_base64 = base64::encode(sig_result.unwrap().to_rsv_bytes());
    assert_eq!(signature_base64.len(), 88);

    for res in test_user_res {
        let mut res = res.unwrap();
        assert_eq!(res.status(), 200);
        let chunk = res.chunk().await.unwrap().unwrap();
        let signing_result: Result<String, String> = serde_json::from_slice(&chunk).unwrap();
        assert_eq!(signature_base64, signing_result.unwrap());
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

    let mut generic_msg_bad_validators = generic_msg.clone();
    generic_msg_bad_validators.validators_info[0].x25519_public_key = [0; 32];

    let test_user_failed_x25519_pub_key = submit_transaction_requests(
        validator_ips_and_keys.clone(),
        generic_msg_bad_validators,
        one,
    )
    .await;

    let mut responses = test_user_failed_x25519_pub_key.into_iter();
    assert_eq!(
        responses.next().unwrap().unwrap().text().await.unwrap(),
        "{\"Err\":\"Subscribe message rejected: Decryption(\\\"Public key does not match that \
         given in UserTransactionRequest\\\")\"}"
    );

    assert_eq!(
        responses.next().unwrap().unwrap().text().await.unwrap(),
        "{\"Err\":\"Oneshot timeout error: channel closed\"}"
    );

    // Test attempting to connect over ws by someone who is not in the signing group
    let validator_ip_and_key = validator_ips_and_keys[0].clone();
    let connection_attempt_handle = tokio::spawn(async move {
        // Wait for the "user" to submit the signing request
        tokio::time::sleep(Duration::from_millis(500)).await;
        let ws_endpoint = format!("ws://{}/ws", validator_ip_and_key.0);
        let (ws_stream, _response) = connect_async(ws_endpoint).await.unwrap();

        // create a SubscribeMessage from a party who is not in the signing commitee
        let subscribe_message_vec =
            serde_json::to_vec(&SubscribeMessage::new(&sig_uid, &AccountKeyring::Ferdie.pair()))
                .unwrap();

        // Attempt a noise handshake including the subscribe message in the payload
        let mut encrypted_connection = noise_handshake_initiator(
            ws_stream,
            &AccountKeyring::Ferdie.pair(),
            validator_ip_and_key.1,
            subscribe_message_vec,
        )
        .await
        .unwrap();

        // Check the response as to whether they accepted our SubscribeMessage
        let response_message = encrypted_connection.recv().await.unwrap();
        let subscribe_response: Result<(), String> =
            serde_json::from_str(&response_message).unwrap();

        assert_eq!(
            Err("Decryption(\"Public key does not match that given in UserTransactionRequest\")"
                .to_string()),
            subscribe_response
        );
        // The stream should not continue to send messages
        // returns true if this part of the test passes
        encrypted_connection.recv().await.is_err()
    });

    let test_user_bad_connection_res = submit_transaction_requests(
        vec![validator_ips_and_keys[1].clone()],
        generic_msg.clone(),
        one,
    )
    .await;

    for res in test_user_bad_connection_res {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "{\"Err\":\"Timed out waiting for remote party\"}"
        );
    }

    assert!(connection_attempt_handle.await.unwrap());

    // Bad Account ID - an account ID is given which is not in the signing group
    let mut generic_msg_bad_account_id = generic_msg.clone();
    generic_msg_bad_account_id.validators_info[0].tss_account =
        AccountKeyring::Dave.to_account_id();

    let test_user_failed_tss_account = submit_transaction_requests(
        validator_ips_and_keys.clone(),
        generic_msg_bad_account_id,
        one,
    )
    .await;

    for res in test_user_failed_tss_account {
        let res = res.unwrap();
        assert_eq!(res.status(), 500);
        assert_eq!(res.text().await.unwrap(), "Invalid Signer: Invalid Signer in Signing group");
    }

    // Test a transcation which does not pass constaints
    generic_msg.transaction_request = hex::encode(&transaction_request_fail.rlp().to_vec());

    let test_user_failed_constraints_res =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    for res in test_user_failed_constraints_res {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "Constraints error: Constraint Evaluation error: Transaction not allowed."
        );
    }

    // Test unsupported transaction type
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
        one.pair().public().into(),
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

    // checks that sig not needed with public key visibility
    let user_input_bad = SignedMessage::new_test(
        Bytes(serde_json::to_vec(&generic_msg.clone()).unwrap()),
        sr25519::Signature::from_raw(sig),
        AccountKeyring::Dave.pair().public().into(),
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
    // fails lower down in stack because no sig needed on pub account
    // fails when tries to decode the nonsense message
    assert_ne!(failed_sign.text().await.unwrap(), "Invalid Signature: Invalid signature.");
    clean_tests();
}
