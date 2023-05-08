use std::{env, fs, path::PathBuf, sync::Arc};

use bip39::{Language, Mnemonic, MnemonicType};
use ec_constraints::{Architecture, Evm, Parse};
use entropy_shared::{Acl, Constraints, Message, OCWMessage, SigRequest, ValidatorInfo};
use ethers_core::types::{Address, TransactionRequest};
use futures::{future::join_all, join, Future};
use hex_literal::hex as h;
use kvdb::{clean_tests, encrypted_sled::PasswordMethod, kv_manager::value::KvManager};
use parity_scale_codec::Encode;
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
    tokio::{
        task::JoinSet,
        time::{sleep, Duration},
    },
    Build, Error, Ignite, Rocket,
};
use serial_test::serial;
use sp_core::{crypto::Ss58Codec, sr25519, Bytes, Pair, H160};
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{ext::sp_runtime::AccountId32, tx::PairSigner, OnlineClient};
use testing_utils::{
    constants::X25519_PUBLIC_KEYS,
    substrate_context::{test_context_stationary, SubstrateTestingContext},
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
    load_kv_store,
    message::{derive_static_secret, mnemonic_to_pair, new_mnemonic, SignedMessage},
    new_party, new_user,
    r#unsafe::api::{delete, get, put, remove_keys, UnsafeQuery},
    signing_client::{
        tests::{put_tx_request_on_chain, run_to_block},
        SignerState,
    },
    store_tx, subscribe_to_me,
    user::api::UserTransactionRequest,
    validator::api::get_random_server_info,
    Message as SigMessage,
};

#[rocket::async_test]
#[serial]
async fn test_get_signer_does_not_throw_err() {
    clean_tests();
    let kv_store = load_kv_store(false, false, false).await;
    let mnemonic = setup_mnemonic(&kv_store, false, false).await;
    assert!(mnemonic.is_ok());
    get_signer(&kv_store).await.unwrap();
    clean_tests();
}
#[rocket::async_test]
#[serial]
async fn test_sign_tx_no_chain() {
    clean_tests();
    let one = AccountKeyring::One;
    let test_user_constraint = AccountKeyring::Charlie;
    let two = AccountKeyring::Two;

    let validator_ips = spawn_testing_validators().await;
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
    // let parsed_tx =
    //     <Evm as Architecture>::TransactionRequest::parse(transaction_request).unwrap();
    let sig_hash = transaction_request.sighash();
    let message_request = Message {
        sig_request: SigRequest { sig_hash: sig_hash.as_bytes().to_vec() },
        account: one.to_raw_public_vec(),
        validators_info: vec![
            ValidatorInfo { ip_address: b"127.0.0.1:3001".to_vec(), x25519_public_key: [0; 32] },
            ValidatorInfo { ip_address: b"127.0.0.1:3002".to_vec(), x25519_public_key: [0; 32] },
        ],
    };
    let converted_transaction_request: String = hex::encode(&transaction_request.rlp().to_vec());
    let generic_msg = UserTransactionRequest {
        arch: "evm".to_string(),
        transaction_request: converted_transaction_request,
        message: message_request,
        validator_ips: vec![b"127.0.0.1:3001".to_vec(), b"127.0.0.1:3002".to_vec()],
    };

    let mock_client = reqwest::Client::new();

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
                        mock_client.post(url).json(&signed_message).send().await
                    })
                    .collect::<Vec<_>>(),
            )
            .await
        };
    let validator_urls_and_keys = vec![
        (validator_ips[0].clone(), X25519_PUBLIC_KEYS[0]),
        (validator_ips[1].clone(), X25519_PUBLIC_KEYS[1]),
    ];
    let test_user_res =
        submit_transaction_requests(validator_urls_and_keys.clone(), generic_msg.clone(), one)
            .await;
    test_user_res.into_iter().for_each(|res| assert_eq!(res.unwrap().status(), 200));

    let test_user_res_not_registered =
        submit_transaction_requests(validator_urls_and_keys.clone(), generic_msg, two).await;

    for res in test_user_res_not_registered {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "Not Registering error: Register Onchain first"
        );
    }

    let sig_request = SigMessage { message: hex::encode(sig_hash) };

    join_all(validator_ips.iter().map(|validator_ip| async {
        let url = format!("http://{}/signer/signature", validator_ip.clone());
        let res = mock_client.post(url).json(&sig_request).send().await.unwrap();
        assert_eq!(res.status(), 202);
        assert_eq!(res.content_length().unwrap(), 88);
    }))
    .await;
    // TODO negative signing tests
    clean_tests();
}

#[rocket::async_test]
#[serial]
async fn test_unsigned_tx_endpoint() {
    clean_tests();

    let substrate_context = test_context_stationary().await;
    let entropy_api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();

    // Alice and Bob are used as validators
    let test_user = AccountKeyring::One;
    let test_user_constraint = AccountKeyring::Charlie;
    let test_user2 = AccountKeyring::Two;
    let test_user2_constraint = AccountKeyring::Dave;

    let (validator_ips, validator_ids) = spawn_testing_validators().await;

    let initial_constraints = |address: [u8; 20]| -> Constraints {
        let mut evm_acl = Acl::<[u8; 20]>::default();
        evm_acl.addresses.push(address);

        Constraints { evm_acl: Some(evm_acl), ..Default::default() }
    };

    // register the user on-chain, their test threhsold keyshares with the threshold server, and
    // initial constraints
    register_user(
        &entropy_api,
        &validator_ips,
        &test_user,
        &test_user_constraint,
        initial_constraints([1u8; 20]),
        &validator_ids,
    )
    .await;
    register_user(
        &entropy_api,
        &validator_ips,
        &test_user2,
        &test_user2_constraint,
        initial_constraints([2u8; 20]),
        &validator_ids,
    )
    .await;

    let ports_and_keys = vec![(3001, X25519_PUBLIC_KEYS[0]), (3002, X25519_PUBLIC_KEYS[1])];

    let validator_info: Vec<(String, [u8; 32])> = ports_and_keys
        .iter()
        .map(|validator_tuple| (format!("127.0.0.1:{}", validator_tuple.0), validator_tuple.1))
        .collect::<Vec<_>>();

    let whitelisted_transaction_requests = vec![
        // alice
        TransactionRequest::new().to(Address::from([1u8; 20])).value(1),
        // test_user2 working tx
        TransactionRequest::new().to(Address::from([2u8; 20])).value(5),
    ];
    let non_whitelisted_transaction_requests = vec![
        // test_user tx should fail, non-whitelisted address
        TransactionRequest::new().to(Address::from([3u8; 20])).value(10),
        // test_user2 tx should fail non-whitelisted address
        TransactionRequest::new().to(Address::from([4u8; 20])).value(15),
    ];
    let transaction_requests = vec![
        whitelisted_transaction_requests.clone(),
        non_whitelisted_transaction_requests.clone(),
    ]
    .concat();

    let keyrings = vec![test_user, test_user2, test_user, test_user2];
    let ocw_to_message_req = |(tx_req, keyring): (TransactionRequest, Sr25519Keyring)| -> Message {
        Message {
            sig_request: SigRequest { sig_hash: tx_req.sighash().as_bytes().to_vec() },
            account: keyring.to_raw_public_vec(),
            validators_info: validator_info
                .iter()
                .map(|validator_tuple| ValidatorInfo {
                    ip_address: validator_tuple.0.clone().into_bytes(),
                    x25519_public_key: validator_tuple.1,
                })
                .collect::<Vec<ValidatorInfo>>(),
        }
    };

    let raw_ocw_messages = transaction_requests
        .clone()
        .into_iter()
        .zip(keyrings.clone())
        .map(ocw_to_message_req)
        .collect::<Vec<_>>();

    let place_sig_messages = raw_ocw_messages
        .iter()
        .zip(keyrings.clone())
        .map(|(raw_ocw_message, keyring)| UnsafeQuery {
            key: create_unique_tx_id(
                &keyring.to_account_id().to_ss58check(),
                &hex::encode(raw_ocw_message.sig_request.sig_hash.clone()),
            ),
            value: serde_json::to_string(&raw_ocw_message).unwrap(),
        })
        .collect::<Vec<_>>();

    let mock_client = reqwest::Client::new();
    // put proper data in kvdb
    join_all(place_sig_messages.iter().map(|place_sig_messages| async {
        let res = mock_client
            .post("http://127.0.0.1:3001/unsafe/put")
            .json(place_sig_messages)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);

        let res_2 = mock_client
            .post("http://127.0.0.1:3002/unsafe/put")
            .json(place_sig_messages)
            .send()
            .await
            .unwrap();
        assert_eq!(res_2.status(), 200);
    }))
    .await;

    let validator_urls_and_keys: Arc<Vec<(String, [u8; 32])>> = Arc::new(
        validator_info
            .iter()
            .map(|validator_tuple| (format!("http://{}", validator_tuple.0), validator_tuple.1))
            .collect(),
    );

    // construct json bodies for transaction requests
    let tx_req_bodies = transaction_requests
        .iter()
        .zip(keyrings.clone())
        .map(|(tx_req, keyring)| {
            (
                serde_json::json!({
                    "arch": "evm",
                    "transaction_request": tx_req.rlp_unsigned().to_string(),
                }),
                keyring,
            )
        })
        .collect::<Vec<_>>();

    // mock client signature requests
    let submit_transaction_requests =
        |validator_urls_and_keys: Arc<Vec<(String, [u8; 32])>>,
         tx_req_body: (serde_json::Value, AccountKeyring)| async move {
            let mock_client = reqwest::Client::new();
            join_all(
                validator_urls_and_keys
                    .iter()
                    .map(|validator_tuple| async {
                        let server_public_key = PublicKey::from(validator_tuple.1);
                        let signed_message = SignedMessage::new(
                            &tx_req_body.1.pair(),
                            &Bytes(serde_json::to_vec(&tx_req_body.0.clone()).unwrap()),
                            &server_public_key,
                        )
                        .unwrap();
                        let url = format!("{}/user/tx", validator_tuple.0.clone());
                        mock_client.post(url).json(&signed_message).send().await
                    })
                    .collect::<Vec<_>>(),
            )
            .await
        };

    // test_user and test_user2 whitelisted transaction requests should succeed
    let test_user_res =
        submit_transaction_requests(validator_urls_and_keys.clone(), tx_req_bodies[0].clone())
            .await;
    test_user_res.into_iter().for_each(|res| assert_eq!(res.unwrap().status(), 200));

    let test_user2_res =
        submit_transaction_requests(validator_urls_and_keys.clone(), tx_req_bodies[1].clone())
            .await;
    test_user2_res.into_iter().for_each(|res| assert_eq!(res.unwrap().status(), 200));

    // the other txs should fail because of failed constraints
    let test_user_failed_constraints_res =
        submit_transaction_requests(validator_urls_and_keys.clone(), tx_req_bodies[2].clone())
            .await;
    test_user_failed_constraints_res
        .into_iter()
        .for_each(|res| assert_eq!(res.unwrap().status(), 500));

    let test_user2_failed_constraints_res =
        submit_transaction_requests(validator_urls_and_keys.clone(), tx_req_bodies[3].clone())
            .await;
    test_user2_failed_constraints_res
        .into_iter()
        .for_each(|res| assert_eq!(res.unwrap().status(), 500));

    // poll a validator server and validate the threshold signatures
    let get_sig_messages = whitelisted_transaction_requests
        .clone()
        .into_iter()
        .zip(keyrings)
        .map(ocw_to_message_req)
        .collect::<Vec<_>>()
        .into_iter()
        .map(|raw_ocw_message| SigMessage {
            message: hex::encode(raw_ocw_message.sig_request.sig_hash),
        })
        .collect::<Vec<_>>();

    join_all(get_sig_messages.iter().map(|get_sig_message| async {
        let client = reqwest::Client::new();
        let url = format!("http://{}/signer/signature", validator_ips[0].clone());
        let res = client.post(url).json(get_sig_message).send().await.unwrap();
        assert_eq!(res.status(), 202);
        assert_eq!(res.content_length().unwrap(), 88);
    }))
    .await;

    // delete all signatures from the servers

    join_all(validator_urls_and_keys.iter().map(|validator_tuple| async {
        let url = format!("{}/signer/drain", validator_tuple.0.clone());
        let res = mock_client.get(url).send().await;
        assert_eq!(res.unwrap().status(), 200);
    }))
    .await;

    // query the signature again, should error since we just deleted them
    join_all(get_sig_messages.iter().map(|get_sig_message| async {
        let client = reqwest::Client::new();
        let url = format!("http://{}/signer/signature", validator_ips[0].clone());
        let res = client.post(url).json(get_sig_message).send().await;
        assert_eq!(res.unwrap().status(), 404);
    }))
    .await;

    // test fail validation decrypt
    let server_public_key = PublicKey::from(X25519_PUBLIC_KEYS[1]);
    let failed_signed_message = SignedMessage::new(
        &tx_req_bodies[0].1.pair(),
        &Bytes(serde_json::to_vec(&tx_req_bodies[0].0.clone()).unwrap()),
        &server_public_key,
    )
    .unwrap();
    let failed_res = mock_client
        .post("http://127.0.0.1:3001//user/tx")
        .json(&failed_signed_message)
        .send()
        .await
        .unwrap();
    assert_eq!(failed_res.status(), 500);
    assert_eq!(failed_res.text().await.unwrap(), "ChaCha20 decryption error: aead::Error");

    let sig: [u8; 64] = [0; 64];
    let slice: [u8; 32] = [0; 32];
    let nonce: [u8; 12] = [0; 12];

    let user_input_bad = SignedMessage::new_test(
        Bytes(serde_json::to_vec(&tx_req_bodies[0].0.clone()).unwrap()),
        sr25519::Signature::from_raw(sig),
        slice,
        slice,
        slice,
        nonce,
    );

    let failed_sign = mock_client
        .post("http://127.0.0.1:3001//user/tx")
        .json(&user_input_bad)
        .send()
        .await
        .unwrap();

    assert_eq!(failed_sign.status(), 500);
    assert_eq!(failed_sign.text().await.unwrap(), "Invalid Signature: Invalid signature.");
    clean_tests();
}

// TODO negative validation tests on user/tx

#[rocket::async_test]
#[serial]
async fn test_store_share() {
    clean_tests();
    let alice = AccountKeyring::Alice;
    let alice_constraint = AccountKeyring::Charlie;

    let value: Vec<u8> = vec![0];

    let cxt = test_context_stationary().await;
    let client = setup_client().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();

    let server_public_key = PublicKey::from(X25519_PUBLIC_KEYS[0]);
    let user_input = SignedMessage::new(&alice.pair(), &Bytes(value.clone()), &server_public_key)
        .unwrap()
        .to_json();
    // fails to add not registering or swapping
    let response = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(user_input.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::InternalServerError);
    assert_eq!(
        response.into_string().await.unwrap(),
        "Not Registering error: Register Onchain first"
    );

    // signal registering
    make_register(&api, &alice, &alice_constraint.to_account_id()).await;

    let response_2 = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(user_input.clone())
        .dispatch()
        .await;
    assert_eq!(response_2.status(), Status::Ok);
    assert_eq!(response_2.into_string().await, None);
    // make sure there is now one confirmation
    check_if_confirmation(&api, &alice).await;

    // fails to add already added share
    let response_3 = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(user_input.clone())
        .dispatch()
        .await;

    assert_eq!(response_3.status(), Status::InternalServerError);
    assert_eq!(response_3.into_string().await.unwrap(), "Kv error: Recv Error: channel closed");

    // fails with wrong node key
    let server_public_key_bob = PublicKey::from(X25519_PUBLIC_KEYS[1]);
    let user_input_bob =
        SignedMessage::new(&alice.pair(), &Bytes(value.clone()), &server_public_key_bob)
            .unwrap()
            .to_json();

    let response_4 = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(user_input_bob.clone())
        .dispatch()
        .await;

    assert_eq!(response_4.status(), Status::InternalServerError);
    let expected_err = "ChaCha20 decryption error: aead::Error";
    assert_eq!(response_4.into_string().await.unwrap(), expected_err);
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
        .post("/user/new")
        .header(ContentType::JSON)
        .body(user_input_bad.clone())
        .dispatch()
        .await;

    assert_eq!(response_5.status(), Status::InternalServerError);
    assert_eq!(response_5.into_string().await.unwrap(), "Invalid Signature: Invalid signature.");
    clean_tests();
}

#[rocket::async_test]
#[serial]
async fn test_update_keys() {
    clean_tests();
    let dave = AccountKeyring::Dave;

    let key: AccountId32 = dave.to_account_id();
    let value: Vec<u8> = vec![0];
    let new_value: Vec<u8> = vec![1];
    let cxt = test_context_stationary().await;
    let client = setup_client().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();

    let server_public_key = PublicKey::from(X25519_PUBLIC_KEYS[0]);
    let user_input =
        SignedMessage::new(&dave.pair(), &Bytes(new_value.clone()), &server_public_key)
            .unwrap()
            .to_json();

    let put_query =
        UnsafeQuery::new(key.to_string(), serde_json::to_string(&value).unwrap()).to_json();
    // manually add dave's key to replace it
    let response = client
        .post("/unsafe/put")
        .header(ContentType::JSON)
        .body(put_query.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    // fails to add not registering or swapping
    let response_2 = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(user_input.clone())
        .dispatch()
        .await;

    assert_eq!(response_2.status(), Status::InternalServerError);
    assert_eq!(
        response_2.into_string().await.unwrap(),
        "Not Registering error: Register Onchain first" /* "Generic Substrate error:
                                                         * Metadata: Pallet Relayer Storage
                                                         * Relayer has incompatible
                                                         * metadata" */
    );

    // signal registering
    make_swapping(&api, &dave).await;

    let response_3 = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(user_input.clone())
        .dispatch()
        .await;
    assert_eq!(response_3.status(), Status::Ok);
    assert_eq!(response_3.into_string().await, None);
    // make sure there is now one confirmation
    check_if_confirmation(&api, &dave).await;

    // check dave has new key
    let response_4 = client
        .post("/unsafe/get")
        .header(ContentType::JSON)
        .body(put_query.clone())
        .dispatch()
        .await;

    assert_eq!(
        response_4.into_string().await,
        Some(std::str::from_utf8(&new_value).unwrap().to_string())
    );
    clean_tests();
}

#[rocket::async_test]
#[serial]
async fn test_store_share_fail_wrong_data() {
    clean_tests();
    // Construct a client to use for dispatching requests.
    let client = setup_client().await;
    let response = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(
            r##"{
		"name": "John Doe",
		"email": "j.doe@m.com",
		"password": "123456"
	}"##,
        )
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::UnprocessableEntity);
    clean_tests();
}
