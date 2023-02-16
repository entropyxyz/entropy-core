use std::env;

use bip39::{Language, Mnemonic, MnemonicType};
use hex_literal::hex as h;
use kvdb::clean_tests;
use rocket::{
    http::{ContentType, Status},
    tokio::time::{sleep, Duration},
};
use serial_test::serial;
use sp_core::{sr25519, Bytes, Pair, H160};
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{ext::sp_runtime::AccountId32, tx::PairSigner, OnlineClient};
use testing_utils::context::{test_context, test_context_stationary, TestContext};
use x25519_dalek::{PublicKey, StaticSecret};

use super::UserInputPartyInfo;
use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    get_signer,
    helpers::{
        launch::{setup_mnemonic, DEFAULT_BOB_MNEMONIC, DEFAULT_MNEMONIC},
        tests::setup_client,
    },
    load_kv_store,
    message::{derive_static_secret, mnemonic_to_pair, new_mnemonic, SignedMessage},
    r#unsafe::api::UnsafeQuery,
    validator::api::get_random_server_info,
};

#[rocket::async_test]
#[serial]
async fn test_get_signer_does_not_throw_err() {
    clean_tests();
    let kv_store = load_kv_store(false, false).await;
    let mnemonic = setup_mnemonic(&kv_store, false, false).await;
    assert!(mnemonic.is_ok());
    get_signer(&kv_store).await.unwrap();
    clean_tests();
}

#[rocket::async_test]
#[serial]
async fn test_unsigned_tx_endpoint() {
    clean_tests();
    let client = setup_client().await;

    let arch = r#"evm"#;
    // encoded_tx_req comes from ethers serializeTransaction() of the following UnsignedTransaction:
    // {"to":"0x772b9a9e8aa1c9db861c6611a82d251db4fac990","value":{"type":"BigNumber","hex":"0x01"},
    // "chainId":1,"nonce":1,"data":"0x43726561746564204f6e20456e74726f7079"} See frontend
    // threshold-server tests for more context
    let transaction_request = r#"0xef01808094772b9a9e8aa1c9db861c6611a82d251db4fac990019243726561746564204f6e20456e74726f7079018080"#;
    let tx_req = serde_json::json!({
        "arch": arch,
        "transaction_request": transaction_request,
    });
    println!("tx_req: {:?}\n", tx_req.clone());

    let response =
        client.post("/user/tx").header(ContentType::JSON).body(tx_req.to_string()).dispatch().await;
    println!("response: {:?}\n", response);
    assert_eq!(response.status(), Status::Ok);
    clean_tests();
}

#[rocket::async_test]
#[serial]
async fn test_store_share() {
    clean_tests();
    let alice = AccountKeyring::Alice;
    let alice_constraint = AccountKeyring::Charlie;
    let alice_stash_id: AccountId32 =
        h!["be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f"].into();

    let value: Vec<u8> = vec![0];

    let cxt = test_context_stationary().await;
    let client = setup_client().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();

    let threshold_servers_query =
        entropy::storage().staking_extension().threshold_servers(&alice_stash_id);
    let query_result = api.storage().fetch(&threshold_servers_query, None).await.unwrap();
    assert!(query_result.is_some());

    let res = query_result.unwrap();
    let server_public_key = PublicKey::from(res.x25519_public_key);
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
    make_register(&api, &alice, &alice_constraint).await;

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
    let bob_stash_id: AccountId32 =
        h!["fe65717dad0447d715f660a0a58411de509b42e6efb8375f562f58a554d5860e"].into();

    let query_bob = entropy::storage().staking_extension().threshold_servers(&bob_stash_id);
    let query_result_bob = api.storage().fetch(&query_bob, None).await.unwrap();
    let res_bob = query_result_bob.unwrap();
    let server_public_key_bob = PublicKey::from(res_bob.x25519_public_key);
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
    if cfg!(feature = "unsafe") {
        clean_tests();
        let dave = AccountKeyring::Dave;
        let alice_stash_id: AccountId32 =
            h!["be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f"].into();

        let key: AccountId32 = dave.to_account_id();
        let value: Vec<u8> = vec![0];
        let new_value: Vec<u8> = vec![1];
        let cxt = test_context_stationary().await;
        let client = setup_client().await;
        let api = get_api(&cxt.node_proc.ws_url).await.unwrap();

        let threshold_servers_query =
            entropy::storage().staking_extension().threshold_servers(&alice_stash_id);
        let query_result = api.storage().fetch(&threshold_servers_query, None).await.unwrap();
        assert!(query_result.is_some());

        let res = query_result.unwrap();
        let server_public_key = PublicKey::from(res.x25519_public_key);
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

pub async fn make_register(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keyring: &Sr25519Keyring,
    constraint_keyring: &Sr25519Keyring,
) {
    clean_tests();
    let sig_req_account =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(sig_req_keyring.pair());
    let registering_query =
        entropy::storage().relayer().registering(sig_req_keyring.to_account_id());
    let is_registering_1 = api.storage().fetch(&registering_query, None).await.unwrap();
    assert!(is_registering_1.is_none());

    let registering_tx = entropy::tx().relayer().register(constraint_keyring.to_account_id(), None);

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

    let is_registering_2 = api.storage().fetch(&registering_query, None).await;
    assert!(is_registering_2.unwrap().unwrap().is_registering);
}

pub async fn make_swapping(api: &OnlineClient<EntropyConfig>, key: &Sr25519Keyring) {
    let signer = PairSigner::new(key.pair());
    let registering_query = entropy::storage().relayer().registering(key.to_account_id());
    let is_registering_1 = api.storage().fetch(&registering_query, None).await.unwrap();
    assert!(is_registering_1.is_none());

    let registering_tx = entropy::tx().relayer().swap_keys();

    api.tx()
        .sign_and_submit_then_watch_default(&registering_tx, &signer)
        .await
        .unwrap()
        .wait_for_in_block()
        .await
        .unwrap()
        .wait_for_success()
        .await
        .unwrap();

    let is_registering_2 = api.storage().fetch(&registering_query, None).await;
    assert!(is_registering_2.unwrap().unwrap().is_registering);
}

pub async fn check_if_confirmation(api: &OnlineClient<EntropyConfig>, key: &Sr25519Keyring) {
    let registering_query = entropy::storage().relayer().registering(key.to_account_id());
    let registered_query = entropy::storage().relayer().registered(key.to_account_id());
    let is_registering = api.storage().fetch(&registering_query, None).await.unwrap();
    // make sure there is one confirmation
    assert_eq!(is_registering.unwrap().confirmations.len(), 1);
    let _ = api.storage().fetch(&registered_query, None).await.unwrap();
}
