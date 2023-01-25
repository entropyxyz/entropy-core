use std::env;

use bip39::{Language, Mnemonic, MnemonicType};
use hex_literal::hex as h;
use kvdb::clean_tests;
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
    tokio::time::{sleep, Duration},
};
use serial_test::serial;
use sp_core::{sr25519, Bytes, Pair, H160};
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{ext::sp_runtime::AccountId32, tx::PairSigner, OnlineClient};
use testing_utils::context::{test_context, test_context_stationary, TestContext};
use x25519_dalek::{PublicKey, StaticSecret};

use super::{api::get_subgroup, UserInputPartyInfo};
use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    get_signer, load_kv_store,
    message::{derive_static_secret, mnemonic_to_pair, new_mnemonic, SignedMessage},
    setup_mnemonic,
    user::{
        tests::entropy::runtime_types::substrate_common::constraints::acl::Acl,
        unsafe_api::UnsafeQuery,
    },
    utils,
    utils::{DEFAULT_BOB_MNEMONIC, DEFAULT_MNEMONIC},
};

pub async fn setup_client() -> rocket::local::asynchronous::Client {
    Client::tracked(crate::rocket().await).await.expect("valid `Rocket`")
}

#[rocket::async_test]
#[serial]
async fn test_get_signer_does_not_throw_err() {
    let kv_store = load_kv_store(false).await;
    setup_mnemonic(&kv_store, false, false).await;
    get_signer(&kv_store).await.unwrap();
}

#[rocket::async_test]
#[serial]
async fn test_unsigned_tx_endpoint() {
    clean_tests();
    let cxt = test_context_stationary().await;
    let client = setup_client().await;
    let tx_req = r#"{"tx":{"to":"0x772b9a9e8aa1c9db861c6611a82d251db4fac990","value":{"type":"BigNumber","hex":"0x64"},"chainId":5,"gasPrice":{"type":"BigNumber","hex":"0x45d964b800"},"gasLimit":{"type":"BigNumber","hex":"0x07c830"},"nonce":5,"data":"0x6d656f77","type":0},"hash":"b31312f9f26bdb33357e63eec6095dae8ae5ae1e6a8a2f1f2170b78f9c28ad09"}"#;
    let response = client.post("/user/tx").header(ContentType::JSON).body(tx_req).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    clean_tests();
}

#[rocket::async_test]
#[serial]
async fn test_unsafe_get_endpoint() {
    if cfg!(feature = "unsafe") {
        let cxt = test_context_stationary().await;
        let client = setup_client().await;
        let get_query = UnsafeQuery::new("MNEMONIC".to_string(), "foo".to_string()).to_json();

        // Test that the get endpoint works
        let response = client
            .post("/unsafe/get")
            .header(ContentType::JSON)
            .body(get_query.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        let response_mnemonic = response.into_string().await.unwrap();
        assert!(!response_mnemonic.is_empty());

        // Update the mnemonic, testing the put endpoint works
        let put_response = client
            .post("/unsafe/put")
            .header(ContentType::JSON)
            .body(get_query.clone())
            .dispatch()
            .await;

        assert_eq!(put_response.status(), Status::Ok);

        // Check the updated mnemonic is the new value
        let get_response =
            client.post("/unsafe/get").header(ContentType::JSON).body(get_query).dispatch().await;

        assert_eq!(get_response.status(), Status::Ok);
        let updated_response_mnemonic = get_response.into_string().await.unwrap();
        assert_eq!(updated_response_mnemonic, "foo".to_string());

        clean_tests();
    }
}

#[rocket::async_test]
#[serial]
async fn test_store_share() {
    clean_tests();
    let alice = AccountKeyring::Alice;
    let alice_constraint = AccountKeyring::Charlie;
    let alice_stash_id: AccountId32 =
        h!["be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f"].into();

    let key: AccountId32 = alice.to_account_id();
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
    clean_tests();
    let dave = AccountKeyring::Dave;
    let alice = AccountKeyring::Alice;
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

    let user_input_alice =
        SignedMessage::new(&alice.pair(), &Bytes(value.clone()), &server_public_key)
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
        "Not Registering error: Register Onchain first"
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
}

#[rocket::async_test]
#[serial]
async fn test_store_share_fail_wrong_data() {
    // Construct a client to use for dispatching requests.
    let client = setup_client().await;
    let cxt = test_context_stationary().await;
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

#[rocket::async_test]
#[serial]
async fn test_get_signing_group() {
    let cxt = test_context().await;
    let client = setup_client().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let p_alice = <sr25519::Pair as Pair>::from_string(DEFAULT_MNEMONIC, None).unwrap();
    let signer_alice = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_alice);
    let result_alice = get_subgroup(&api, &signer_alice).await.unwrap();
    assert_eq!(result_alice, Some(0));

    let p_bob = <sr25519::Pair as Pair>::from_string(DEFAULT_BOB_MNEMONIC, None).unwrap();
    let signer_bob = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_bob);
    let result_bob = get_subgroup(&api, &signer_bob).await.unwrap();
    assert_eq!(result_bob, Some(1));

    let p_charlie = <sr25519::Pair as Pair>::from_string("//Charlie//stash", None).unwrap();
    let signer_charlie = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_charlie);
    let result_charlie = get_subgroup(&api, &signer_charlie).await;
    assert!(result_charlie.is_err());

    clean_tests();
}

pub async fn make_register(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keyring: &Sr25519Keyring,
    constraint_keyring: &Sr25519Keyring,
) {
    let sig_req_account =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(sig_req_keyring.pair());
    let constraint_account =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(constraint_keyring.pair());
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
    let is_registered = api.storage().fetch(&registered_query, None).await.unwrap();
}
