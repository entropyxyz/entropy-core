use std::env;

use bip39::{Language, Mnemonic, MnemonicType};
use hex;
use hex_literal::hex as h;
use kvdb::clean_tests;
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
    tokio::time::{sleep, Duration},
};
use serial_test::serial;
use sp_core::{sr25519, Bytes, Pair};
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{ext::sp_runtime::AccountId32, tx::PairSigner};
use testing_utils::context::{test_context, test_context_stationary, TestContext};
use x25519_dalek::{PublicKey, StaticSecret};

use super::{api::get_subgroup, UserInputPartyInfo};
use crate::{
    chain_api::{entropy::EntropyRuntime, get_api, EntropyConfig},
    get_signer, load_kv_store,
    message::{derive_static_secret, mnemonic_to_pair, new_mnemonic, SignedMessage},
    user::unsafe_api::UnsafeQuery,
    utils,
    utils::DEFAULT_MNEMONIC,
};

pub async fn setup_client() -> rocket::local::asynchronous::Client {
    Client::tracked(crate::rocket().await).await.expect("valid `Rocket`")
}

#[rocket::async_test]
#[serial]
async fn test_get_signer_does_not_throw_err() {
    let kv_store = load_kv_store().await;
    get_signer(&kv_store).await.unwrap();
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
        assert!(response_mnemonic.len() > 0);

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
    let alice_stash_id: AccountId32 =
        h!["be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f"].into();
    let key: AccountId32 = alice.to_account_id().into();
    let value: Vec<u8> = vec![0];

    let cxt = test_context_stationary().await;
    let client = setup_client().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();

    let query_result =
        api.storage().staking_extension().threshold_accounts(&alice_stash_id, None).await.unwrap();
    assert!(!query_result.is_none());

    let res = query_result.unwrap();
    let server_public_key = PublicKey::from(res.1);
    let user_input =
        SignedMessage::new(&alice.pair(), &Bytes(value), &server_public_key).unwrap().to_json();

    // fails to add not registering
    let response = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(user_input.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::InternalServerError);

    // signal registering
    make_register(&api, &alice).await;

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

    clean_tests();
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
    let p_alice = <sr25519::Pair as Pair>::from_string("//Alice//stash", None).unwrap();
    let signer_alice = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_alice);
    let result_alice = get_subgroup(&api, &signer_alice).await.unwrap();
    assert_eq!(result_alice, Some(0));

    let p_bob = <sr25519::Pair as Pair>::from_string("//Bob//stash", None).unwrap();
    let signer_bob = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_bob);
    let result_bob = get_subgroup(&api, &signer_bob).await.unwrap();
    assert_eq!(result_bob, Some(1));

    let p_charlie = <sr25519::Pair as Pair>::from_string("//Charlie//stash", None).unwrap();
    let signer_charlie = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_charlie);
    let result_charlie = get_subgroup(&api, &signer_charlie).await.unwrap();
    assert_eq!(result_charlie, None);

    clean_tests();
}

pub async fn make_register(api: &EntropyRuntime, alice: &Sr25519Keyring) {
    let signer = PairSigner::new(alice.pair());
    let is_registering_1 =
        api.storage().relayer().registering(&alice.to_account_id(), None).await.unwrap();
    assert_eq!(is_registering_1.is_none(), true);
    api.tx()
        .relayer()
        .register()
        .sign_and_submit_then_watch_default(&signer)
        .await
        .unwrap()
        .wait_for_in_block()
        .await
        .unwrap()
        .wait_for_success()
        .await
        .unwrap();
    let is_registering_2 =
        api.storage().relayer().registering(&alice.to_account_id(), None).await.unwrap();
    assert_eq!(is_registering_2.unwrap().is_registering, true);
}

pub async fn check_if_confirmation(api: &EntropyRuntime, alice: &Sr25519Keyring) {
    let is_registering =
        api.storage().relayer().registering(&alice.to_account_id(), None).await.unwrap();
    // make sure there is one confirmation
    assert_eq!(is_registering.unwrap().confirmations.len(), 1);
    let is_registered =
        api.storage().relayer().registered(&alice.to_account_id(), None).await.unwrap();
    // still not registered need more confirmations
    assert_eq!(is_registered.is_none(), true);
}
