use std::env;

use kvdb::clean_tests;
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
    tokio::time::{sleep, Duration},
};
use serial_test::serial;
use sp_core::Pair;
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{sp_runtime::AccountId32, PairSigner};
use testing_utils::context::{test_context_stationary, TestContext};

use super::UserInputPartyInfo;
use crate::chain_api::{get_api, EntropyRuntime};

pub async fn setup_client() -> rocket::local::asynchronous::Client {
    Client::tracked(crate::rocket().await).await.expect("valid `Rocket`")
}

#[rocket::async_test]
#[serial]
async fn test_store_share() {
    let alice = AccountKeyring::Alice;
    let key: AccountId32 = alice.to_account_id();
    let value = vec![10];

    let cxt = test_context_stationary().await;
    let client = setup_client().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let user_input = UserInputPartyInfo { key: key.clone(), value: value.clone() };

    // fails to add not registering
    let response = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&user_input.clone()).unwrap())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::InternalServerError);

    // signal registering
    make_register(&api, &alice).await;

    let response = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&user_input.clone()).unwrap())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().await, None);

    check_if_registered(&api, &alice).await;

    make_register(&api, &alice).await;
    // fails to add already added share
    let response = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&user_input).unwrap())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::InternalServerError);

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

pub async fn make_register(api: &EntropyRuntime, alice: &Sr25519Keyring) {
    let signer = PairSigner::new(alice.pair());
    let is_registering_1 =
        api.storage().relayer().registering(&alice.to_account_id(), None).await.unwrap();
    assert_eq!(is_registering_1, None);
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
    assert_eq!(is_registering_2, Some(true));
}

pub async fn check_if_registered(api: &EntropyRuntime, alice: &Sr25519Keyring) {
    let is_registering =
        api.storage().relayer().registering(&alice.to_account_id(), None).await.unwrap();
    assert_eq!(is_registering, None);
    let is_registered =
        api.storage().relayer().registered(&alice.to_account_id(), None).await.unwrap();
    assert_eq!(is_registered, Some(true));
}
