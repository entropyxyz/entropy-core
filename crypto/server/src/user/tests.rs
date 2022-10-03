use std::env;

use kvdb::clean_tests;
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
    tokio::time::{sleep, Duration},
};
use serial_test::serial;
use sp_core::{Pair, sr25519};
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{sp_runtime::AccountId32, PairSigner, DefaultConfig};
use testing_utils::context::{test_context_stationary, test_context, TestContext};
use bip39::{Language, Mnemonic};

use super::{UserInputPartyInfo, api::get_subgroup};
use crate::{chain_api::{get_api, EntropyRuntime}, utils::DEFAULT_MNEMONIC};

pub async fn setup_client() -> rocket::local::asynchronous::Client {
    Client::tracked(crate::rocket().await).await.expect("valid `Rocket`")
}

#[rocket::async_test]
#[serial]
async fn test_store_share() {
    let alice = AccountKeyring::Alice;
    let key: AccountId32 = alice.to_account_id().into();
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


#[rocket::async_test]
#[serial]
async fn test_get_signing_group() {
	let cxt = test_context().await;
    let client = setup_client().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let p_alice = <sr25519::Pair as Pair>::from_string("//Alice//stash", None).unwrap();
	let signer_alice = PairSigner::<DefaultConfig, sr25519::Pair>::new(p_alice);
	let result_alice = get_subgroup(&api, &signer_alice).await.unwrap();
	assert_eq!(result_alice, Some(0));

	let p_bob = <sr25519::Pair as Pair>::from_string("//Bob//stash", None).unwrap();
	let signer_bob = PairSigner::<DefaultConfig, sr25519::Pair>::new(p_bob);
	let result_bob = get_subgroup(&api, &signer_bob).await.unwrap();
	assert_eq!(result_bob, Some(1));


	let p_charlie = <sr25519::Pair as Pair>::from_string("//Charlie//stash", None).unwrap();
	let signer_charlie = PairSigner::<DefaultConfig, sr25519::Pair>::new(p_charlie);
	let result_charlie = get_subgroup(&api, &signer_charlie).await.unwrap();
	assert_eq!(result_charlie, None);

    clean_tests();
}

pub async fn make_register(api: &EntropyRuntime, alice: &Sr25519Keyring) {
    let signer = PairSigner::new(alice.pair());
    let is_registering_1 =
        api.storage().relayer().registering(&alice.to_account_id(), None).await.unwrap();
    assert_eq!(is_registering_1.unwrap().is_registering, false);
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

pub async fn check_if_registered(api: &EntropyRuntime, alice: &Sr25519Keyring) {
    let is_registering =
        api.storage().relayer().registering(&alice.to_account_id(), None).await.unwrap();
    assert_eq!(is_registering.is_none(), true);
    let is_registered =
        api.storage().relayer().registered(&alice.to_account_id(), None).await.unwrap();
    assert_eq!(is_registered.unwrap(), true);
}
