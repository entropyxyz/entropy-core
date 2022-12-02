use kvdb::clean_tests;
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
    tokio::time::{sleep, Duration},
};
use serial_test::serial;
use testing_utils::context::test_context;
use sp_core::{sr25519, Pair, crypto::AccountId32};
use subxt::{tx::{PairSigner, Signer}};
use hex_literal::hex;

use super::api::get_all_keys;
use crate::{chain_api::{get_api, entropy, EntropyConfig}, utils::{DEFAULT_BOB_MNEMONIC, DEFAULT_MNEMONIC}};
pub async fn setup_client() -> rocket::local::asynchronous::Client {
    Client::tracked(crate::rocket().await).await.expect("valid `Rocket`")
}

#[rocket::async_test]
#[serial]
async fn test_sync_keys() {
    clean_tests();
    let client = setup_client().await;

    let response = client.post("/validator/sync_keys").header(ContentType::JSON).dispatch().await;

    dbg!(response);
}

#[rocket::async_test]
async fn test_get_all_keys() {
    let cxt = test_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();

	let p_alice = <sr25519::Pair as Pair>::from_string(DEFAULT_MNEMONIC, None).unwrap();

    let signer = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_alice);
	let id: AccountId32 =
        hex!["fe65717dad0447d715f660a0a58411de509b42e6efb8375f562f58a554d5860e"].into();
    // temporay helper function to be removed
		let registering_tx = entropy::tx()
        .relayer()
        .test_unsafe_register(id);
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
    let result = get_all_keys(&api).await.unwrap();
}
