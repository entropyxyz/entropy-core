use kvdb::clean_tests;
use rocket::{
    local::asynchronous::Client,
    http::{ContentType, Status},
};
use serial_test::serial;
use sp_core::{sr25519, Pair, Bytes, H256, H160};
use subxt::{
    tx::PairSigner,
    OnlineClient,
    ext::sp_runtime::AccountId32,
};
use testing_utils::substrate_context::testing_context;
use sp_keyring::Sr25519Keyring;
use x25519_dalek::PublicKey;
use hex_literal::hex as h;

use super::substrate::get_subgroup;
use crate::{
    chain_api::{get_api, EntropyConfig,
        entropy,
    },
    helpers::{
        launch::{DEFAULT_BOB_MNEMONIC, DEFAULT_MNEMONIC},
        substrate::{make_register, }
    },
    message::SignedMessage,
};
use entropy_shared::{Constraints, Acl};
pub async fn setup_client() -> Client {
    Client::tracked(crate::rocket().await).await.expect("valid `Rocket`")
}

pub async fn register_user_single_validator(
    entropy_api: &OnlineClient<EntropyConfig>,
    sig_req_account: &Sr25519Keyring,
    constraint_modificaiton_account: &Sr25519Keyring,
) {
    let validator_1_stash_id: AccountId32 =
        h!["be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f"].into(); // alice stash;
    let value: Vec<u8> = vec![0];

    let threshold_servers_query =
        entropy::storage().staking_extension().threshold_servers(&validator_1_stash_id);
    let client = setup_client().await;
    let query_result = entropy_api.storage().fetch(&threshold_servers_query, None).await.unwrap();
    assert!(query_result.is_some());

    let res = query_result.unwrap();
    let server_public_key = PublicKey::from(res.x25519_public_key);
    let user_input = SignedMessage::new(&sig_req_account.pair(), &Bytes(value.clone()), &server_public_key)
        .unwrap()
        .to_json();

    let initial_constraints = {
        let mut evm_acl = Acl::<H160>::default();
        evm_acl.addresses.push(H160::from([0u8; 20]));
        
        Constraints {
            evm_acl: Some(evm_acl),
            ..Default::default()
        }
    };

    make_register(&entropy_api, &sig_req_account, &constraint_modificaiton_account, Some(initial_constraints)).await;

    let response_2 = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(user_input.clone())
        .dispatch()
        .await;
    assert_eq!(response_2.status(), Status::Ok);
    assert_eq!(response_2.into_string().await, None);
    // make sure there is now one confirmation
    check_if_confirmation(&entropy_api, &sig_req_account).await;
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

#[rocket::async_test]
#[serial]
async fn test_get_signing_group() {
    clean_tests();
    let cxt = testing_context().await;
    let _ = setup_client().await;
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
