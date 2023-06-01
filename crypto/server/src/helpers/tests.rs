// only compile when testing
#![cfg(test)]

use entropy_shared::Constraints;
use futures::future::join_all;
use kvdb::{
    clean_tests,
    encrypted_sled::PasswordMethod,
    kv_manager::{KvManager, PartyId},
};
use rand_core::OsRng;
use rocket::{local::asynchronous::Client, tokio::time::Duration, Ignite, Rocket};
use serial_test::serial;
use sp_core::{crypto::AccountId32, sr25519, Bytes, Pair};
use sp_keyring::Sr25519Keyring;
use subxt::{tx::PairSigner, OnlineClient};
use synedrion::{make_key_shares, TestSchemeParams};
use testing_utils::{constants::X25519_PUBLIC_KEYS, substrate_context::testing_context};
use x25519_dalek::PublicKey;

use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    get_signer,
    helpers::{
        launch::{
            setup_mnemonic, Configuration, DEFAULT_BOB_MNEMONIC, DEFAULT_ENDPOINT, DEFAULT_MNEMONIC,
        },
        signing::SignatureState,
        substrate::{get_subgroup, make_register},
    },
    new_user,
    r#unsafe::api::{delete, get, put, remove_keys},
    sign_tx,
    signing_client::{
        api::{drain, get_signature, new_party, subscribe_to_me},
        SignerState,
    },
    store_tx,
    user::UserInputPartyInfo,
    validation::SignedMessage,
    validator::api::sync_kvdb,
};

pub async fn setup_client() -> Client {
    Client::tracked(crate::rocket().await).await.expect("valid `Rocket`")
}

pub async fn create_clients(
    port: i64,
    key_number: String,
    values: Vec<Vec<u8>>,
    keys: Vec<String>,
    is_alice: bool,
    is_bob: bool,
) -> (Rocket<Ignite>, KvManager) {
    let config = rocket::Config::figment().merge(("port", port));

    let signer_state = SignerState::default();
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());
    let signature_state = SignatureState::new();

    let path = format!(".entropy/testing/test_db_{key_number}");
    let _ = std::fs::remove_dir_all(path.clone());

    let kv_store =
        KvManager::new(path.into(), PasswordMethod::NoPassword.execute().unwrap()).unwrap();
    let _ = setup_mnemonic(&kv_store, is_alice, is_bob).await;

    for (i, value) in values.into_iter().enumerate() {
        let reservation = kv_store.clone().kv().reserve_key(keys[i].to_string()).await.unwrap();
        let _ = kv_store.clone().kv().put(reservation, value).await;
    }

    // Unsafe routes are for testing purposes only
    // they are unsafe as they can expose vulnerabilites
    // should they be used in production. Unsafe routes
    // are disabled by default.
    // To enable unsafe routes compile with --feature unsafe.
    let mut unsafe_routes = routes![];
    if cfg!(feature = "unsafe") || cfg!(test) {
        unsafe_routes = routes![remove_keys, get, put, delete];
    }

    let result = rocket::custom(config)
        .mount("/validator", routes![sync_kvdb])
        .mount("/signer", routes![new_party, subscribe_to_me, get_signature, drain])
        .mount("/user", routes![store_tx, new_user, sign_tx])
        .mount("/unsafe", unsafe_routes)
        .manage(signer_state)
        .manage(configuration)
        .manage(kv_store.clone())
        .manage(signature_state)
        .ignite()
        .await
        .unwrap();

    (result, kv_store)
}

pub async fn spawn_testing_validators() -> (Vec<String>, Vec<PartyId>) {
    // spawn threshold servers
    let ports = vec![3001i64, 3002];

    let (alice_rocket, alice_kv) =
        create_clients(ports[0], "validator1".to_string(), vec![], vec![], true, false).await;
    let alice_id = PartyId::new(get_signer(&alice_kv).await.unwrap().account_id().clone());

    let (bob_rocket, bob_kv) =
        create_clients(ports[1], "validator2".to_string(), vec![], vec![], false, true).await;
    let bob_id = PartyId::new(get_signer(&bob_kv).await.unwrap().account_id().clone());

    tokio::spawn(async move { alice_rocket.launch().await.unwrap() });
    tokio::spawn(async move { bob_rocket.launch().await.unwrap() });
    tokio::time::sleep(Duration::from_secs(1)).await;

    let ips = ports.iter().map(|port| format!("127.0.0.1:{}", port)).collect();
    let ids = vec![alice_id, bob_id];
    (ips, ids)
}

/// Registers a new user on-chain, sends test threshold keys to to the server, and sets their
/// initial constraints. This leaves the user in a state of "Registered", ready to submit
/// transaction requests.
pub async fn register_user(
    entropy_api: &OnlineClient<EntropyConfig>,
    threshold_servers: &[String],
    sig_req_keyring: &Sr25519Keyring,
    constraint_modification_account: &Sr25519Keyring,
    initial_constraints: Constraints,
    party_ids: &[PartyId],
) {
    let validator1_server_public_key = PublicKey::from(X25519_PUBLIC_KEYS[0]);
    let validator2_server_public_key = PublicKey::from(X25519_PUBLIC_KEYS[1]);

    let shares = make_key_shares::<TestSchemeParams>(&mut OsRng, 2, None);

    let party_ids: Vec<AccountId32> = party_ids
        .into_iter()
        .map(|party_id| {
            let p: [u8; 32] =
                hex::decode(String::from(party_id.clone())).unwrap().try_into().unwrap();
            p.into()
        })
        .collect();

    let validator_1_user_input_party_info = UserInputPartyInfo {
        key_share: kvdb::kv_manager::helpers::serialize(&shares[0]).unwrap(),
        party_ids: party_ids.clone(),
    };

    let validator_1_threshold_keyshare: Vec<u8> =
        serde_json::to_string(&validator_1_user_input_party_info).unwrap().into_bytes();

    let validator_2_user_input_party_info = UserInputPartyInfo {
        key_share: kvdb::kv_manager::helpers::serialize(&shares[1]).unwrap(),
        party_ids: party_ids.clone(),
    };

    let validator_2_threshold_keyshare: Vec<u8> =
        serde_json::to_string(&validator_2_user_input_party_info).unwrap().into_bytes();

    let register_body_alice_validator = SignedMessage::new(
        &sig_req_keyring.pair(),
        &Bytes(validator_1_threshold_keyshare),
        &validator1_server_public_key,
    )
    .unwrap()
    .to_json();
    let register_body_bob_validator = SignedMessage::new(
        &sig_req_keyring.pair(),
        &Bytes(validator_2_threshold_keyshare),
        &validator2_server_public_key,
    )
    .unwrap()
    .to_json();

    // call register() on-chain
    make_register(entropy_api, sig_req_keyring, &constraint_modification_account.to_account_id())
        .await;

    // send threshold keys to server
    let bodies = vec![register_body_alice_validator, register_body_bob_validator];
    let new_user_server_res =
        join_all(threshold_servers.iter().zip(bodies).map(|(ip_port, body)| {
            let client = reqwest::Client::new();
            let url = format!("http://{}/user/new", ip_port.clone());
            client.post(url).header("Content-Type", "application/json").body(body).send()
        }))
        .await;
    new_user_server_res.into_iter().for_each(|response| {
        assert_eq!(response.unwrap().status(), 200);
    });

    // confirm that user is Registered
    check_registered_status(entropy_api, sig_req_keyring).await;

    // update/set their constraints
    let update_constraints_tx = entropy::tx()
        .constraints()
        .update_constraints(sig_req_keyring.to_account_id(), initial_constraints);

    let constraint_modification_account = PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(
        constraint_modification_account.pair(),
    );

    entropy_api
        .tx()
        .sign_and_submit_then_watch_default(
            &update_constraints_tx,
            &constraint_modification_account,
        )
        .await
        .unwrap()
        .wait_for_in_block()
        .await
        .unwrap()
        .wait_for_success()
        .await
        .unwrap();
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

/// Verify that a Registering account has 1 confirmation, and that it is not already Registered.
pub async fn check_if_confirmation(api: &OnlineClient<EntropyConfig>, key: &Sr25519Keyring) {
    let registering_query = entropy::storage().relayer().registering(key.to_account_id());
    let registered_query = entropy::storage().relayer().registered(key.to_account_id());
    let is_registering = api.storage().fetch(&registering_query, None).await.unwrap();
    // make sure there is one confirmation
    assert_eq!(is_registering.unwrap().confirmations.len(), 1);
    let _ = api.storage().fetch(&registered_query, None).await.unwrap();
}

/// Verify that a Registered account exists.
pub async fn check_registered_status(api: &OnlineClient<EntropyConfig>, key: &Sr25519Keyring) {
    let registered_query = entropy::storage().relayer().registered(key.to_account_id());
    api.storage().fetch(&registered_query, None).await.unwrap();
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

pub fn create_user_input_party_info() -> UserInputPartyInfo {
    let shares = make_key_shares::<TestSchemeParams>(&mut OsRng, 2, None);
    let key_share: Vec<u8> = kvdb::kv_manager::helpers::serialize(&shares[0]).unwrap();
    let party_ids: Vec<AccountId32> = vec![
        hex_literal::hex!["be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f"]
            .into(),
        hex_literal::hex!["8676839ca1e196624106d17c56b1efbb90508a86d8053f7d4fcd21127a9f7565"]
            .into(),
    ];
    UserInputPartyInfo { key_share, party_ids }
}
