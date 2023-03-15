use std::{env, fs, path::PathBuf, sync::Arc};

use entropy_shared::{Acl, Constraints};
use futures::future::join_all;
use hex_literal::hex as h;
use kvdb::{clean_tests, encrypted_sled::PasswordMethod, kv_manager::value::KvManager};
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
use sp_core::{sr25519, Bytes, Pair, H160, H256};
use sp_keyring::Sr25519Keyring;
use subxt::{ext::sp_runtime::AccountId32, tx::PairSigner, Error as SubxtError, OnlineClient};
use testing_utils::substrate_context::testing_context;
use x25519_dalek::PublicKey;

use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    helpers::{
        launch::{
            setup_mnemonic, Configuration, DEFAULT_BOB_MNEMONIC, DEFAULT_ENDPOINT, DEFAULT_MNEMONIC,
        },
        signing::SignatureState,
        substrate::{get_subgroup, make_register},
    },
    message::{derive_static_secret, mnemonic_to_pair, new_mnemonic, to_bytes, SignedMessage},
    new_user,
    r#unsafe::api::{delete, get, put, remove_keys, UnsafeQuery},
    signing_client::{
        api::{drain, get_signature, new_party, subscribe_to_me},
        SignerState,
    },
    store_tx,
    validator::api::{
        check_balance_for_fees, get_all_keys, get_and_store_values, get_random_server_info,
        sync_kvdb, tell_chain_syncing_is_done, Keys,
    },
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

    let path = format!("test_db_{key_number}");
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
        .mount("/user", routes![store_tx, new_user])
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

pub async fn spawn_testing_validators() -> Vec<String> {
    // spawn threshold servers
    let ports = vec![3001i64, 3002];

    let (alice_rocket, _) =
        create_clients(ports[0], "validator1".to_string(), vec![], vec![], true, false).await;
    let (bob_rocket, _) =
        create_clients(ports[1], "validator2".to_string(), vec![], vec![], false, true).await;
    tokio::spawn(async move { alice_rocket.launch().await.unwrap() });
    tokio::spawn(async move { bob_rocket.launch().await.unwrap() });
    tokio::time::sleep(Duration::from_secs(1)).await;

    ports.iter().map(|port| format!("127.0.0.1:{}", port)).collect()
}

// TODO move to helpers
fn get_test_keyshare_for_validator(index: i32) -> Vec<u8> {
    let root = project_root::get_project_root().unwrap();
    let path: PathBuf = [root, "test_data".into(), "key_shares".into(), index.to_string().into()]
        .into_iter()
        .collect();
    fs::read(path).unwrap()
}

/// Registers a new user on-chain and sends test threshold keys to to the server.
/// Should leave the user in a state of "Registered"
pub async fn register_user(
    entropy_api: &OnlineClient<EntropyConfig>,
    threshold_servers: &Vec<String>,
    sig_req_keyring: &Sr25519Keyring,
    constraint_modification_account: &Sr25519Keyring,
) {
    let validator_1_stash_id: AccountId32 =
        h!["be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f"].into(); // alice stash
    let validator_2_stash_id: AccountId32 =
        h!["fe65717dad0447d715f660a0a58411de509b42e6efb8375f562f58a554d5860e"].into(); // bob stash

    let query_alice_validator_keys =
        entropy::storage().staking_extension().threshold_servers(&validator_1_stash_id);
    let query_bob_validator_keys =
        entropy::storage().staking_extension().threshold_servers(&validator_2_stash_id);

    let alice_validator_keys =
        entropy_api.storage().fetch(&query_alice_validator_keys, None).await.unwrap().unwrap();
    let bob_validator_keys =
        entropy_api.storage().fetch(&query_bob_validator_keys, None).await.unwrap().unwrap();

    // assert!(alice_validator_keys.is_some());
    // assert!(bob_validator_keys.is_some());

    // let alice_validator_keys = alice_validator_keys.unwrap();
    let alice_server_public_key = PublicKey::from(alice_validator_keys.x25519_public_key);
    let bob_server_public_key = PublicKey::from(bob_validator_keys.x25519_public_key);
    // store empty value in server; just register
    let validator_1_threshold_keyshare: Vec<u8> = get_test_keyshare_for_validator(0);
    let validator_2_threshold_keyshare: Vec<u8> = get_test_keyshare_for_validator(1);

    let register_body_alice_validator = SignedMessage::new(
        &sig_req_keyring.pair(),
        &Bytes(validator_1_threshold_keyshare),
        &alice_server_public_key,
    )
    .unwrap()
    .to_json();
    let register_body_bob_validator = SignedMessage::new(
        &sig_req_keyring.pair(),
        &Bytes(validator_2_threshold_keyshare),
        &bob_server_public_key,
    )
    .unwrap()
    .to_json();

    let initial_constraints = {
        let mut evm_acl = Acl::<[u8; 20]>::default();
        evm_acl.addresses.push([1u8; 20]);

        Constraints { evm_acl: Some(evm_acl), ..Default::default() }
    };

    make_register(&entropy_api, &sig_req_keyring, &constraint_modification_account.to_account_id())
        .await;

    let bodies = vec![register_body_alice_validator, register_body_bob_validator];

    // let alice_response = threshold_servers[0].post("/user/new")
    //     .header(ContentType::JSON)
    //     .body(bodies.get(0).unwrap())
    //     .dispatch()
    //     .await;

    let responses = join_all(threshold_servers.iter().zip(bodies).map(|(ip_port, body)| {
        let client = reqwest::Client::new();
        let url = format!("http://{}/user/new", ip_port.clone());
        client.post(url).header("Content-Type", "application/json").body(body).send()
    }))
    .await;

    // assert_eq!(alice_response.status(), Status::Ok);
    responses.into_iter().for_each(|response| {
        assert_eq!(response.unwrap().status(), 200);
    });

    // let response_alice_tss = client
    //     .post("/user/new")
    //     .header(ContentType::JSON)
    //     .body(register_body_alice_validator.clone())
    //     .dispatch()
    //     .await;
    // assert_eq!(response_alice_tss.status(), 200);
    // assert_eq!(response_alice_tss.into_string().await, None);

    // let response_bob_tss = client
    //     .post("http://127.0.0.1:3002/user/new")
    //     // .header(ContentType::JSON)
    //     .body(register_body_bob_validator.clone())
    //     .send()
    //     .await.unwrap();
    // assert_eq!(response_bob_tss.status(), 200);
    // assert_eq!(response_bob_tss.into_string().await, None);

    // make sure there is now one confirmation
    check_registered_status(&entropy_api, &sig_req_keyring).await;

    // update their constraints
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
