use bip39::{Language, Mnemonic};
use entropy_shared::MIN_BALANCE;
use hex_literal::hex;
use kvdb::{clean_tests, encrypted_sled::PasswordMethod, kv_manager::value::KvManager};
use rocket::{http::ContentType, Ignite, Rocket};
use serial_test::serial;
use sp_core::{crypto::AccountId32, sr25519, Pair};
use subxt::tx::PairSigner;
use testing_utils::context::test_context;
use x25519_dalek::PublicKey;

use super::api::{
    check_balance_for_fees, get_all_keys, get_and_store_values, get_random_server_info, sync_kvdb,
    tell_chain_syncing_is_done, Keys,
};
use crate::{
    chain_api::{get_api, EntropyConfig},
    helpers::{
        launch::{
            setup_mnemonic, Configuration, DEFAULT_BOB_MNEMONIC, DEFAULT_ENDPOINT, DEFAULT_MNEMONIC,
        },
        signing::SignatureState,
        tests::setup_client,
        validator::get_subgroup,
    },
    message::{derive_static_secret, mnemonic_to_pair, new_mnemonic, to_bytes, SignedMessage},
    new_user,
    signing_client::SignerState,
    store_tx,
};

#[rocket::async_test]
#[serial]
async fn test_sync_kvdb() {
    clean_tests();
    let client = setup_client().await;

    let response = client.post("/validator/sync_kvdb").header(ContentType::JSON).dispatch().await;

    dbg!(response);
    clean_tests();
}

#[rocket::async_test]
async fn test_get_all_keys() {
    clean_tests();
    let cxt = test_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();

    let mut result = get_all_keys(&api, 3).await.unwrap();
    let mut result_2 = get_all_keys(&api, 5).await.unwrap();
    let mut result_3 = get_all_keys(&api, 1).await.unwrap();
    let mut result_4 = get_all_keys(&api, 6).await.unwrap();

    let mut expected_results = vec![
        "5CiPPseXPECbkjWCa6MnjNokrgYjMqmKndv2rSnekmSK2DjL",
        "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy",
        "5HGjWAeFDfFCWPsjFQdVV2Msvz2XtMktvgocEZcCj68kUMaw",
    ];
    result.sort();
    expected_results.sort();
    result_2.sort();
    result_3.sort();
    result_4.sort();

    assert_eq!(result, expected_results);
    assert_eq!(result_2, expected_results);
    assert_eq!(result_3, expected_results);
    assert_eq!(result_4, expected_results);
    clean_tests();
}

#[rocket::async_test]
#[should_panic]
async fn test_get_all_keys_fail() {
    clean_tests();
    let cxt = test_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let _ = get_all_keys(&api, 0).await.unwrap();
    clean_tests();
}

#[rocket::async_test]
#[serial]
async fn test_get_no_safe_crypto_error() {
    clean_tests();

    let addrs = vec![
        "5CiPPseXPECbkjWCa6MnjNokrgYjMqmKndv2rSnekmSK2DjL".to_string(),
        "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy".to_string(),
        "5HGjWAeFDfFCWPsjFQdVV2Msvz2XtMktvgocEZcCj68kUMaw".to_string(),
    ];

    let a_usr_sk = mnemonic_to_pair(&new_mnemonic());
    let a_usr_ss = derive_static_secret(&a_usr_sk);
    let sender = PublicKey::from(&a_usr_ss).to_bytes();

    let b_usr_sk =
        mnemonic_to_pair(&Mnemonic::from_phrase(DEFAULT_BOB_MNEMONIC, Language::English).unwrap());
    let b_usr_ss = derive_static_secret(&b_usr_sk);
    let recip = PublicKey::from(&b_usr_ss);
    let values = vec![vec![10], vec![11], vec![12]];
    let mut enckeys: Vec<SignedMessage> = vec![];
    for addr in &addrs {
        enckeys.push(SignedMessage::new(&a_usr_sk, &to_bytes(addr.as_bytes()), &recip).unwrap());
    }

    let keys = Keys { enckeys, sender };
    let port = 3001;
    let client1 = create_clients(port, "bob".to_string(), values, addrs, false, true).await;
    tokio::spawn(async move { client1.0.launch().await.unwrap() });

    let client = reqwest::Client::new();
    let formatted_url = format!("http://127.0.0.1:{port}/validator/sync_kvdb");
    let result = client
        .post(formatted_url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&keys).unwrap())
        .send()
        .await
        .unwrap();

    // Validates that keys signed/encrypted to the correct key
    // return no error (status code 200).
    assert_eq!(result.status(), 200);
    clean_tests();
}

#[rocket::async_test]
#[serial]
async fn test_get_safe_crypto_error() {
    clean_tests();

    let addrs: Vec<&[u8]> = vec![
        "5CiPPseXPECbkjWCa6MnjNokrgYjMqmKndv2rSnekmSK2DjL".as_bytes(),
        "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy".as_bytes(),
        "5HGjWAeFDfFCWPsjFQdVV2Msvz2XtMktvgocEZcCj68kUMaw".as_bytes(),
    ];

    let a_usr_sk = mnemonic_to_pair(&new_mnemonic());
    let a_usr_ss = derive_static_secret(&a_usr_sk);
    let sender = PublicKey::from(&a_usr_ss).to_bytes();

    let b_usr_sk = mnemonic_to_pair(&new_mnemonic());
    let b_usr_ss = derive_static_secret(&b_usr_sk);
    let recip = PublicKey::from(&b_usr_ss);

    let mut enckeys: Vec<SignedMessage> = vec![];
    for addr in addrs {
        enckeys.push(SignedMessage::new(&a_usr_sk, &to_bytes(addr), &recip).unwrap());
    }

    let keys = Keys { enckeys, sender };
    let port = 3001;
    let client1 = create_clients(port, "bob".to_string(), vec![], vec![], false, true).await;
    tokio::spawn(async move { client1.0.launch().await.unwrap() });

    let client = reqwest::Client::new();
    let formatted_url = format!("http://127.0.0.1:{port}/validator/sync_kvdb");
    let result = client
        .post(formatted_url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&keys).unwrap())
        .send()
        .await
        .unwrap();

    // Validates that keys signed/encrypted to a different key
    // than the validator server return with a 500 error.
    assert_eq!(result.status(), 500);
    clean_tests();
}

#[rocket::async_test]
#[serial]
async fn test_get_and_store_values() {
    clean_tests();
    let cxt = test_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let p_alice = <sr25519::Pair as Pair>::from_string(DEFAULT_MNEMONIC, None).unwrap();
    let signer_alice = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_alice);
    let my_subgroup = get_subgroup(&api, &signer_alice).await.unwrap().unwrap();
    let server_info = get_random_server_info(&api, my_subgroup).await.unwrap();
    let recip_key = x25519_dalek::PublicKey::from(server_info.x25519_public_key);
    let keys = vec![
        "5CiPPseXPECbkjWCa6MnjNokrgYjMqmKndv2rSnekmSK2DjL".to_string(),
        "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy".to_string(),
        "5HGjWAeFDfFCWPsjFQdVV2Msvz2XtMktvgocEZcCj68kUMaw".to_string(),
    ];
    let port_0 = 3002;
    let port_1 = 3003;
    let values = vec![vec![10], vec![11], vec![12]];
    // Construct a client to use for dispatching requests.
    let client0 =
        create_clients(port_0, "alice".to_string(), values.clone(), keys.clone(), true, false)
            .await;
    let client1 =
        create_clients(port_1, "bob".to_string(), vec![], keys.clone(), false, true).await;

    tokio::spawn(async move { client0.0.launch().await.unwrap() });
    tokio::spawn(async move { client1.0.launch().await.unwrap() });
    let _result = get_and_store_values(
        keys.clone(),
        &client1.1,
        "127.0.0.1:3002".to_string(),
        9,
        false,
        &recip_key,
    )
    .await;
    for (i, key) in keys.iter().enumerate() {
        println!("!! -> -> RECEIVED KEY at IDX {} of value {:?}", i, key);
        let val = client1.1.kv().get(key).await;
        assert!(val.is_ok());
        assert_eq!(val.unwrap(), values[i]);
    }
    clean_tests();
}

#[rocket::async_test]
async fn test_get_random_server_info() {
    clean_tests();
    let cxt = test_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let p_alice = <sr25519::Pair as Pair>::from_string(DEFAULT_MNEMONIC, None).unwrap();
    let signer_alice = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_alice);
    let my_subgroup = get_subgroup(&api, &signer_alice).await.unwrap().unwrap();

    let result = get_random_server_info(&api, my_subgroup).await.unwrap();

    assert_eq!("127.0.0.1:3001".as_bytes().to_vec(), result.endpoint);
    clean_tests();
}

#[rocket::async_test]
#[should_panic = "Account does not exist, add balance"]
async fn test_check_balance_for_fees() {
    clean_tests();
    let cxt = test_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let alice_stash_address: AccountId32 =
        hex!["be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f"].into();
    let result = check_balance_for_fees(&api, &alice_stash_address, MIN_BALANCE).await.unwrap();

    assert!(result);

    let result_2 = check_balance_for_fees(&api, &alice_stash_address, 10000000000000000000000u128)
        .await
        .unwrap();
    assert!(!result_2);

    let random_account: AccountId32 =
        hex!["8676839ca1e196624106d17c56b1efbb90508a86d8053f7d4fcd21127a9f7565"].into();
    let _ = check_balance_for_fees(&api, &random_account, MIN_BALANCE).await.unwrap();
    clean_tests();
}

#[rocket::async_test]
#[should_panic = "called `Result::unwrap()` on an `Err` value: \
                  GenericSubstrate(Runtime(Module(ModuleError { pallet: \"StakingExtension\", \
                  error: \"NoThresholdKey\", description: [], error_data: ModuleErrorData { \
                  pallet_index: 12, error: [3, 0, 0, 0] } })))"]
async fn test_tell_chain_syncing_is_done() {
    clean_tests();
    let cxt = test_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let p_alice = <sr25519::Pair as Pair>::from_string("//Alice", None).unwrap();
    let signer_alice = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_alice);

    // expect this to fail in the proper way
    tell_chain_syncing_is_done(&api, &signer_alice).await.unwrap();
}

async fn create_clients(
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

    let result = rocket::custom(config)
        .mount("/validator", routes![sync_kvdb])
        .mount("/user", routes![new_user, store_tx])
        .manage(signer_state)
        .manage(configuration)
        .manage(kv_store.clone())
        .manage(signature_state)
        .ignite()
        .await
        .unwrap();

    (result, kv_store)
}
