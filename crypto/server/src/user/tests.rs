use std::{env, fs, path::PathBuf};

use bip39::{Language, Mnemonic, MnemonicType};
use entropy_constraints::{Architecture, Evm, Parse};
use entropy_shared::{Message, OCWMessage, SigRequest};
use ethers_core::{
    types::{Address, TransactionRequest}
};
use futures::{Future, join};
use hex_literal::hex as h;
use kvdb::{clean_tests, encrypted_sled::PasswordMethod, kv_manager::value::KvManager};
use rocket::{
    http::{ContentType, Status},
    tokio::time::{sleep, Duration},
    Ignite, Rocket,
};
use serial_test::serial;
use sp_core::{sr25519, Bytes, Pair, H160};
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{ext::sp_runtime::AccountId32, tx::PairSigner, OnlineClient};
use testing_utils::context::{test_context, test_context_stationary, TestContext};
use x25519_dalek::{PublicKey, StaticSecret};
use parity_scale_codec::Encode;

use super::UserInputPartyInfo;
use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    drain, get_signature, get_signer,
    helpers::{
        launch::{
            setup_mnemonic, Configuration, DEFAULT_BOB_MNEMONIC, DEFAULT_ENDPOINT, DEFAULT_MNEMONIC,
        },
        signing::SignatureState,
        tests::setup_client,
    },
    load_kv_store,
    message::{derive_static_secret, mnemonic_to_pair, new_mnemonic, SignedMessage},
    new_party, new_user, store_tx,
    r#unsafe::api::{delete, get, put, remove_keys},
    r#unsafe::api::UnsafeQuery,
    signing_client::SignerState,
    subscribe_to_me,
    validator::api::get_random_server_info,
    Message as SigMessage,
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


/// TODO
/// setup mock ocw data via /new_party
/// kickoff /tx with mock client
/// validate that sighash is signed and returned
/// validate sighash was drained
/// validate that sighash was stored in kvdb
#[rocket::async_test]
#[serial]
async fn test_unsigned_tx_endpoint() {
    clean_tests();

    // setup mock client data
    let whitelisted_addresses = vec![Address::from([1u8; 20]), Address::from([2u8; 20])];
    let alice_transaction_request = 
        TransactionRequest::new()
            .to(whitelisted_addresses[0])
            .value(1);
    let bob_transaction_request =
        TransactionRequest::new()
            .to(whitelisted_addresses[1])
            .value(5);
    let alice_req_body = serde_json::json!({
        "arch": "evm",
        "transaction_request": alice_transaction_request.rlp_unsigned().to_string(),
    });
    let bob_req_body = serde_json::json!({
        "arch": "evm",
        "transaction_request": bob_transaction_request.rlp_unsigned().to_string(),
    });
   

    // spin up 2 threshold servers
    let port_0 = 3001;
    // let validator_1_url = format!("http://127.0.0.1:{}", port_0);
    let port_1 = 3002;
    // let validator_2_url = format!("http://127.0.0.1:{}", port_1);

    // let ports = vec![3001i64, 3002];
    // let validator_urls: Vec<String> = ports.iter().map(|port| format!("http://127.0.0.1:{}", port)).collect();

    // Construct a client to use for dispatching requests.
    let client0 = create_clients(port_0, "0".to_string()).await;
    let client1 = create_clients(port_1, "1".to_string()).await;
    // let clients = join_all(ports.iter().map(|port| create_clients(*port, "0".to_string())).collect()).await;
    tokio::spawn(async move { client0.launch().await.unwrap() });
    tokio::spawn(async move { client1.launch().await.unwrap() });
    // let spawns = join_all(clients.iter().map(|client: &Rocket<Ignite>| client.launch()).collect()).await;

    // Unfortunately, we cannot get a notification when a Rocket server has finished starting up,
    // so we will give them a second for that.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let ip_addresses: Vec<Vec<u8>> = vec![b"127.0.0.1:3001".to_vec(), b"127.0.0.1:3002".to_vec()];
    let raw_messages = vec![
        Message {
            sig_request: SigRequest { sig_hash: alice_transaction_request.sighash().as_bytes().to_vec() },
            account: AccountKeyring::Alice.to_raw_public_vec(),
            ip_addresses: ip_addresses.clone(),
        },
        // TODO test bob client
        Message {
            sig_request: SigRequest { sig_hash: bob_transaction_request.sighash().as_bytes().to_vec() },
            account: AccountKeyring::Bob.to_raw_public_vec(),
            ip_addresses,
        },
    ];
    let messages: Vec<u8> = raw_messages.encode();

    let mock_ocw = reqwest::Client::new();

    let url = format!("http://127.0.0.1:{port_0}/signer/new_party");
    let mock_ocw_response = mock_ocw.post(url).body(messages.clone()).send().await;
    assert_eq!(mock_ocw_response.unwrap().status(), 200);

    let url = format!("http://127.0.0.1:{port_1}/signer/new_party");
    let mock_ocw_response = mock_ocw.post(url).body(messages).send().await;
    assert_eq!(mock_ocw_response.unwrap().status(), 200);

    let handle = tokio::spawn(async move {
        let mock_client = reqwest::Client::new();

        // client requests server to sign the sighash
        let alice_sig_req_response1= mock_client
            .post("http://127.0.0.1:3001/user/tx")
            .header("Content-Type", "application/json")
            .body(alice_req_body.to_string())
            .send();

        let alice_sig_req_response2= mock_client
            .post("http://127.0.0.1:3002/user/tx")
            .header("Content-Type", "application/json")
            .body(alice_req_body.to_string())
            .send();

        let (alice_sig_req_response1, alice_sig_req_response2)= join!(alice_sig_req_response1, alice_sig_req_response2);

        assert_eq!(alice_sig_req_response1.unwrap().status(), 200);
        assert_eq!(alice_sig_req_response2.unwrap().status(), 200);
    });


    handle.await.unwrap();

    let handle2 = tokio::spawn(async move {
        let mock_client = reqwest::Client::new();

        // client requests server to sign the sighash
        let bob_sig_req_response1= mock_client
            .post("http://127.0.0.1:3001/user/tx")
            .header("Content-Type", "application/json")
            .body(bob_req_body.to_string())
            .send();

        let bob_sig_req_response2= mock_client
            .post("http://127.0.0.1:3002/user/tx")
            .header("Content-Type", "application/json")
            .body(bob_req_body.to_string())
            .send();

        let (bob_sig_req_response1, bob_sig_req_response2)= join!(bob_sig_req_response1, bob_sig_req_response2);
        let bob_res1 = bob_sig_req_response1.unwrap();
        let bob_res2 = bob_sig_req_response2.unwrap();

        assert_eq!(bob_res1.status(), 200);
        assert_eq!(bob_res2.status(), 200);
    });

    handle2.await.unwrap();
    // let (handle1, handle2) = join!(handle, handle2);

    let mock_client = reqwest::Client::new();

    // all of this can be removed
    let alice_get_sig_message =
        SigMessage { message: hex::encode(raw_messages[0].sig_request.sig_hash.clone()) };
    let bob_get_sig_message =
        SigMessage { message: hex::encode(raw_messages[1].sig_request.sig_hash.clone()) };
    // JH what does this do?
    // after the signing is completed, client can get it at /signer/signature
    let alice_get_sig_response = mock_client
        .post("http://127.0.0.1:3001/signer/signature")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&alice_get_sig_message).unwrap())
        .send()
        .await;
    assert_eq!(alice_get_sig_response.as_ref().unwrap().status(), 202);
    assert_eq!(alice_get_sig_response.unwrap().text().await.unwrap().len(), 88);

    // JH what does this do?
    // after the signing is completed, client can get it at /signer/signature
    let bob_get_sig_response = mock_client
        .post("http://127.0.0.1:3001/signer/signature")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&bob_get_sig_message).unwrap())
        .send()
        .await;
    assert_eq!(bob_get_sig_response.as_ref().unwrap().status(), 202);
    assert_eq!(bob_get_sig_response.unwrap().text().await.unwrap().len(), 88);

    // client requests server delete the signature
    let delete_signatures_respose = mock_client.get("http://127.0.0.1:3001/signer/drain").send().await;
    assert_eq!(delete_signatures_respose.unwrap().status(), 200);
    let delete_signatures_respose = mock_client.get("http://127.0.0.1:3002/signer/drain").send().await;
    assert_eq!(delete_signatures_respose.unwrap().status(), 200);

    // query the signature again, should error since we just deleted it
    let alice_sig_req_response = mock_client
        .post("http://127.0.0.1:3001/signer/signature")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&alice_get_sig_message).unwrap())
        .send()
        .await;

    let bob_sig_req_response = mock_client
        .post("http://127.0.0.1:3002/signer/signature")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&bob_get_sig_message).unwrap())
        .send()
        .await;

    assert_eq!(alice_sig_req_response.unwrap().status(), 500);
    assert_eq!(bob_sig_req_response.unwrap().status(), 500);

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

async fn create_clients(port: i64, key_number: String) -> Rocket<Ignite> {
    let config = rocket::Config::figment().merge(("port", port));

    let signer_state = SignerState::default();
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());
    let signature_state = SignatureState::new();

    let path = format!("test_db_{key_number}");
    let _ = std::fs::remove_dir_all(path.clone());

    let kv_store =
        KvManager::new(path.into(), PasswordMethod::NoPassword.execute().unwrap()).unwrap();

    // Shortcut: store the shares manually
    let root = project_root::get_project_root().unwrap();
    let share_id = i32::from(port != 3001);
    let path: PathBuf =
        [root, "test_data".into(), "key_shares".into(), share_id.to_string().into()]
            .into_iter()
            .collect();
    let v_serialized = fs::read(path).unwrap();
    let alice_key = AccountKeyring::Alice.to_account_id();
    let bob_key = AccountKeyring::Bob.to_account_id();
    let alice_reservation = kv_store.kv().reserve_key(alice_key.to_string()).await.unwrap();
    let bob_reservation = kv_store.kv().reserve_key(bob_key.to_string()).await.unwrap();
    // alice and bob reuse the same keyshares for testing
    let _ = kv_store.kv().put(alice_reservation, v_serialized.clone()).await;
    let _ = kv_store.kv().put(bob_reservation, v_serialized).await;


    // Unsafe routes are for testing purposes only
    // they are unsafe as they can expose vulnerabilites
    // should they be used in production. Unsafe routes
    // are disabled by default.
    // To enable unsafe routes compile with --feature unsafe.
    let mut unsafe_routes = routes![];
    if cfg!(feature = "unsafe") || cfg!(test) {
        unsafe_routes = routes![remove_keys, get, put, delete];
    }

    rocket::custom(config)
        .mount("/signer", routes![new_party, subscribe_to_me, get_signature, drain])
        .mount("/user", routes![store_tx, new_user])
        .mount("/unsafe", unsafe_routes)
        .manage(signer_state)
        .manage(configuration)
        .manage(kv_store)
        .manage(signature_state)
        .ignite()
        .await
        .unwrap()
}
