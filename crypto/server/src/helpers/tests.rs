// only compile when testing
#![cfg(test)]

use std::{net::TcpListener, time::Duration};

use axum::{routing::IntoMakeService, Router};
use entropy_shared::KeyVisibility;
use futures::future::{self, join_all};
use kvdb::{
    clean_tests,
    encrypted_sled::PasswordMethod,
    get_db_path,
    kv_manager::{KvManager, PartyId},
};
use rand_core::OsRng;
use serial_test::serial;
use sp_core::crypto::AccountId32;
use subxt::{
    ext::sp_core::{
        sr25519::{self},
        Bytes, Pair,
    },
    tx::PairSigner,
    utils::AccountId32 as subxtAccountId32,
    OnlineClient,
};
use synedrion::{make_key_shares, sessions::PrehashedMessage, KeyShare, TestSchemeParams};
use testing_utils::{constants::X25519_PUBLIC_KEYS, substrate_context::testing_context};
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::connect_async;
use x25519_dalek::PublicKey;

use super::signing::RecoverableSignature;
use crate::{
    app,
    chain_api::{entropy, get_api, EntropyConfig},
    get_signer,
    helpers::{
        launch::{
            setup_mnemonic, Configuration, DEFAULT_BOB_MNEMONIC, DEFAULT_ENDPOINT, DEFAULT_MNEMONIC,
        },
        signing::SignatureState,
        substrate::{get_subgroup, make_register},
        tests::entropy::runtime_types::entropy_shared::constraints::Constraints,
    },
    signing_client::{
        new_party::{signing_protocol, Channels},
        protocol_transport::{
            listener::WsChannels, noise::noise_handshake_initiator, ws_to_channels, Broadcaster,
            WsConnection,
        },
        SignerState, SigningErr, SubscribeMessage,
    },
    user::api::ValidatorInfo,
    validation::SignedMessage,
    AppState,
};

pub async fn setup_client() {
    let kv_store =
        KvManager::new(get_db_path(true).into(), PasswordMethod::NoPassword.execute().unwrap())
            .unwrap();
    let _ = setup_mnemonic(&kv_store, true, false).await;

    let signer_state = SignerState::default();
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());
    let signature_state = SignatureState::new();
    let app_state = AppState { signer_state, configuration, kv_store, signature_state };
    let app = app(app_state).into_make_service();
    let listener = TcpListener::bind("0.0.0.0:3001").unwrap();

    tokio::spawn(async move {
        axum::Server::from_tcp(listener).unwrap().serve(app).await.unwrap();
    });
}

pub async fn create_clients(
    key_number: String,
    values: Vec<Vec<u8>>,
    keys: Vec<String>,
    is_alice: bool,
    is_bob: bool,
) -> (IntoMakeService<Router>, KvManager) {
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

    let app_state =
        AppState { signer_state, configuration, kv_store: kv_store.clone(), signature_state };

    let app = app(app_state).into_make_service();

    (app, kv_store)
}

pub async fn spawn_testing_validators() -> (Vec<String>, Vec<PartyId>) {
    // spawn threshold servers
    let ports = vec![3001i64, 3002];

    let (alice_axum, alice_kv) =
        create_clients("validator1".to_string(), vec![], vec![], true, false).await;
    let alice_id = PartyId::new(AccountId32::new(
        *get_signer(&alice_kv).await.unwrap().account_id().clone().as_ref(),
    ));

    let (bob_axum, bob_kv) =
        create_clients("validator2".to_string(), vec![], vec![], false, true).await;
    let bob_id = PartyId::new(AccountId32::new(
        *get_signer(&bob_kv).await.unwrap().account_id().clone().as_ref(),
    ));
    let listener_alice = TcpListener::bind(format!("0.0.0.0:{}", ports[0])).unwrap();
    let listener_bob = TcpListener::bind(format!("0.0.0.0:{}", ports[1])).unwrap();

    tokio::spawn(async move {
        axum::Server::from_tcp(listener_alice).unwrap().serve(alice_axum).await.unwrap();
    });

    tokio::spawn(async move {
        axum::Server::from_tcp(listener_bob).unwrap().serve(bob_axum).await.unwrap();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let ips = ports.iter().map(|port| format!("127.0.0.1:{}", port)).collect();
    let ids = vec![alice_id, bob_id];
    (ips, ids)
}

/// Registers a new user on-chain, sends test threshold keys to to the server, and sets their
/// initial constraints. This leaves the user in a state of "Registered", ready to submit
/// transaction requests.
///
/// If key visibility is private, this will return the user's key share to be used when testing
/// the user participating in the signing protocol.
pub async fn register_user(
    entropy_api: &OnlineClient<EntropyConfig>,
    threshold_servers: &[String],
    sig_req_keyring: &sr25519::Pair,
    constraint_modification_account: &sr25519::Pair,
    initial_constraints: Constraints,
    key_visibility: KeyVisibility,
) -> Option<Vec<u8>> {
    let validator1_server_public_key = PublicKey::from(X25519_PUBLIC_KEYS[0]);
    let validator2_server_public_key = PublicKey::from(X25519_PUBLIC_KEYS[1]);

    let number_of_shares = if key_visibility == KeyVisibility::Private { 3 } else { 2 };

    let shares = make_key_shares::<TestSchemeParams>(&mut OsRng, number_of_shares, None);
    let validator_1_threshold_keyshare: Vec<u8> =
        kvdb::kv_manager::helpers::serialize(&shares[0]).unwrap();
    let validator_2_threshold_keyshare: Vec<u8> =
        kvdb::kv_manager::helpers::serialize(&shares[1]).unwrap();

    let user_owned_keyshare = if key_visibility == KeyVisibility::Private {
        Some(kvdb::kv_manager::helpers::serialize(&shares[2]).unwrap())
    } else {
        None
    };

    let register_body_alice_validator = SignedMessage::new(
        &sig_req_keyring,
        &Bytes(validator_1_threshold_keyshare),
        &validator1_server_public_key,
    )
    .unwrap()
    .to_json();
    let register_body_bob_validator = SignedMessage::new(
        &sig_req_keyring,
        &Bytes(validator_2_threshold_keyshare),
        &validator2_server_public_key,
    )
    .unwrap()
    .to_json();

    // call register() on-chain
    make_register(
        entropy_api,
        sig_req_keyring.clone(),
        &subxtAccountId32::from(constraint_modification_account.public()),
        key_visibility,
    )
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
    check_registered_status(entropy_api, &subxtAccountId32::from(sig_req_keyring.public())).await;

    // update/set their constraints
    let update_constraints_tx = entropy::tx()
        .constraints()
        .update_constraints(subxtAccountId32::from(sig_req_keyring.public()), initial_constraints);

    let constraint_modification_account =
        PairSigner::<EntropyConfig, sr25519::Pair>::new(constraint_modification_account.clone());

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

    user_owned_keyshare
}

pub async fn make_swapping(api: &OnlineClient<EntropyConfig>, key: &sr25519::Pair) {
    let signer = PairSigner::<EntropyConfig, sr25519::Pair>::new(key.clone());
    let registering_query = entropy::storage().relayer().registering(signer.account_id());
    let is_registering_1 =
        api.storage().at_latest().await.unwrap().fetch(&registering_query).await.unwrap();
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

    let is_registering_2 = api.storage().at_latest().await.unwrap().fetch(&registering_query).await;
    assert!(is_registering_2.unwrap().unwrap().is_registering);
}

/// Verify that a Registering account has 1 confirmation, and that it is not already Registered.
pub async fn check_if_confirmation(api: &OnlineClient<EntropyConfig>, key: &sr25519::Pair) {
    let signer = PairSigner::<EntropyConfig, sr25519::Pair>::new(key.clone());
    let registering_query = entropy::storage().relayer().registering(signer.account_id());
    let registered_query = entropy::storage().relayer().registered(signer.account_id());
    let is_registering =
        api.storage().at_latest().await.unwrap().fetch(&registering_query).await.unwrap();
    // make sure there is one confirmation
    assert_eq!(is_registering.unwrap().confirmations.len(), 1);
    let _ = api.storage().at_latest().await.unwrap().fetch(&registered_query).await.unwrap();
}

/// Verify that a Registered account exists.
pub async fn check_registered_status(api: &OnlineClient<EntropyConfig>, key: &subxtAccountId32) {
    let registered_query = entropy::storage().relayer().registered(key);
    api.storage().at_latest().await.unwrap().fetch(&registered_query).await.unwrap();
}

#[tokio::test]
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

/// Called when KeyVisibility is private - the user connects to relevant validators
/// and participates in the signing protocol
pub async fn user_connects_to_validators(
    key_share: &KeyShare<TestSchemeParams>,
    sig_uid: &str,
    validators_info: Vec<ValidatorInfo>,
    user_signing_keypair: &sr25519::Pair,
    user_account_id: &AccountId32,
) -> Result<RecoverableSignature, SigningErr> {
    // Set up channels for communication between signing protocol and other signing parties
    let (tx, _rx) = broadcast::channel(1000);
    let (tx_to_others, rx_to_others) = mpsc::channel(1000);
    let tx_ref = &tx;
    let tx_to_others_ref = &tx_to_others;

    // Create a vec of futures which connect to the other parties over ws
    let connect_to_validators = validators_info
        .iter()
        .map(|validator_info| async move {
            // Open a ws connection
            let ws_endpoint = format!("ws://{}/ws", validator_info.ip_address);
            let (ws_stream, _response) = connect_async(ws_endpoint).await?;
            let ws_stream = WsConnection::WsStream(ws_stream);

            // Send a SubscribeMessage in the payload of the final handshake message
            let server_public_key = PublicKey::from(validator_info.x25519_public_key);
            let signed_message = SignedMessage::new(
                user_signing_keypair,
                &Bytes(serde_json::to_vec(&SubscribeMessage::new(
                    sig_uid,
                    PartyId::new(user_account_id.clone()),
                ))?),
                &server_public_key,
            )?;
            let subscribe_message_vec = serde_json::to_vec(&signed_message)?;

            let mut encrypted_connection = noise_handshake_initiator(
                ws_stream,
                user_signing_keypair,
                validator_info.x25519_public_key,
                subscribe_message_vec,
            )
            .await
            .unwrap();

            // Check the response as to whether they accepted our SubscribeMessage
            let response_message = encrypted_connection.recv().await.unwrap();

            let subscribe_response: Result<(), String> = serde_json::from_str(&response_message)?;
            if let Err(error_message) = subscribe_response {
                return Err(SigningErr::BadSubscribeMessage(error_message));
            }

            // Setup channels
            let ws_channels = WsChannels {
                broadcast: tx_ref.subscribe(),
                tx: tx_to_others_ref.clone(),
                is_final: false,
            };

            let remote_party_id = PartyId::new(validator_info.tss_account.clone());

            // Handle protocol messages in another task
            tokio::spawn(async move {
                if let Err(err) =
                    ws_to_channels(encrypted_connection, ws_channels, remote_party_id).await
                {
                    tracing::warn!("{:?}", err);
                };
            });

            Ok::<_, SigningErr>(())
        })
        .collect::<Vec<_>>();

    // Connect to validators
	future::try_join_all(connect_to_validators).await?;

    // Set up the signing protocol
    let channels = Channels(Broadcaster(tx_ref.clone()), rx_to_others);
    let tss_accounts = validators_info.iter().map(|v| v.tss_account.clone()).collect();
    let digest: PrehashedMessage = hex::decode(sig_uid)?
        .try_into()
        .map_err(|_| SigningErr::Conversion("Digest Conversion"))?;

    // Execute the signing protocol
    let rsig = signing_protocol::execute_protocol(
        channels,
        key_share,
        &digest,
        user_signing_keypair,
        tss_accounts,
    )
    .await?;

	// Return a signature if everything went well
    let (signature, recovery_id) = rsig.to_backend();
    Ok(RecoverableSignature { signature, recovery_id })
}
