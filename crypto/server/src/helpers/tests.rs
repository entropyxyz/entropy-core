// only compile when testing
#![cfg(test)]

use std::{net::TcpListener, time::Duration};

use axum::{routing::IntoMakeService, Router};
use entropy_shared::KeyVisibility;
use futures::future;
use kvdb::{
    clean_tests,
    encrypted_sled::PasswordMethod,
    get_db_path,
    kv_manager::{KeyParams, KvManager, PartyId},
};
use rand_core::OsRng;
use serial_test::serial;
use sp_core::crypto::AccountId32;
use subxt::{
    ext::sp_core::{sr25519, Pair},
    tx::PairSigner,
    utils::{AccountId32 as subxtAccountId32, Static},
    OnlineClient,
};
use synedrion::KeyShare;
use testing_utils::substrate_context::testing_context;
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::connect_async;

use super::signing::RecoverableSignature;
use crate::{
    app,
    chain_api::{entropy, get_api, EntropyConfig},
    get_signer,
    helpers::{
        launch::{
            setup_latest_block_number, setup_mnemonic, Configuration, DEFAULT_BOB_MNEMONIC,
            DEFAULT_ENDPOINT, DEFAULT_MNEMONIC,
        },
        signing::SignatureState,
        substrate::get_subgroup,
    },
    signing_client::{
        protocol_execution::{execute_protocol, Channels},
        protocol_transport::{
            listener::WsChannels, noise::noise_handshake_initiator, ws_to_channels, Broadcaster,
        },
        ListenerState, ProtocolErr, SubscribeMessage,
    },
    user::api::ValidatorInfo,
    AppState,
};

pub async fn setup_client() {
    let kv_store =
        KvManager::new(get_db_path(true).into(), PasswordMethod::NoPassword.execute().unwrap())
            .unwrap();
    let _ = setup_mnemonic(&kv_store, true, false).await;
    let _ = setup_latest_block_number(&kv_store).await;
    let listener_state = ListenerState::default();
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());
    let signature_state = SignatureState::new();
    let app_state = AppState { listener_state, configuration, kv_store, signature_state };
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
    let listener_state = ListenerState::default();
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());
    let signature_state = SignatureState::new();

    let path = format!(".entropy/testing/test_db_{key_number}");
    let _ = std::fs::remove_dir_all(path.clone());

    let kv_store =
        KvManager::new(path.into(), PasswordMethod::NoPassword.execute().unwrap()).unwrap();
    let _ = setup_mnemonic(&kv_store, is_alice, is_bob).await;
    let _ = setup_latest_block_number(&kv_store).await;

    for (i, value) in values.into_iter().enumerate() {
        let reservation = kv_store.clone().kv().reserve_key(keys[i].to_string()).await.unwrap();
        let _ = kv_store.clone().kv().put(reservation, value).await;
    }

    let app_state =
        AppState { listener_state, configuration, kv_store: kv_store.clone(), signature_state };

    let app = app(app_state).into_make_service();

    (app, kv_store)
}

pub async fn spawn_testing_validators(
    sig_req_keyring: Option<String>,
    // If this is true a keyshare for the user will be generated and returned
    private_key_visibility: bool,
) -> (Vec<String>, Vec<PartyId>, Option<KeyShare<KeyParams>>) {
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

    let user_keyshare_option = if sig_req_keyring.is_some() {
        let number_of_shares = if private_key_visibility { 3 } else { 2 };
        let shares = KeyShare::<KeyParams>::new_centralized(&mut OsRng, number_of_shares, None);
        let validator_1_threshold_keyshare: Vec<u8> =
            kvdb::kv_manager::helpers::serialize(&shares[0]).unwrap();
        let validator_2_threshold_keyshare: Vec<u8> =
            kvdb::kv_manager::helpers::serialize(&shares[1]).unwrap();
        // add key share to kvdbs
        let alice_reservation =
            alice_kv.kv().reserve_key(sig_req_keyring.clone().unwrap()).await.unwrap();
        alice_kv.kv().put(alice_reservation, validator_1_threshold_keyshare).await.unwrap();

        let bob_reservation =
            bob_kv.kv().reserve_key(sig_req_keyring.clone().unwrap()).await.unwrap();
        bob_kv.kv().put(bob_reservation, validator_2_threshold_keyshare).await.unwrap();

        if private_key_visibility {
            Some(shares[2].clone())
        } else {
            None
        }
    } else {
        None
    };

    let listener_alice = TcpListener::bind(format!("0.0.0.0:{}", ports[0])).unwrap();
    let listener_bob = TcpListener::bind(format!("0.0.0.0:{}", ports[1])).unwrap();
    tokio::spawn(async move {
        axum::Server::from_tcp(listener_alice).unwrap().serve(alice_axum).await.unwrap();
    });

    tokio::spawn(async move {
        axum::Server::from_tcp(listener_bob).unwrap().serve(bob_axum).await.unwrap();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let ips = ports.iter().map(|port| format!("127.0.0.1:{port}")).collect();
    let ids = vec![alice_id, bob_id];
    (ips, ids, user_keyshare_option)
}

pub async fn update_programs(
    entropy_api: &OnlineClient<EntropyConfig>,
    sig_req_keyring: &sr25519::Pair,
    constraint_modification_account: &sr25519::Pair,
    initial_program: Vec<u8>,
) {
    // update/set their constraints
    let update_program_tx = entropy::tx()
        .constraints()
        .update_v2_constraints(subxtAccountId32::from(sig_req_keyring.public()), initial_program);

    let constraint_modification_account =
        PairSigner::<EntropyConfig, sr25519::Pair>::new(constraint_modification_account.clone());

    entropy_api
        .tx()
        .sign_and_submit_then_watch_default(&update_program_tx, &constraint_modification_account)
        .await
        .unwrap()
        .wait_for_in_block()
        .await
        .unwrap()
        .wait_for_success()
        .await
        .unwrap();
}

/// Verify that a Registering account has all confirmation, and that it is registered.
pub async fn check_if_confirmation(api: &OnlineClient<EntropyConfig>, key: &sr25519::Pair) {
    let signer = PairSigner::<EntropyConfig, sr25519::Pair>::new(key.clone());
    let registering_query = entropy::storage().relayer().registering(signer.account_id());
    let registered_query = entropy::storage().relayer().registered(signer.account_id());
    let is_registering = api.storage().at_latest().await.unwrap().fetch(&registering_query).await;
    // cleared from is_registering state
    assert!(is_registering.unwrap().is_none());
    let is_registered =
        api.storage().at_latest().await.unwrap().fetch(&registered_query).await.unwrap();
    assert_eq!(is_registered.unwrap(), Static(KeyVisibility::Public));
}

#[tokio::test]
#[serial]
async fn test_get_signing_group() {
    clean_tests();
    let cxt = testing_context().await;
    setup_client().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let p_alice = <sr25519::Pair as Pair>::from_string(DEFAULT_MNEMONIC, None).unwrap();
    let signer_alice = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_alice);
    let result_alice = get_subgroup(&api, &signer_alice).await.unwrap().0;
    assert_eq!(result_alice, Some(0));

    let p_bob = <sr25519::Pair as Pair>::from_string(DEFAULT_BOB_MNEMONIC, None).unwrap();
    let signer_bob = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_bob);
    let result_bob = get_subgroup(&api, &signer_bob).await.unwrap().0;
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
    key_share: &KeyShare<KeyParams>,
    sig_uid: &str,
    validators_info: Vec<ValidatorInfo>,
    user_signing_keypair: &sr25519::Pair,
    sig_hash: [u8; 32],
) -> Result<RecoverableSignature, ProtocolErr> {
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

            // Send a SubscribeMessage in the payload of the final handshake message
            let subscribe_message_vec =
                serde_json::to_vec(&SubscribeMessage::new(sig_uid, user_signing_keypair))?;

            let mut encrypted_connection = noise_handshake_initiator(
                ws_stream,
                user_signing_keypair,
                validator_info.x25519_public_key,
                subscribe_message_vec,
            )
            .await
            .map_err(|e| ProtocolErr::EncryptedConnection(e.to_string()))?;

            // Check the response as to whether they accepted our SubscribeMessage
            let response_message = encrypted_connection
                .recv()
                .await
                .map_err(|e| ProtocolErr::EncryptedConnection(e.to_string()))?;

            let subscribe_response: Result<(), String> = serde_json::from_str(&response_message)?;
            if let Err(error_message) = subscribe_response {
                return Err(ProtocolErr::BadSubscribeMessage(error_message));
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

            Ok::<_, ProtocolErr>(())
        })
        .collect::<Vec<_>>();

    // Connect to validators
    future::try_join_all(connect_to_validators).await?;

    // Set up the signing protocol
    let channels = Channels(Broadcaster(tx_ref.clone()), rx_to_others);
    let mut tss_accounts: Vec<AccountId32> =
        validators_info.iter().map(|v| v.tss_account.clone()).collect();
    tss_accounts.push(user_signing_keypair.public().into());

    // Execute the signing protocol
    let rsig = execute_protocol::execute_signing_protocol(
        channels,
        key_share,
        &sig_hash,
        user_signing_keypair,
        tss_accounts,
    )
    .await?;

    // Return a signature if everything went well
    let (signature, recovery_id) = rsig.to_backend();
    Ok(RecoverableSignature { signature, recovery_id })
}
