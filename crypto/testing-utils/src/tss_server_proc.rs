use std::{net::TcpListener, time::Duration};

use axum::{routing::IntoMakeService, Router};
use entropy_protocol::{KeyParams, PartyId};
use kvdb::{encrypted_sled::PasswordMethod, get_db_path, kv_manager::KvManager};
use rand_core::OsRng;
use subxt::utils::AccountId32 as SubxtAccountId32;
use synedrion::KeyShare;

use server::{
    app,
    get_signer,
    launch::{setup_latest_block_number, setup_mnemonic, Configuration, ValidatorName},
    // signing_client::ListenerState,
    AppState,
};

pub const DEFAULT_ENDPOINT: &str = "ws://localhost:9944";

lazy_static::lazy_static! {
    /// A shared reference to the logger used for tests.
    ///
    /// Since this only needs to be initialized once for the whole test suite we define it as a lazy
    /// static.
    pub static ref LOGGER: () = {
        // We set up the tests to only print out logs of `ERROR` or higher by default, otherwise we
        // fall back to the user's `RUST_LOG` settings.
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    };
}

/// Initialize the global loger used in tests.
///
/// The logger will only be initialized once, even if this function is called multiple times.
pub fn initialize_test_logger() {
    lazy_static::initialize(&LOGGER);
}

// pub async fn setup_client() -> KvManager {
//     let kv_store =
//         KvManager::new(get_db_path(true).into(), PasswordMethod::NoPassword.execute().unwrap())
//             .unwrap();
//     let _ = setup_mnemonic(&kv_store, &Some(ValidatorName::Alice)).await;
//     let _ = setup_latest_block_number(&kv_store).await;
//     let listener_state = ListenerState::default();
//     let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());
//     let app_state = AppState { listener_state, configuration, kv_store: kv_store.clone() };
//     let app = app(app_state).into_make_service();
//     let listener = TcpListener::bind("0.0.0.0:3001").unwrap();
//
//     tokio::spawn(async move {
//         axum::Server::from_tcp(listener).unwrap().serve(app).await.unwrap();
//     });
//     kv_store
// }

async fn create_clients(
    key_number: String,
    values: Vec<Vec<u8>>,
    keys: Vec<String>,
    validator_name: &Option<ValidatorName>,
) -> (IntoMakeService<Router>, KvManager) {
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());

    let path = format!(".entropy/testing/test_db_{key_number}");
    let _ = std::fs::remove_dir_all(path.clone());

    let kv_store =
        KvManager::new(path.into(), PasswordMethod::NoPassword.execute().unwrap()).unwrap();
    let _ = setup_mnemonic(&kv_store, validator_name).await;
    let _ = setup_latest_block_number(&kv_store).await;

    for (i, value) in values.into_iter().enumerate() {
        let reservation = kv_store.clone().kv().reserve_key(keys[i].to_string()).await.unwrap();
        let _ = kv_store.clone().kv().put(reservation, value).await;
    }

    let app_state = AppState::new(configuration, kv_store.clone());
    let app = app(app_state).into_make_service();

    (app, kv_store)
}

pub async fn spawn_testing_validators(
    sig_req_keyring: Option<String>,
    // If this is true a keyshare for the user will be generated and returned
    extra_private_keys: bool,
) -> (Vec<String>, Vec<PartyId>, Option<KeyShare<KeyParams>>) {
    // spawn threshold servers
    let ports = [3001i64, 3002];

    let (alice_axum, alice_kv) =
        create_clients("validator1".to_string(), vec![], vec![], &Some(ValidatorName::Alice)).await;
    let alice_id = PartyId::new(SubxtAccountId32(
        *get_signer(&alice_kv).await.unwrap().account_id().clone().as_ref(),
    ));

    let (bob_axum, bob_kv) =
        create_clients("validator2".to_string(), vec![], vec![], &Some(ValidatorName::Bob)).await;
    let bob_id = PartyId::new(SubxtAccountId32(
        *get_signer(&bob_kv).await.unwrap().account_id().clone().as_ref(),
    ));

    let user_keyshare_option = if sig_req_keyring.is_some() {
        let number_of_shares = if extra_private_keys { 3 } else { 2 };
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

        if extra_private_keys {
            Some(shares[2].clone())
        } else {
            Some(shares[1].clone())
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
