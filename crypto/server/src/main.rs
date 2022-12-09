//! # Server
//!
//! ## Overview
//!
//! Consists of three core routes:
//! - "/user/new" - add a user to the system
//! (I'd rename cm/handle_signing to cm/new_party)
//! - "/cm/handle_signing" - endpoint for the CM to be informed to start a signing protocol
//! - "/signer/new_party" - endpoint for the CM to start a signing protocol
//!
//! CM also has a route "/cm/provide_share", but this is in the process of being swapped out for
//! on-chain public storage of the knowledge of which nodes hold which shares.
//!
//! ## Pieces Launched
//! - Rocket server - Includes global state and mutex locked IPs
//! - Sled DB KVDB
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]

pub(crate) mod chain_api;
pub(crate) mod message;
pub(crate) mod sign_init;
mod signing_client;
mod user;
mod utils;
mod validator;
use bip39::{Language, Mnemonic, MnemonicType};
#[macro_use]
extern crate rocket;
use std::{thread, time::Duration};

use clap::Parser;
use kvdb::kv_manager::{error::KvError, KeyReservation, KvManager};
use rocket::routes;
use sp_keyring::AccountKeyring;
use substrate_common::SIGNING_PARTY_SIZE;
use subxt::ext::sp_core::{crypto::AccountId32, sr25519, Pair};

use self::{
    chain_api::get_api,
    signing_client::{api::*, SignerState},
    user::api::*,
    utils::{init_tracing, load_kv_store, Configuration, SignatureState, StartupArgs},
};
use crate::{
    message::{derive_static_secret, mnemonic_to_pair},
    user::unsafe_api::{delete, get, put, remove_keys},
    validator::api::{get_all_keys, get_and_store_values, get_key_url, sync_kvdb},
};

#[launch]
async fn rocket() -> _ {
    init_tracing();
    let signer_state = SignerState::default();
    let configuration = Configuration::new();
    let kv_store = load_kv_store().await;
    let signature_state = SignatureState::new();

    let args = StartupArgs::parse();

    println!("args : {:?}", args.clone());

    // Below deals with syncing the kvdb
    if args.sync {
        let api = get_api(&configuration.endpoint).await.unwrap();
        let mut is_syncing = true;
        let sleep_time = Duration::from_secs(20);
        // wait for chain to be fully synced before starting key swap
        while is_syncing {
            let health = api.rpc().system_health().await.unwrap();
            is_syncing = health.is_syncing;
            if is_syncing {
                println!("chain syncing, retrying {:?}", is_syncing);
                thread::sleep(sleep_time);
            }
        }
        // TODO: find a proper batch size
        let batch_size = 10;
        let signer = get_signer(&kv_store).await.unwrap();
        let key_server_url = get_key_url(&api, &signer).await.unwrap();
        let all_keys = get_all_keys(&api, batch_size).await.unwrap();
        let _ = get_and_store_values(all_keys, &kv_store, key_server_url, batch_size).await;
        println!("inside {:?}", is_syncing);
    }

    // Unsafe routes are for testing purposes only
    // they are unsafe as they can expose vulnerabilites
    // should they be used in production. Unsafe routes
    // are disabled by default.
    // To enable unsafe routes compile with --feature unsafe.
    let mut unsafe_routes = routes![];
    if cfg!(feature = "unsafe") {
        unsafe_routes = routes![remove_keys, get, put, delete];
    }

    rocket::build()
        .mount("/user", routes![new_user])
        .mount("/signer", routes![new_party, subscribe_to_me, get_signature, drain])
        .mount("/validator", routes![sync_kvdb])
        .mount("/unsafe", unsafe_routes)
        .manage(signer_state)
        .manage(signature_state)
        .manage(configuration)
        .manage(kv_store)
}

async fn setup_mnemonic(kv: &KvManager) {
    // Check if a mnemonic exists in the kvdb.
    let exists_result = kv.kv().exists("MNEMONIC").await;
    match exists_result {
        Ok(v) => {
            if !v {
                // Generate a new mnemonic
                let mnemonic: Mnemonic;
                // If using a test configuration then set to the default mnemonic.
                if cfg!(test) {
                    mnemonic =
                        Mnemonic::from_phrase(utils::DEFAULT_MNEMONIC, Language::English).unwrap();
                } else if cfg!(feature = "alice") {
                    mnemonic =
                        Mnemonic::from_phrase(utils::DEFAULT_ALICE_MNEMONIC, Language::English)
                            .unwrap();
                } else if cfg!(feature = "bob") {
                    mnemonic =
                        Mnemonic::from_phrase(utils::DEFAULT_BOB_MNEMONIC, Language::English)
                            .unwrap();
                } else {
                    mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
                }
                let phrase = mnemonic.phrase();
                println!("[server-config]");
                let pair = mnemonic_to_pair(&mnemonic);
                let static_secret = derive_static_secret(&pair);
                let dh_public = x25519_dalek::PublicKey::from(&static_secret);

                let ss_reservation =
                    kv.kv().reserve_key("SHARED_SECRET".to_string()).await.unwrap();
                match kv.kv().put(ss_reservation, static_secret.to_bytes().to_vec()).await {
                    Ok(r) => {},
                    Err(r) => warn!("failed to update ss: {:?}", r),
                }

                let dh_reservation = kv.kv().reserve_key("DH_PUBLIC".to_string()).await.unwrap();
                match kv.kv().put(dh_reservation, dh_public.to_bytes().to_vec()).await {
                    Ok(r) => println!("dh_public_key={dh_public:?}"),
                    Err(r) => warn!("failed to update dh: {:?}", r),
                }

                let p = <sr25519::Pair as Pair>::from_phrase(phrase, None).unwrap();
                let id = AccountId32::new(p.0.public().0);
                println!("account_id={id}");

                // Update the value in the kvdb
                let reservation = kv.kv().reserve_key("MNEMONIC".to_string()).await.unwrap();
                let result = kv.kv().put(reservation, phrase.as_bytes().to_vec()).await;
                match result {
                    Ok(r) => {},
                    Err(r) => warn!("failed to update mnemonic: {:?}", r),
                }
            }
        },
        Err(v) => warn!("{:?}", v),
    }
}
