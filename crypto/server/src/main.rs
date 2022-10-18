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
mod communication_manager;
pub(crate) mod message;
pub(crate) mod sign_init;
mod signing_client;
mod user;
mod utils;
use bip39::{Language, Mnemonic, MnemonicType};
#[macro_use]
extern crate rocket;
use communication_manager::deprecating_sign::entropy::sudo::storage::Key;
use kvdb::kv_manager::{error::KvError, KeyReservation, KvManager};
use rocket::routes;
use sp_core::{crypto::AccountId32, sr25519, Pair};
use sp_keyring::AccountKeyring;
use substrate_common::SIGNING_PARTY_SIZE;

use self::{
    communication_manager::{api::*, deprecating_sign::provide_share, CommunicationManagerState},
    signing_client::{api::*, SignerState},
    user::api::*,
    utils::{init_tracing, load_kv_store, Configuration, SignatureState},
};
use crate::{
    message::{derive_static_secret, mnemonic_to_pair},
    user::unsafe_api::get_dh,
};

#[launch]
async fn rocket() -> _ {
    init_tracing();
    let signer_state = SignerState::default();
    let cm_state = CommunicationManagerState::default();
    let configuration = Configuration::new();
    let kv_store = load_kv_store().await;
    let signature_state = SignatureState::new();
    // Unsafe routes are for testing purposes only
    // they are unsafe as they can expose vulnerabilites
    // should they be used in production. Unsafe routes
    // are disabled by default.
    // To enable unsafe routes compile with --feature unsafe.
    let mut unsafe_routes = routes![];
    if cfg!(feature = "unsafe") {
        unsafe_routes = routes![get_dh];
    }

    rocket::build()
        .mount("/user", routes![new_user])
        .mount("/signer", routes![new_party, subscribe_to_me, get, drain])
        .mount("/cm", routes![provide_share, handle_signing])
        .mount("/unsafe", unsafe_routes)
        .manage(signer_state)
        .manage(cm_state)
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
                    Ok(r) => println!("dh_public_key={:?}", dh_public),
                    Err(r) => warn!("failed to update dh: {:?}", r),
                }
                let reservation = kv.kv().reserve_key("MNEMONIC".to_string()).await.unwrap();

                let p = <sr25519::Pair as Pair>::from_phrase(phrase, None).unwrap();
                let id = AccountId32::new(p.0.public().0);
                println!("account_id={}", id);

                // Update the value in the kvdb
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
