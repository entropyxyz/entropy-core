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

pub(crate) mod chain_api;
mod communication_manager;
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

use self::{
    communication_manager::{api::*, deprecating_sign::provide_share, CommunicationManagerState},
    signing_client::{api::*, SignerState},
    user::api::*,
    utils::{init_tracing, load_kv_store, Configuration},
};

pub const SIGNING_PARTY_SIZE: usize = 6;

#[launch]
async fn rocket() -> _ {
    init_tracing();
    let signer_state = SignerState::default();
    let cm_state = CommunicationManagerState::default();
    let configuration = Configuration::new();
    let kv_store = load_kv_store();
    setup_mnemonic(&kv_store).await;

    rocket::build()
        .mount("/user", routes![new_user])
        .mount("/signer", routes![new_party, subscribe_to_me])
        .mount("/cm", routes![provide_share, handle_signing])
        .manage(signer_state)
        .manage(cm_state)
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
                let mut mnemonic: Mnemonic =
                    Mnemonic::new(MnemonicType::Words24, Language::English);
                // If using a test configuration then set to the default mnemonic.
                if cfg!(test) {
                    mnemonic =
                        Mnemonic::from_phrase(utils::DEFAULT_MNEMONIC, Language::English).unwrap();
                };

                let phrase = mnemonic.phrase();
                let key = KeyReservation { key: "MNEMONIC".to_string() };

                let p = <sr25519::Pair as Pair>::from_phrase(phrase, None).unwrap();
                let id = AccountId32::new(p.0.public().0);
                println!("Threshold account id: {}", id);

                // Update the value in the kvdb
                let result = kv.kv().put(key, phrase.as_bytes().to_vec()).await;
                match result {
                    Ok(r) => println!("updated mnemonic"),
                    Err(r) => warn!("failed to update mnemonic: {:?}", r),
                }
            }
        },
        Err(v) => warn!("{:?}", v),
    }
}
