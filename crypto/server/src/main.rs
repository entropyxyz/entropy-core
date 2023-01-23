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
use std::{string::String, thread, time::Duration};

use clap::Parser;
use kvdb::kv_manager::{error::KvError, KeyReservation, KvManager};
use rocket::routes;
use sp_keyring::AccountKeyring;
use substrate_common::{MIN_BALANCE, SIGNING_PARTY_SIZE};
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
    validator::api::{
        check_balance_for_fees, get_all_keys, get_and_store_values, get_key_url, sync_kvdb,
        tell_chain_syncing_is_done,
    },
};

#[launch]
async fn rocket() -> _ {
    init_tracing();
    let args = StartupArgs::parse();
    let signer_state = SignerState::default();
    let configuration = Configuration::new(args.chain_endpoint);
    let kv_store = load_kv_store(args.bob).await;
    let signature_state = SignatureState::new();

    setup_mnemonic(&kv_store, args.alice, args.bob).await;
    // Below deals with syncing the kvdb
    if args.sync {
        let api = get_api(&configuration.endpoint).await.expect("Issue acquiring chain API");
        let mut is_syncing = true;
        let sleep_time = Duration::from_secs(20);
        // wait for chain to be fully synced before starting key swap
        while is_syncing {
            let health = api.rpc().system_health().await.expect("Issue checking chain health");
            is_syncing = health.is_syncing;
            if is_syncing {
                println!("chain syncing, retrying {is_syncing:?}");
                thread::sleep(sleep_time);
            }
        }
        // TODO: find a proper batch size
        let batch_size = 10;
        let signer = get_signer(&kv_store).await.expect("Issue acquiring threshold signer key");
        let has_fee_balance = check_balance_for_fees(&api, signer.account_id(), MIN_BALANCE)
            .await
            .expect("Issue checking chain for signer balance");
        if !has_fee_balance {
            panic!("threshold account needs balance: {:?}", signer.account_id());
        }

        // if not in subgroup retry until you are
        let mut my_subgroup = get_subgroup(&api, &signer).await;
        while my_subgroup.is_err() {
            println!("you are not currently a validator, retrying");
            thread::sleep(sleep_time);
            my_subgroup = get_subgroup(&api, &signer).await;
        }

        let key_server_url = get_key_url(
            &api,
            &signer,
            my_subgroup.expect("Issue getting my subgroup").expect("Issue getting my subgroup"),
        )
        .await
        .expect("Issue getting a url in signing group");
        let all_keys =
            get_all_keys(&api, batch_size).await.expect("Issue getting registered keys from chain");
        let _ =
            get_and_store_values(all_keys, &kv_store, key_server_url, batch_size, args.dev).await;
        tell_chain_syncing_is_done(&api, &signer)
            .await
            .expect("Issue telling chain syncing is done");
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

    rocket::build()
        .mount("/user", routes![store_tx, new_user])
        .mount("/signer", routes![new_party, subscribe_to_me, get_signature, drain])
        .mount("/validator", routes![sync_kvdb])
        .mount("/unsafe", unsafe_routes)
        .manage(signer_state)
        .manage(signature_state)
        .manage(configuration)
        .manage(kv_store)
}

pub async fn setup_mnemonic(kv: &KvManager, is_alice: bool, is_bob: bool) {
    // Check if a mnemonic exists in the kvdb.
    let exists_result = kv.kv().exists("MNEMONIC").await.expect("issue querying DB");
    if !exists_result {
        // Generate a new mnemonic
        let mut mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        // If using a test configuration then set to the default mnemonic.
        if cfg!(test) {
            mnemonic = Mnemonic::from_phrase(utils::DEFAULT_MNEMONIC, Language::English)
                .expect("Issue creating Mnemonic");
        }
        if is_alice {
            mnemonic = Mnemonic::from_phrase(utils::DEFAULT_ALICE_MNEMONIC, Language::English)
                .expect("Issue creating Mnemonic");
        }
        if is_bob {
            mnemonic = Mnemonic::from_phrase(utils::DEFAULT_BOB_MNEMONIC, Language::English)
                .expect("Issue creating Mnemonic");
        }

        let phrase = mnemonic.phrase();
        println!("[server-config]");
        let pair = mnemonic_to_pair(&mnemonic);
        let static_secret = derive_static_secret(&pair);
        let dh_public = x25519_dalek::PublicKey::from(&static_secret);

        let ss_reservation =
            kv.kv().reserve_key("SHARED_SECRET".to_string()).await.expect("Issue reserving ss key");
        kv.kv()
            .put(ss_reservation, static_secret.to_bytes().to_vec())
            .await
            .expect("failed to update secret share");

        let dh_reservation =
            kv.kv().reserve_key("DH_PUBLIC".to_string()).await.expect("Issue reserving DH key");

        kv.kv()
            .put(dh_reservation, dh_public.to_bytes().to_vec())
            .await
            .expect("failed to update dh");
        println!("dh_public_key={dh_public:?}");

        let p = <sr25519::Pair as Pair>::from_phrase(phrase, None)
            .expect("Issue getting pair from mnemonic");
        let id = AccountId32::new(p.0.public().0);
        println!("account_id={id}");

        // Update the value in the kvdb
        let reservation =
            kv.kv().reserve_key("MNEMONIC".to_string()).await.expect("Issue reserving mnemonic");
        let result = kv
            .kv()
            .put(reservation, phrase.as_bytes().to_vec())
            .await
            .expect("failed to update mnemonic");
    }
}
