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
pub(crate) mod chain_api;
mod helpers;
pub(crate) mod message;
pub(crate) mod sign_init;
mod signing_client;
mod r#unsafe;
mod user;
mod validator;
use validator::api::get_random_server_info;

#[macro_use]
extern crate rocket;
use std::{string::String, thread, time::Duration};

use clap::Parser;
use entropy_shared::{MIN_BALANCE, SIGNING_PARTY_SIZE};
use rocket::routes;

use self::{
    chain_api::get_api,
    signing_client::{api::*, SignerState},
    user::api::*,
};
use crate::{
    helpers::{
        launch::{init_tracing, load_kv_store, setup_mnemonic, Configuration, StartupArgs},
        signing::SignatureState,
        validator::get_signer,
        substrate::get_subgroup,
    },
    r#unsafe::api::{delete, get, put, remove_keys},
    validator::api::{
        check_balance_for_fees, get_all_keys, get_and_store_values, sync_kvdb,
        tell_chain_syncing_is_done,
    },
};

#[launch]
async fn rocket() -> _ {
    init_tracing();

    let args = StartupArgs::parse();

    let signer_state = SignerState::default();
    let configuration = Configuration::new(args.chain_endpoint);
    let kv_store = load_kv_store(args.bob, args.alice).await;
    let signature_state = SignatureState::new();

    setup_mnemonic(&kv_store, args.alice, args.bob).await.expect("Issue creating Mnemonic");
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
            my_subgroup = Ok(get_subgroup(&api, &signer).await.expect("Failed to get subgroup."));
        }
        let sbgrp = my_subgroup.expect("Failed to get subgroup.").expect("failed to get subgroup");
        let key_server_info = get_random_server_info(&api, sbgrp)
            .await
            .expect("Issue getting registered keys from chain.");
        let ip_address =
            String::from_utf8(key_server_info.endpoint).expect("failed to parse IP address.");
        let recip_key = x25519_dalek::PublicKey::from(key_server_info.x25519_public_key);
        let all_keys = get_all_keys(&api, batch_size).await.expect("failed to get all keys.");
        let _ =
            get_and_store_values(all_keys, &kv_store, ip_address, batch_size, args.dev, &recip_key)
                .await;
        tell_chain_syncing_is_done(&api, &signer).await.expect("failed to finish chain sync.");
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
