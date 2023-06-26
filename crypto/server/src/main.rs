//! # Server
//!
//! The Threshold Server which stores key shares and participates in the signing protocol.
//!
//! ## Overview
//!
//! This exposes a HTTP API.
//!
//! ## The HTTP endpoints
//!
//! Some endpoints are designed to be called by the user, some by the entropy chain node,
//! and some by other instances of `server`:
//!
//! ### For the user
//!
//! Most user-facing endpoints take a [SignedMessage](crate::message::SignedMessage) which
//! is an encrypted, signed message.
//!
//! #### `/user/new` - POST
//!
//! [crate::user::api::new_user()]
//!
//! Called by a user when registering to submit a key-share. Takes a Synedrion keyshare
//! encrypted in a `SignedMessage`.
//!
//! Curl example for `user/new`:
//! ```text
//! curl -X POST -H "Content-Type: application/json" \
//!   -d '{"msg" "0x174...hex encoded signedmessage...","sig":"821754409744cbb878b44bd1e3dc575a4ea721e12d781b074fcdb808fc79fd33dd1928b1a281c0b6261a30536a7c0106a102f27dad1bc3ef475b626f0e57c983","pk":[172,133,159,138,33,110,235,27,50,11,76,118,209,24,218,61,116,7,250,82,52,132,208,169,128,18,109,59,77,13,34,10],"recip":[10,192,41,240,184,83,178,59,237,101,45,109,13,230,155,124,195,141,148,249,55,50,238,252,133,181,134,30,144,247,58,34],"a":[169,94,23,7,19,184,134,70,233,117,2,84,242,135,246,95,159,14,218,125,209,191,175,89,41,196,182,96,117,5,159,98],"nonce":[114,93,158,35,209,188,96,248,85,131,95,237]}' \
//!   -H "Accept: application/json" \
//!   http://127.0.0.1:3001/user/new
//! ```
//!
//! #### `/user/sign_tx` - POST
//!
//! [crate::user::api::sign_tx()]
//!
//! Called by a user to submit a transaction to sign (the new way of doing signing). Takes a
//! [`UserTransactionRequest`](crate::user::api::UserTransactionRequest) encryted in a
//! `SignedMessage`.
//!
//! Curl example for `user/sign_tx`:
//! ```text
//! curl -X POST -H "Content-Type: application/json" \
//!   -d '{"msg" "0x174...hex encoded signedmessage...","sig":"821754409744cbb878b44bd1e3dc575a4ea721e12d781b074fcdb808fc79fd33dd1928b1a281c0b6261a30536a7c0106a102f27dad1bc3ef475b626f0e57c983","pk":[172,133,159,138,33,110,235,27,50,11,76,118,209,24,218,61,116,7,250,82,52,132,208,169,128,18,109,59,77,13,34,10],"recip":[10,192,41,240,184,83,178,59,237,101,45,109,13,230,155,124,195,141,148,249,55,50,238,252,133,181,134,30,144,247,58,34],"a":[169,94,23,7,19,184,134,70,233,117,2,84,242,135,246,95,159,14,218,125,209,191,175,89,41,196,182,96,117,5,159,98],"nonce":[114,93,158,35,209,188,96,248,85,131,95,237]}' \
//!   -H "Accept: application/json" \
//!   http://127.0.0.1:3001/user/sign_tx
//! ```
//!
//! #### `/user/tx` - POST
//!
//! [crate::user::api::store_tx()]
//!
//! Called by a user when signing to submit a transaction to be signed using the signing
//! protocol (the original way of doing signing).
//!
//! Curl example for `user/tx`:
//! ```text
//! curl -X POST -H "Content-Type: application/json" \
//!   -d '{"msg" "0x174...hex encoded signedmessage...","sig":"821754409744cbb878b44bd1e3dc575a4ea721e12d781b074fcdb808fc79fd33dd1928b1a281c0b6261a30536a7c0106a102f27dad1bc3ef475b626f0e57c983","pk":[172,133,159,138,33,110,235,27,50,11,76,118,209,24,218,61,116,7,250,82,52,132,208,169,128,18,109,59,77,13,34,10],"recip":[10,192,41,240,184,83,178,59,237,101,45,109,13,230,155,124,195,141,148,249,55,50,238,252,133,181,134,30,144,247,58,34],"a":[169,94,23,7,19,184,134,70,233,117,2,84,242,135,246,95,159,14,218,125,209,191,175,89,41,196,182,96,117,5,159,98],"nonce":[114,93,158,35,209,188,96,248,85,131,95,237]}' \
//!   -H "Accept: application/json" \
//!   http://127.0.0.1:3001/user/tx
//! ```
//!
//! #### `/signer/signature` - POST
//!
//! [crate::signing_client::api::get_signature()]
//!
//! Get a signature, given a message hash. If a message was successfully signed, this
//! returns the signature.
//!
//! This takes a [`Message`](crate::signing_client::api::Message) containing a hex encoded message
//! hash. For evm transactions this should be an ethers
//! [`TransactionRequest`](ethers_core::types::transaction::request::TransactionRequest) sighash.
//!
//! Curl example for `/signer/signature`:
//! ```text
//! curl -X POST -H "Content-Type: application/json" \
//!   -d '{"message" "0x174...hex encoded sighash..."}' \
//!   -H "Accept: application/json" \
//!   http://127.0.0.1:3001/signer/signature
//! ```
//!
//! #### `/signer/drain` - GET
//!
//! [crate::signing_client::api::drain()]
//!
//! Remove signatures from state.
//! This should be called after `get_signature`.
//!
//! Curl example for `user/drain`:
//! ```text
//! curl -X GET -H "Accept: application/json" \
//!   http://127.0.0.1:3001/user/drain
//! ```
//!
//! ### For the blockchain node
//!
//! ### For other instances of the threshold server
//!
//! - [`/signer/subscribe_to_me`](crate::signing_client::api::subscribe_to_me()) - POST - Called by
//! other threshold servers when the signing procotol is initiated.
//! - [`/validator/sync_kvdb`](crate::validator::api::sync_kvdb()) - POST - Called by another
//! threshold server when joining to get the key-shares from a member of their sub-group.
//!
//! ### For testing / development
//!
//! [Unsafe](crate::unsafe::api) has additional routes which are for testing and development
//! purposes only and will not be used in production. These routes are only available if this crate
//! is compiled with the `unsafe` feature enabled.
//!
//! - [`unsafe/get`](crate::unsafe::api::get()) - POST - get a value from the key-value store, given
//!   its key.
//! - [`unsafe/put`](crate::unsafe::api::put()) - POST - update an existing value in the key-value
//!   store.
//! - [`unsafe/delete`](crate::unsafe::api::delete()) - POST - remove a value from the key-value
//!   store, given its key.
//! - [`unsafe/remove_keys`](crate::unsafe::api::remove_keys()) - GET - remove everything from the
//!   key-value store.
//!
//! ## Pieces Launched
//!
//! - Axum server - Includes global state and mutex locked IPs
//! - [kvdb](kvdb) - Encrypted key-value database for storing key-shares and other data, build using
//! [sled](https://docs.rs/sled)
#![doc(html_logo_url = "https://entropy.xyz/assets/logo_02.png")]
pub(crate) mod chain_api;
pub(crate) mod health;
mod helpers;
pub(crate) mod sign_init;
mod signing_client;
mod r#unsafe;
mod user;
pub(crate) mod validation;
mod validator;
use std::{net::SocketAddr, str::FromStr, string::String, thread, time::Duration};

use axum::{
    http::Method,
    routing::{get, post},
    Router,
};
use clap::Parser;
use entropy_shared::{MIN_BALANCE, SIGNING_PARTY_SIZE};
use kvdb::kv_manager::KvManager;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::{self, TraceLayer},
};
use tracing::Level;
use validator::api::get_random_server_info;

use self::{
    chain_api::get_api,
    signing_client::{api::*, SignerState},
    user::api::*,
};
use crate::{
    health::api::healthz,
    helpers::{
        launch::{init_tracing, load_kv_store, setup_mnemonic, Configuration, StartupArgs},
        signing::SignatureState,
        substrate::get_subgroup,
        validator::get_signer,
    },
    r#unsafe::api::{delete, put, remove_keys, unsafe_get},
    validator::api::{
        check_balance_for_fees, get_all_keys, get_and_store_values, sync_kvdb,
        tell_chain_syncing_is_done,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub signer_state: SignerState,
    pub configuration: Configuration,
    pub kv_store: KvManager,
    pub signature_state: SignatureState,
}

#[tokio::main]
async fn main() {
    init_tracing();

    let args = StartupArgs::parse();

    let signer_state = SignerState::default();
    let configuration = Configuration::new(args.chain_endpoint);
    let kv_store = load_kv_store(args.bob, args.alice, args.no_password).await;
    let signature_state = SignatureState::new();

    let app_state = AppState {
        signer_state,
        configuration: configuration.clone(),
        kv_store: kv_store.clone(),
        signature_state,
    };

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

    // TODO: unhardcode endpoint
    let addr = SocketAddr::from_str(&args.threshold_url).expect("failed to parse threshold url.");
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app(app_state).into_make_service())
        .await
        .expect("failed to launch axum server.");
}

pub fn app(app_state: AppState) -> Router {
    let mut routes = Router::new()
        .route("/user/sign_tx", post(sign_tx))
        .route("/user/new", post(new_user))
        .route("/signer/subscribe_to_me", post(subscribe_to_me))
        .route("/signer/signature", post(get_signature))
        .route("/signer/drain", get(drain))
        .route("/validator/sync_kvdb", post(sync_kvdb))
        .route("/healthz", get(healthz));

    // Unsafe routes are for testing purposes only
    // they are unsafe as they can expose vulnerabilites
    // should they be used in production. Unsafe routes
    // are disabled by default.
    // To enable unsafe routes compile with --feature unsafe.
    if cfg!(feature = "unsafe") || cfg!(test) {
        tracing::warn!("Server started in unsafe mode do not use in production!!!!!!!");
        routes = routes
            .route("/unsafe/put", post(put))
            .route("/unsafe/get", post(unsafe_get))
            .route("/unsafe/delete", post(delete))
            .route("/unsafe/remove_keys", get(remove_keys));
    }

    routes
        .with_state(app_state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(CorsLayer::new().allow_origin(Any).allow_methods([Method::GET, Method::POST]))
}
