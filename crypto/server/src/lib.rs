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
//! Most user-facing endpoints take a [SignedMessage](crate::validation::SignedMessage) which
//! is an encrypted, signed message.
//!
//!
//! #### `/user/sign_tx` - POST
//!
//! [crate::user::api::sign_tx()]
//!
//! Called by a user to submit a transaction to sign (the new way of doing signing). Takes a
//! [`UserTransactionRequest`](crate::user::api::UserTransactionRequest) encryted in a
//! `SignedMessage`.
//!
//! The response is chunked response stream. If the `UserTransactionRequest` could be processed, a
//! success response header is sent.  Then the signing protocol runs. When the it finishes, a single
//! message will be sent on the response stream with the result.
//!
//! If everything went well, the message will be a JSON object with a signle property "Ok"
//! containing a base64 encoded signature, for example:
//!
//! `{"Ok":"BnJRjRUw9+trW36bK7S2KglY+TG5rGn1e3FKQlJYvx+jai7wG5Z0BWPFGYPxAwB5yROUOnucuzXoG7TrI7QNIAE="}`
//!
//! Otherwise, the message will be a JSON object with a signle property "Err" containing an error
//! message, for example:
//!
//! `{"Err":"reqwest event error: Invalid status code: 500 Internal Server Error"}`
//!
//! Curl example for `user/sign_tx`:
//! ```text
//! curl -X POST -H "Content-Type: application/json" \
//!   -d '{"msg" "0x174...hex encoded signedmessage...","sig":"821754409744cbb878b44bd1e3dc575a4ea721e12d781b074fcdb808fc79fd33dd1928b1a281c0b6261a30536a7c0106a102f27dad1bc3ef475b626f0e57c983","pk":[172,133,159,138,33,110,235,27,50,11,76,118,209,24,218,61,116,7,250,82,52,132,208,169,128,18,109,59,77,13,34,10],"recip":[10,192,41,240,184,83,178,59,237,101,45,109,13,230,155,124,195,141,148,249,55,50,238,252,133,181,134,30,144,247,58,34],"a":[169,94,23,7,19,184,134,70,233,117,2,84,242,135,246,95,159,14,218,125,209,191,175,89,41,196,182,96,117,5,159,98],"nonce":[114,93,158,35,209,188,96,248,85,131,95,237]}' \
//!   -H "Accept: application/json" \
//!   http://127.0.0.1:3001/user/sign_tx
//! ```
//!
//! ### For the blockchain node
//!
//! #### `/user/new` - POST
//!
//! [crate::user::api::new_user()]
//!
//! Called by the off-chain worker (propagation pallet) during user registration.
//! This takes a parity scale encoded [entropy_shared::types::OcwMessageDkg] which tells us which
//! validators are in the registration group and will perform a DKG.
//!
//! ### For other instances of the threshold server
//!
//! - [`/user/receive_key`](receive_key) - recieve a keyshare from another threshold server in the
//!   same signing subgroup. Takes a [UserRegistrationInfo] wrapped in a
//!   [crate::validation::SignedMessage].
//! - [`/ws`](crate::signing_client::api::ws_handler()) - Websocket server for signing protocol
//! messages. This is opened by other threshold servers when the signing procotol is initiated.
//! - [`/validator/sync_kvdb`](crate::validator::api::sync_kvdb()) - POST - Called by another
//! threshold server when joining to get the key-shares from a member of their sub-group.
//!
//! ### For testing / development
//!
//! [Unsafe](crate::unsafe::api) has additional routes which are for testing and development
//! purposes only and will not be used in production. These routes are only available if this crate
//! is compiled with the `unsafe` feature enabled.
//!
//! - [`unsafe/get`](crate::unsafe::api::unsafe_get()) - POST - get a value from the key-value
//!   store, given its key.
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
pub mod chain_api;
pub mod common;
pub(crate) mod health;
pub(crate) mod helpers;
pub(crate) mod sign_init;
pub(crate) mod signing_client;
pub(crate) mod r#unsafe;
pub(crate) mod user;
pub mod validation;
pub(crate) mod validator;

use axum::{
    http::Method,
    routing::{get, post},
    Router,
};
use kvdb::kv_manager::KvManager;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::{self, TraceLayer},
};
use tracing::Level;
use validator::api::get_random_server_info;

use self::{
    signing_client::{api::*, ListenerState},
    user::api::*,
};
use crate::{
    health::api::healthz,
    launch::Configuration,
    r#unsafe::api::{delete, put, remove_keys, unsafe_get},
    validator::api::sync_kvdb,
};
pub use crate::{
    helpers::{launch, validator::get_signer},
    validator::api::sync_validator,
};

#[derive(Clone)]
pub struct AppState {
    pub listener_state: ListenerState,
    pub configuration: Configuration,
    pub kv_store: KvManager,
}

impl AppState {
    pub fn new(configuration: Configuration, kv_store: KvManager) -> Self {
        Self { listener_state: ListenerState::default(), configuration, kv_store }
    }
}

pub fn app(app_state: AppState) -> Router {
    let mut routes = Router::new()
        .route("/user/sign_tx", post(sign_tx))
        .route("/user/new", post(new_user))
        .route("/user/receive_key", post(receive_key))
        .route("/signer/proactive_refresh", post(proactive_refresh))
        .route("/validator/sync_kvdb", post(sync_kvdb))
        .route("/healthz", get(healthz))
        .route("/ws", get(ws_handler));

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
