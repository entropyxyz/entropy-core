// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! # Threshold Server
//!
//! The Threshold Signature Server which stores key shares and participates in the signing protocol.
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
//! #### `/user/relay_tx` - POST
//!
//! [crate::user::api::relay_tx()]
//!
//! Called by a user to submit a transaction to sign. Takes a
//! [UserSignatureRequest] encrypted in a [SignedMessage](crate::validation::SignedMessage).
//!
//! Picks signers and gets them to sign a message then returns the responses to the user.
//!
//! The response is chunked response stream. If the `UserSignatureRequest` could be processed, a
//! success response header is sent.  Then the signing protocol runs. When the it finishes, a single
//! message will be sent on the response stream with the result.
//!
//! If everything went well, the message will be a vector of JSON objects with a signle property "Ok"
//! containing an array which contains two strings. Each element in the vector is a response from a signer.
//!
//! For example:
//!
//! `[{"Ok":["t7Mcxfdigds3RoT6OO/P+uMFE+XigRjUpn72E1cRU4Q2u7cVxZlsNRYhnahA+DvSNHBddj0HRz5u/XPlJT9QOQE=","32d7c0bfd90b546993d1ad51c542e1fc9dd1706c7bca395c8bd7f9642ae842400769488404dabd25d438cf08785a6750f95e7489245b8760af115f450d5f0a83"]}]`
//!
//! The first string is a base64 encoded signature produced by the signing protocol. This is a 65
//! byte signature, the final byte of which is a
//! [recovery ID](https://docs.rs/synedrion/latest/synedrion/ecdsa/struct.RecoveryId.html).
//!
//! The second string is a hex encoded sr25519 signature of the signature made by the TSS server,
//! which can be used to authenticate that this response really came from this TSS server.
//!
//! In case signing was not successfull, the message will be a JSON object with a signle property "Err"
//! containing an error message, for example:
//!
//! "[{\"Err\":\"Too many requests - wait a block\"},{\"Err\":\"Too many requests - wait a block\"}]"
//!
//! Curl example for `user/sign_tx`:
//! ```text
//! curl -X POST -H "Content-Type: application/json" \
//!   -d '{"msg" "0x174...hex encoded signedmessage...","sig":"821754409744cbb878b44bd1e3dc575a4ea721e12d781b074fcdb808fc79fd33dd1928b1a281c0b6261a30536a7c0106a102f27dad1bc3ef475b626f0e57c983","pk":[172,133,159,138,33,110,235,27,50,11,76,118,209,24,218,61,116,7,250,82,52,132,208,169,128,18,109,59,77,13,34,10],"recip":[10,192,41,240,184,83,178,59,237,101,45,109,13,230,155,124,195,141,148,249,55,50,238,252,133,181,134,30,144,247,58,34],"a":[169,94,23,7,19,184,134,70,233,117,2,84,242,135,246,95,159,14,218,125,209,191,175,89,41,196,182,96,117,5,159,98],"nonce":[114,93,158,35,209,188,96,248,85,131,95,237]}' \
//!   -H "Accept: application/json" \
//!   http://127.0.0.1:3001/user/relay_tx
//! ```
//!
//! #### `/user/sign_tx` - POST
//!
//! [crate::user::api::sign_tx()]
//!
//! Called by a relayer to submit a transaction to sign. Takes a
//! [RelayerSignatureRequest] encrypted in a [SignedMessage](crate::validation::SignedMessage).
//!
//! The response is chunked response stream. If the `RelayerSignatureRequest` could be processed, a
//! success response header is sent.  Then the signing protocol runs. When the it finishes, a single
//! message will be sent on the response stream with the result.
//!
//! If everything went well, the message will be a JSON object with a signle property "Ok"
//! containing an array which contains two strings.
//!
//! For example:
//!
//! `{"Ok":["t7Mcxfdigds3RoT6OO/P+uMFE+XigRjUpn72E1cRU4Q2u7cVxZlsNRYhnahA+DvSNHBddj0HRz5u/XPlJT9QOQE=","32d7c0bfd90b546993d1ad51c542e1fc9dd1706c7bca395c8bd7f9642ae842400769488404dabd25d438cf08785a6750f95e7489245b8760af115f450d5f0a83"]}`
//!
//! The first string is a base64 encoded signature produced by the signing protocol. This is a 65
//! byte signature, the final byte of which is a
//! [recovery ID](https://docs.rs/synedrion/latest/synedrion/ecdsa/struct.RecoveryId.html).
//!
//! The second string is a hex encoded sr25519 signature of the signature made by the TSS server,
//! which can be used to authenticate that this response really came from this TSS server.
//!
//! In case signing was not successfull, the message will be a JSON object with a signle property "Err"
//! containing an error message, for example:
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
//! ### For the node operator
//!
//! [`/info`](crate::node_info::api::info()) - Get - get a Json object of type
//! [crate::node_info::api::TssPublicKeys] which contains the TSS account ID and x25519 public key.
//!
//! ### For the blockchain node
//!
//! ### For other instances of the threshold server
//!
//!   Takes a [UserRegistrationInfo] containing the users account ID and associated keyshare, wrapped
//!   in a [crate::validation::SignedMessage].
//!
//! - [`/ws`](crate::signing_client::api::ws_handler()) - Websocket server for signing and DKG protocol
//!   messages. This is opened by other threshold servers when the signing procotol is initiated.
//!
//! - [`/validator/sync_kvdb`](crate::validator::api::sync_kvdb()) - POST - Called by another
//!   threshold server when joining to get the key-shares from a member of their sub-group.
//!
//!   Takes a list of users account IDs for which shares are requested, wrapped in a
//!   [crate::validation::SignedMessage].
//!   Responds with a list of [crate::validation::SignedMessage]s each containing a serialized
//!   [synedrion::KeyShare].
//!
//! - [`/version`](crate::node_info::api::version()) - Get - get the node version info
//! - [`/heathlz`](crate::health::api::healthz()) - Get - get if the node is running
//! - [`/hashes`](crate::node_info::api::hashes()) - Get - get the hashes supported by the node

//! ### For testing / development
//!
//! [Unsafe](crate::unsafe::api) has additional routes which are for testing and development
//! purposes only and will not be used in production. These routes are only available if this crate
//! is compiled with the `unsafe` feature enabled.
//!
//! - [`/unsafe/get_network_keyshare`](crate::unsafe::api::unsafe_get_network_key_share()) - GET - Read the network keyshare
//! - [`/unsafe/write_to_request_limit`](crate::unsafe::api::write_to_request_limit()) - POST - Write the request limit
//! - [`/unsafe/read_from_request_limit`](crate::unsafe::api::read_from_request_limit()) - POST - Read the request limit
//! - [`/unsafe/write_to_block_number`](crate::unsafe::api::write_to_block_numbers()) - POST - Write to the block numbers
//!
//! ## Pieces Launched
//!
//! - Axum server - Includes global state and mutex locked IPs
//! - [kvdb](entropy_kvdb) - Encrypted key-value database for storing key-shares and other data, build using
//!   [sled](https://docs.rs/sled)
#![doc(html_logo_url = "https://entropy.xyz/assets/logo_02.png")]
pub use entropy_client::chain_api;
pub(crate) mod attestation;
pub(crate) mod backup_provider;
pub(crate) mod health;
pub mod helpers;
pub(crate) mod node_info;
pub(crate) mod sign_init;
pub(crate) mod signing_client;
pub(crate) mod r#unsafe;
pub mod user;
pub mod validation;
pub mod validator;

pub use crate::helpers::{app_state::AppState, launch, validator::get_signer_and_x25519_secret};
use crate::{
    attestation::api::get_attest,
    backup_provider::api::{backup_encryption_key, quote_nonce, recover_encryption_key},
    chain_api::EntropyConfig,
    health::api::healthz,
    node_info::api::{hashes, info, version as get_version},
    r#unsafe::api::{
        read_from_request_limit, unsafe_get_network_key_share, write_to_block_numbers,
        write_to_request_limit,
    },
    signing_client::{api::*, ListenerState},
    user::api::*,
    validator::api::{new_reshare, rotate_network_key},
};
use axum::{
    http::Method,
    routing::{get, post},
    Router,
};
use subxt::utils::AccountId32 as SubxtAccountId32;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::{self, TraceLayer},
};
use tracing::Level;

pub fn app(app_state: AppState) -> Router {
    let mut routes = Router::new()
        .route("/v1/generate_network_key", post(generate_network_key))
        .route("/v1/user/sign_tx", post(sign_tx))
        .route("/v1/user/relay_tx", post(relay_tx))
        .route("/v1/signer/proactive_refresh", post(proactive_refresh))
        .route("/v1/validator/reshare", post(new_reshare))
        .route("/v1/rotate_network_key", post(rotate_network_key))
        .route("/v1/attest", get(get_attest))
        .route("/v1/backup_encryption_key", post(backup_encryption_key))
        .route("/v1/recover_encryption_key", post(recover_encryption_key))
        .route("/v1/backup_provider_quote_nonce", post(quote_nonce))
        .route("/healthz", get(healthz))
        .route("/v1/version", get(get_version))
        .route("/v1/hashes", get(hashes))
        .route("/v1/info", get(info))
        .route("/v1/ws", get(ws_handler));

    // Unsafe routes are for testing purposes only
    // they are unsafe as they can expose vulnerabilites
    // should they be used in production. Unsafe routes
    // are disabled by default.
    // To enable unsafe routes compile with --feature unsafe.
    if cfg!(feature = "unsafe") || cfg!(test) {
        tracing::warn!("Server started in unsafe mode - do not use in production!");
        routes = routes
            .route("/unsafe/write_to_request_limit", post(write_to_request_limit))
            .route("/unsafe/read_from_request_limit", post(read_from_request_limit))
            .route("/unsafe/write_to_block_numbers", post(write_to_block_numbers))
            .route("/unsafe/get_network_keyshare", get(unsafe_get_network_key_share))
    }

    routes
        .with_state(app_state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<axum::body::Body>| {
                    tracing::info_span!(
                        "http-request",
                        uuid = %uuid::Uuid::new_v4(),
                        uri = %request.uri(),
                        method = %request.method(),
                    )
                })
                .on_request(trace::DefaultOnRequest::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(CorsLayer::new().allow_origin(Any).allow_methods([Method::GET, Method::POST]))
}
