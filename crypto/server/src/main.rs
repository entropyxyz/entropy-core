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

mod communication_manager;
pub(crate) mod sign_init;
mod signing_client;
mod user;
mod utils;

#[macro_use] extern crate rocket;
use rocket::routes;

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

  rocket::build()
    .mount("/user", routes![new_user])
    .mount("/signer", routes![new_party, subscribe_to_me])
    .mount("/cm", routes![provide_share, handle_signing])
    .manage(signer_state)
    .manage(cm_state)
    .manage(configuration)
    .manage(kv_store)
}
