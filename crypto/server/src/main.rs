//! # Signing Client
//!
//! ## Overview
//!
//! Signing Client, to be run by every Entropy node. Also see Communication Manager.
//!
//! ## Pieces Launched
//! - Rocket server - Includes global state and mutex locked IPs
//! - Sled DB KVDB
#![allow(unused_variables)]
#![allow(unused_imports)]

mod communication_manager;
mod signing_client;
mod user;
mod utils;

pub use signing_client::SignInit;

#[macro_use] extern crate rocket;
use rocket::routes;

use crate::{
  communication_manager::{api::*, deprecating_sign::provide_share, CommunicationManagerState},
  signing_client::{api::*, SignerState},
  user::api::*,
  utils::{init_tracing, Configuration},
};

pub const SIGNING_PARTY_SIZE: usize = 6;

#[launch] // initializes an async Rocket-specialized runtime
async fn rocket() -> _ {
  init_tracing();
  let signer_state = SignerState::default();
  let cm_state = CommunicationManagerState::default();
  let configuration = Configuration::new();

  rocket::build()
    .mount("/user", routes![new_user])
    .mount("/signer", routes![new_party, subscribe])
    .manage(signer_state)
    .mount("/cm", routes![provide_share, handle_signing])
    .manage(cm_state)
    .manage(configuration)
}
