#![cfg_attr(not(feature = "std"), no_std)]
//! Types that is shared by clients and substrate nodes,
//! i.e. messages sent from one to the other and structs contained in those messages
//!
//! This helps ensures those structs are synced among clients and nodes.

mod types;
use codec::alloc::vec::Vec;

pub type RegistrationMessage = types::RegistrationMessage;
pub type RegistrationResponse = types::RegistrationResponse;
pub type SigRequest = types::SigRequest;
pub type SigResponse = types::SigResponse;
pub type OCWMessage = Vec<types::Message>;
pub type Message = types::Message;

#[cfg(test)]
pub const SIGNING_PARTY_SIZE: usize = 2;

// TODO: fix and change back
#[cfg(not(test))]
pub const SIGNING_PARTY_SIZE: usize = 2;

