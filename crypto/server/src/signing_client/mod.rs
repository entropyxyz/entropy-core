//! Communicate with other threshold servers and carry out the signing protocol
pub mod api;
mod errors;
pub(crate) mod new_party;
pub(crate) mod subscribe;

use std::{collections::HashMap, sync::Mutex};

#[cfg(test)]
pub mod tests;

pub use self::{
    errors::*,
    new_party::SigningMessage,
    subscribe::{Listener, SubscribeMessage},
};

/// The state used by this node to create signatures
#[derive(Default, Debug)]
pub struct SignerState {
    /// Mapping of PartyIds to `SubscriberManager`s, one entry per active party.
    // TODO(TK): SubscriberManager to be replaced with None when subscribing phase ends.
    pub listeners: Mutex<HashMap<String, Listener>>,
}

impl SignerState {
    /// Create a new `SignerState`
    pub fn contains_listener(&self, session_id: &String) -> bool {
        self.listeners.lock().unwrap().contains_key(session_id)
    }
}
