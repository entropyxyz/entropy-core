pub mod api;
mod errors;
mod new_party;
mod subscribe;

use std::{collections::HashMap, sync::Mutex};

#[cfg(test)]
mod tests;

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
    pub fn contains_listener(&self, key: &str) -> bool {
        self.listeners.lock().unwrap().contains_key(key)
    }
}
