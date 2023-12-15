//! Communicate with other threshold servers and carry out the signing and DKG protocols
pub mod api;
mod errors;
pub(crate) mod listener;
pub(crate) mod protocol_execution;
pub(crate) mod protocol_transport;

#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use entropy_protocol::SessionId;

pub use self::{errors::*, listener::Listener, protocol_execution::ProtocolMessage};

/// The state used when setting up protocol connections to track who we are expecting to connect
/// to for a particular protcol execution (Signing or DKG).
#[derive(Default, Debug, Clone)]
pub struct ListenerState {
    /// Mapping of identifiers for the protocol run to [Listener]s.
    /// In the case of DKG, the identifier is the signature request account
    /// In the case of signing, the identifier is the message id from
    /// [crate::helpers::signing::create_unique_tx_id]
    pub listeners: Arc<Mutex<HashMap<SessionId, Listener>>>,
}

impl ListenerState {
    /// Create a new `ListenerState`
    pub fn contains_listener(&self, session_id: &SessionId) -> Result<bool, SubscribeErr> {
        Ok(self
            .listeners
            .lock()
            .map_err(|e| SubscribeErr::LockError(e.to_string()))?
            .contains_key(session_id))
    }
}
