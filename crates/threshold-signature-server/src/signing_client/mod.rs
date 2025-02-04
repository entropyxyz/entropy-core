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

//! Communicate with other threshold servers and carry out the signing and DKG protocols
pub mod api;
mod errors;
pub(crate) mod protocol_execution;
pub(crate) mod protocol_transport;

#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use entropy_protocol::{Listener, SessionId};

pub use self::{errors::*, protocol_execution::ProtocolMessage};

/// The state used when setting up protocol connections to track who we are expecting to connect
/// to for a particular protcol execution (Signing or DKG).
#[derive(Default, Debug, Clone)]
pub struct ListenerState {
    /// Mapping of [SessionId]s for the protocol run to [Listener]s.
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

    /// Gets the list of peers who haven't yet subscribed to us for this particular session.
    pub fn unsubscribed_peers(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<subxt::utils::AccountId32>, SubscribeErr> {
        let listeners =
            self.listeners.lock().map_err(|e| SubscribeErr::LockError(e.to_string()))?;
        let listener =
            listeners.get(session_id).ok_or(SubscribeErr::NoSessionId(session_id.clone()))?;

        let unsubscribed_peers =
            listener.validators.keys().map(|id| subxt::utils::AccountId32(*id)).collect();

        Ok(unsubscribed_peers)
    }
}
