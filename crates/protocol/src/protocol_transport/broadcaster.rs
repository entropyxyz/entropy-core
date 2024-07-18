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

//! Listener becomes Broadcaster when all other parties have subscribed.
use tokio::sync::{
    broadcast::{self, error::SendError},
    mpsc,
};

use crate::protocol_message::ProtocolMessage;

/// A wrapper around [broadcast::Sender] for broadcasting protocol messages
#[derive(Debug, Clone)]
pub struct Broadcaster {
    /// Channel for outgoing protocol messages to all parties
    pub broadcast: broadcast::Sender<ProtocolMessage>,
    /// Channel for incoming protocol messages from all parties
    /// A clone of the sender is kept here so that we can use it in the session loop to put messages
    /// destined for a different sub-session back into the incoming queue
    pub incoming_sender: mpsc::Sender<ProtocolMessage>,
}

impl Broadcaster {
    /// Send an outgoing protocol message
    pub fn send(&self, msg: ProtocolMessage) -> Result<usize, Box<SendError<ProtocolMessage>>> {
        Ok(self.broadcast.send(msg)?)
    }
}
