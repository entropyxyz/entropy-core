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
use tokio::sync::broadcast::{self, error::SendError};

use crate::protocol_message::ProtocolMessage;

/// A wrapper around [broadcast::Sender] for broadcasting protocol messages
#[derive(Debug)]
pub struct Broadcaster(pub broadcast::Sender<ProtocolMessage>);

impl Broadcaster {
    pub fn send(&self, msg: ProtocolMessage) -> Result<usize, Box<SendError<ProtocolMessage>>> {
        Ok(self.0.send(msg)?)
    }
}
