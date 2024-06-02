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

use std::str;

use serde::{Deserialize, Serialize};
use sp_core::sr25519;
use synedrion::sessions::CombinedMessage;

use crate::{protocol_transport::errors::ProtocolMessageErr, PartyId};

/// A Message send during the signing or DKG protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Identifier of the author of this message
    pub from: PartyId,
    /// Identifier of the destination of this message
    pub to: PartyId,
    // pub payload: CombinedMessage<sr25519::Signature>,
    pub message_or_verifying_key: MessageOrVerifyingKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageOrVerifyingKey {
    /// The signed protocol message
    CombinedMessage(Box<CombinedMessage<sr25519::Signature>>),
    VerifyingKey(Vec<u8>),
}

impl TryFrom<&[u8]> for ProtocolMessage {
    type Error = ProtocolMessageErr;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let parsed_msg: ProtocolMessage = bincode::deserialize(value)?;
        Ok(parsed_msg)
    }
}

impl ProtocolMessage {
    pub(crate) fn new(
        from: &PartyId,
        to: &PartyId,
        payload: CombinedMessage<sr25519::Signature>,
    ) -> Self {
        Self {
            from: from.clone(),
            to: to.clone(),
            message_or_verifying_key: MessageOrVerifyingKey::CombinedMessage(Box::new(payload)),
        }
    }
}
