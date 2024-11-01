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

use crate::{SessionId, PROTOCOL_MESSAGE_VERSION, SUPPORTED_PROTOCOL_MESSAGE_VERSIONS};
use serde::{Deserialize, Serialize};
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32;

use super::errors::ProtocolVersionMismatchError;

/// A message sent by a party when initiating a websocket connection to participate
/// in the signing or DKG protcol
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct SubscribeMessage {
    /// Protocol session identifier
    pub session_id: SessionId,
    /// Public key of connecting party
    pub public_key: sr25519::Public,
    /// Signature to authenticate connecting party
    pub signature: sr25519::Signature,
    /// Specifies the version of the protocol messages which will be used for this session
    pub version: u32,
}

impl SubscribeMessage {
    pub fn new(session_id: SessionId, pair: &sr25519::Pair) -> Result<Self, bincode::Error> {
        let session_id_serialized = bincode::serialize(&session_id)?;
        let signature = pair.sign(&session_id_serialized);
        Ok(Self {
            session_id,
            public_key: pair.public(),
            signature,
            version: PROTOCOL_MESSAGE_VERSION,
        })
    }

    pub fn account_id(&self) -> AccountId32 {
        self.public_key.0.into()
    }

    pub fn verify(&self) -> Result<bool, bincode::Error> {
        let session_id_serialized = bincode::serialize(&self.session_id)?;
        Ok(sr25519::Pair::verify(&self.signature, session_id_serialized, &self.public_key))
    }

    pub fn check_supported(&self) -> Result<(), ProtocolVersionMismatchError> {
        if self.version > PROTOCOL_MESSAGE_VERSION {
            Err(ProtocolVersionMismatchError::VersionTooNew(PROTOCOL_MESSAGE_VERSION))
        } else if !SUPPORTED_PROTOCOL_MESSAGE_VERSIONS.contains(&self.version) {
            Err(ProtocolVersionMismatchError::VersionTooOld(
                *SUPPORTED_PROTOCOL_MESSAGE_VERSIONS
                    .iter()
                    .min()
                    .expect("At least one protocol message version must be supported"),
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version_check() {
        let session_id = SessionId::Dkg { block_number: 0 };
        let pair = sr25519::Pair::from_seed(&[0; 32]);
        let subscribe_message = SubscribeMessage::new(session_id.clone(), &pair).unwrap();
        assert!(subscribe_message.check_supported().is_ok());

        let session_id_serialized = bincode::serialize(&session_id).unwrap();
        let signature = pair.sign(&session_id_serialized);
        let mut subscribe_message =
            SubscribeMessage { session_id, public_key: pair.public(), signature, version: 0 };
        assert_eq!(
            subscribe_message.check_supported(),
            Err(ProtocolVersionMismatchError::VersionTooOld(
                *SUPPORTED_PROTOCOL_MESSAGE_VERSIONS.iter().min().unwrap()
            ))
        );

        subscribe_message.version = 2;
        assert_eq!(
            subscribe_message.check_supported(),
            Err(ProtocolVersionMismatchError::VersionTooNew(PROTOCOL_MESSAGE_VERSION))
        );
    }
}
