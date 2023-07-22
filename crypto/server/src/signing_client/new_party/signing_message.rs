use std::str;

use kvdb::kv_manager::PartyId;
use serde::{Deserialize, Serialize};
use subxt::ext::sp_core::sr25519::Signature;
use synedrion::sessions::SignedMessage;

use crate::signing_client::errors::SigningMessageError;
/// A Message related to the signing protocol.
// https://github.com/axelarnetwork/grpc-protobuf/blob/ad810e5e865ce6d3a41cf70ce32e719fff5926ad/grpc.proto#L94
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct SigningMessage {
    pub from: PartyId,
    // If `None`, it's a broadcast message
    pub to: Option<PartyId>,
    pub payload: SignedMessage<Signature>,
}

impl TryFrom<&String> for SigningMessage {
    type Error = SigningMessageError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        let parsed_msg: SigningMessage = serde_json::from_str(value)?;
        Ok(parsed_msg)
    }
}

impl SigningMessage {
    pub(super) fn new_bcast(from: &PartyId, payload: SignedMessage<Signature>) -> Self {
        Self { from: from.clone(), to: None, payload }
    }

    pub(super) fn new_p2p(from: &PartyId, to: &PartyId, payload: SignedMessage<Signature>) -> Self {
        Self { from: from.clone(), to: Some(to.clone()), payload }
    }
}
