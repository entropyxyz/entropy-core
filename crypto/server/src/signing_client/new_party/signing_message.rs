// use rocket::http::hyper::body::Bytes;
use std::str;

use bincode::deserialize;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};

use crate::signing_client::errors::SigningMessageError;
/// A Message related to the signing protocol.
// https://github.com/axelarnetwork/grpc-protobuf/blob/ad810e5e865ce6d3a41cf70ce32e719fff5926ad/grpc.proto#L94
#[derive(Debug, Clone, Serialize, Deserialize)]
// #[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(crate = "rocket::serde")]
pub struct SigningMessage {
    pub from_party_uid: String,
    pub payload: Vec<u8>,
    pub is_broadcast: bool,
    pub round: usize,
}

impl TryFrom<&String> for SigningMessage {
    type Error = SigningMessageError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        let parsed_msg: SigningMessage = serde_json::from_str(value)?;
        Ok(parsed_msg)
    }
}

// https://github.com/axelarnetwork/tofnd/blob/117a35b808663ceebfdd6e6582a3f0a037151198/src/gg20/proto_helpers.rs#L23
impl SigningMessage {
    pub(super) fn new_bcast(
        round: usize,
        bcast: &[u8],
        index: usize,
        party_uids: &[String],
    ) -> Self {
        Self::new_traffic(round, &party_uids[index], bcast, true)
    }

    pub(super) fn new_p2p(round: usize, p2p: &[u8], index: usize, party_uids: &[String]) -> Self {
        Self::new_traffic(round, &party_uids[index], p2p, false)
    }

    pub(super) fn new_traffic(round: usize, from_id: &str, msg: &[u8], is_broadcast: bool) -> Self {
        Self { from_party_uid: from_id.to_string(), payload: msg.to_vec(), is_broadcast, round }
    }
}
