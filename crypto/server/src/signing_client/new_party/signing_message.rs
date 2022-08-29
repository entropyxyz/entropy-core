use rocket::http::hyper::body::Bytes;
use serde::{Deserialize, Serialize};

use crate::signing_client::errors::SigningMessageError;

/// A Message related to the signing protocol.
// https://github.com/axelarnetwork/grpc-protobuf/blob/ad810e5e865ce6d3a41cf70ce32e719fff5926ad/grpc.proto#L94
#[derive(Debug, Clone, Serialize, Deserialize)]
// #[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(crate = "rocket::serde")]
pub struct SigningMessage {
    pub from_party_uid: String,
    pub payload: BytesWrap,
    pub is_broadcast: bool,
}

impl TryFrom<&[u8]> for SigningMessage {
    type Error = SigningMessageError;

    // Reqwest responses come back formatted with an added crud feature:
    // 'data:{<actual_message>}\n'
    // 👆👆👆  this is crud    👆
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw_msg = std::str::from_utf8(value)?;
        let trimmed_msg = raw_msg.split_once(':').ok_or(SigningMessageError::BadSplit)?.1;
        let parsed_msg = serde_json::from_str(trimmed_msg)?;
        Ok(parsed_msg)
    }
}

/// A wrapper to implement serialize
#[derive(Debug, Clone)]
// #[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct BytesWrap(pub Bytes);
impl Serialize for BytesWrap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        todo!()
    }
}
impl<'de> Deserialize<'de> for BytesWrap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        todo!()
    }
}

// https://github.com/axelarnetwork/tofnd/blob/117a35b808663ceebfdd6e6582a3f0a037151198/src/gg20/proto_helpers.rs#L23
impl SigningMessage {
    pub(super) fn new_bcast(bcast: &[u8]) -> Self { Self::new_traffic("", bcast, true) }

    pub(super) fn new_p2p(receiver_id: &str, p2p: &[u8]) -> Self {
        Self::new_traffic(receiver_id, p2p, false)
    }

    pub(super) fn new_traffic(receiver_id: &str, msg: &[u8], is_broadcast: bool) -> Self {
        Self {
            from_party_uid: receiver_id.to_string(),
            payload: BytesWrap(Bytes::from(msg.to_vec())),
            is_broadcast,
        }
    }
}
