use std::{convert::TryFrom, fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use synedrion::{KeyShare, TestSchemeParams};
use tracing::{info, span, Level, Span};
use zeroize::Zeroize;

use super::{
    error::{InnerKvError, KvResult},
    helpers::{deserialize, serialize},
    kv::Kv,
};
use crate::encrypted_sled::Password;

/// Mnemonic type needs to be known globaly to create/access the mnemonic kv store
#[derive(Zeroize, Debug, Clone, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct Entropy(pub Vec<u8>);

// TODO: this is really sp_core::crypto::AccoundId32,
// but I didn't want to bring the `sp_core` dependency here. Should we do it?
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PartyId(pub [u8; 32]);

impl From<PartyId> for String {
    fn from(party_id: PartyId) -> Self { hex::encode(party_id.0) }
}

impl TryFrom<String> for PartyId {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let bytes = hex::decode(s).map_err(|err| format!("{}", err))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|err| format!("Invalid length: {:?}", err))?;
        Ok(Self(arr))
    }
}

impl fmt::Display for PartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "PartyId({})", hex::encode(&self.0[0..4]))
    }
}

/// This records encapsulates the additional information that's only available
/// after the share is created: the correspondence of shares to party IDs they were distributed to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyInfo {
    // TODO: in the future this will probably be a mapping {party_id: [share_id, share_id, ...]}
    pub party_ids: Vec<PartyId>,
    pub share: KeyShare<TestSchemeParams>,
}

/// Kv manager for grpc services
#[derive(Clone)]
pub struct KvManager {
    kv: Kv<KvValue>,
}

impl KvManager {
    pub fn new(root: PathBuf, password: Password) -> KvResult<Self> {
        Ok(KvManager { kv: Kv::<KvValue>::new(root, password)? })
    }

    pub fn kv(&self) -> &Kv<KvValue> { &self.kv }
}

/// Value type stored in the kv-store
pub type KvValue = Vec<u8>;

/// Create PartyInfo from KvValue
impl TryFrom<KvValue> for PartyInfo {
    type Error = InnerKvError;

    fn try_from(v: KvValue) -> Result<Self, Self::Error> {
        deserialize(&v).ok_or(InnerKvError::DeserializationErr)
    }
}

/// Create KvValue from PartyInfo
impl TryFrom<PartyInfo> for KvValue {
    type Error = InnerKvError;

    fn try_from(v: PartyInfo) -> Result<Self, Self::Error> {
        serialize(&v).map_err(|_| InnerKvError::SerializationErr)
    }
}

/// Create Entropy from KvValue
impl TryFrom<KvValue> for Entropy {
    type Error = InnerKvError;

    fn try_from(v: KvValue) -> Result<Self, Self::Error> {
        deserialize(&v).ok_or(InnerKvError::DeserializationErr)
    }
}

/// Create KvValue from Entropy
impl TryFrom<Entropy> for KvValue {
    type Error = InnerKvError;

    fn try_from(v: Entropy) -> Result<Self, Self::Error> {
        serialize(&v).map_err(|_| InnerKvError::SerializationErr)
    }
}

impl PartyInfo {
    /// log PartyInfo state
    pub fn log_info(&self, session_id: &str, sign_span: Span) {
        let init_span = span!(parent: &sign_span, Level::INFO, "init");
        let _enter = init_span.enter();
        info!(
            "[uid:{:?}] starting Sign with [session ID: {}]",
            self.share.party_index(),
            session_id,
        );
    }
}
