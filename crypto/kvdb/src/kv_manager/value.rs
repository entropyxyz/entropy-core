use std::{convert::TryFrom, fmt, path::PathBuf};

use cggmp21::{KeyShare, TestSchemeParams};
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PartyId(pub [u8; 32]);

impl fmt::Display for PartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "PartyId({})", hex::encode(&self.0[0..4]))
    }
}

impl cggmp21::sessions::PartyId for PartyId {}

/// `KeyShareKv` record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyInfo {
    pub share: KeyShare<PartyId, TestSchemeParams>,
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
    pub fn get_party_info(share: KeyShare<PartyId, TestSchemeParams>) -> Self { Self { share } }

    /// log PartyInfo state
    pub fn log_info(&self, session_id: &str, sign_span: Span) {
        let init_span = span!(parent: &sign_span, Level::INFO, "init");
        let _enter = init_span.enter();

        let parties = self.share.parties();
        let parties_str = parties.iter().map(|id| format!("{}", id)).collect::<Vec<_>>().join(", ");

        info!(
            "[uid:{}] starting Sign with [session ID: {}, n={}, participants:{}",
            self.share.party(),
            session_id,
            parties.len(),
            parties_str,
        );
    }
}
