use std::{convert::TryFrom, fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use sp_core::crypto::AccountId32;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PartyId(AccountId32);

impl PartyId {
    pub fn new(acc: AccountId32) -> Self { Self(acc) }
}

impl From<PartyId> for String {
    fn from(party_id: PartyId) -> Self {
        let bytes: &[u8] = party_id.0.as_ref();
        hex::encode(bytes)
    }
}

impl TryFrom<String> for PartyId {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let bytes = hex::decode(s).map_err(|err| format!("{}", err))?;
        let acc = AccountId32::try_from(bytes.as_ref())
            .map_err(|_err| format!("Invalid party ID length: {}", bytes.len()))?;
        Ok(Self(acc))
    }
}

impl fmt::Display for PartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let bytes: &[u8] = self.0.as_ref();
        write!(f, "PartyId({})", hex::encode(&bytes[0..4]))
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
