use std::{convert::TryFrom, path::PathBuf};

use serde::{Deserialize, Serialize};
use tofn::{
    gg20::keygen::{GroupPublicInfo, ShareSecretInfo},
    sdk::api::{deserialize, serialize},
};
use zeroize::Zeroize;

use super::{
    error::{InnerKvError, KvResult},
    kv::Kv,
};
use crate::encrypted_sled::Password;

/// Mnemonic type needs to be known globaly to create/access the mnemonic kv store
#[derive(Zeroize, Debug, Clone, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct Entropy(pub Vec<u8>);

/// Struct to hold `tonfd` info. This consists of information we need to
/// store in the KV store that is not relevant to `tofn`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TofndInfo {
    pub party_uids: Vec<String>,
    pub share_counts: Vec<usize>,
    pub index: usize,
}

/// `KeyShareKv` record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyInfo {
    pub common: GroupPublicInfo,
    pub shares: Vec<ShareSecretInfo>,
    pub tofnd: TofndInfo,
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
