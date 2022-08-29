use std::{convert::TryFrom, path::PathBuf};

use serde::{Deserialize, Serialize};
use tofn::{
    gg20::keygen::{GroupPublicInfo, SecretKeyShare, ShareSecretInfo},
    sdk::api::{deserialize, serialize},
};
use tracing::{info, span, Level, Span};
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
        dbg!(v.clone());
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
    /// Get GroupPublicInfo and ShareSecretInfo from tofn to create PartyInfo
    /// Also needed in recovery
    pub fn get_party_info(
        secret_key_shares: Vec<SecretKeyShare>,
        uids: Vec<String>,
        share_counts: Vec<usize>,
        tofnd_index: usize,
    ) -> Self {
        // grap the first share to acquire common data
        let common = secret_key_shares[0].group().clone();

        // aggregate share data into a vector
        let shares = secret_key_shares.into_iter().map(|share| share.share().clone()).collect();

        // add tofnd data
        let tofnd = TofndInfo { party_uids: uids, share_counts, index: tofnd_index };

        PartyInfo { common, shares, tofnd }
    }

    /// log PartyInfo state
    pub fn log_info(&self, session_id: &str, sign_span: Span) {
        let init_span = span!(parent: &sign_span, Level::INFO, "init");
        let _enter = init_span.enter();

        info!(
            "[uid:{}, shares:{}] starting Sign with [key: {}, (t,n)=({},{}), participants:{:?}",
            self.tofnd.party_uids[self.tofnd.index],
            self.tofnd.share_counts[self.tofnd.index],
            session_id,
            self.common.threshold(),
            self.tofnd.share_counts.iter().sum::<usize>(),
            self.tofnd.party_uids,
        );
    }
}
