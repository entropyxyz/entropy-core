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

use core::fmt;
use std::{convert::TryFrom, path::PathBuf};

use entropy_protocol::PartyId;
use serde::{Deserialize, Serialize};
use synedrion::{KeyShare, ProductionParams};
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

/// This records encapsulates the additional information that's only available
/// after the share is created: the correspondence of shares to party IDs they were distributed to.
#[derive(Clone, Serialize, Deserialize)]
pub struct PartyInfo {
    // TODO: in the future this will probably be a mapping {party_id: [share_id, share_id, ...]}
    pub party_ids: Vec<PartyId>,
    pub share: KeyShare<ProductionParams, PartyId>,
}

impl fmt::Debug for PartyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Point")
            .field("party_ids", &self.party_ids)
            .field("share", &self.share.verifying_key())
            .finish()
    }
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

    pub fn kv(&self) -> &Kv<KvValue> {
        &self.kv
    }
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
        info!("[uid:{:?}] starting Sign with [session ID: {}]", self.share.owner(), session_id,);
    }
}
