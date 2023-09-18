// TODO do these all need to be public?
pub mod errors;
pub mod execute_protocol;
pub mod protocol_transport;

use std::{fmt, net::SocketAddrV4};

use entropy_shared::X25519PublicKey;
use serde::{Deserialize, Serialize};
// TODO to minimise dependencies we could maybe use subxt::utils::AccountId32
use sp_core::crypto::AccountId32;
use synedrion::k256::ecdsa::{RecoveryId, Signature};

// This could maybe move to entropy-shared
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PartyId(AccountId32);

impl PartyId {
    pub fn new(acc: AccountId32) -> Self {
        Self(acc)
    }
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
        let bytes = hex::decode(s).map_err(|err| format!("{err}"))?;
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

#[cfg(not(test))]
use synedrion::ProductionParams;
#[cfg(not(test))]
pub type KeyParams = ProductionParams;

#[cfg(test)]
use synedrion::TestParams;
#[cfg(test)]
pub type KeyParams = TestParams;

pub use synedrion::KeyShare;

#[derive(Clone, Debug)]
pub struct RecoverableSignature {
    pub signature: Signature,
    pub recovery_id: RecoveryId,
}

impl RecoverableSignature {
    pub fn to_rsv_bytes(&self) -> [u8; 65] {
        let mut res = [0u8; 65];

        let rs = self.signature.to_bytes();
        res[0..64].copy_from_slice(&rs);

        res[64] = self.recovery_id.to_byte();

        res
    }
}

// TODO move from user::api
/// Information from the validators in signing party
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorInfo {
    pub x25519_public_key: X25519PublicKey,
    pub ip_address: SocketAddrV4,
    pub tss_account: AccountId32,
}
