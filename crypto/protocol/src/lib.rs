//! Protocol execution and transport logic for the Entropy signing and DKG protocols
pub mod errors;
pub mod execute_protocol;
mod protocol_message;
pub mod protocol_transport;
pub mod user;

use std::fmt;

use entropy_shared::X25519PublicKey;
pub use protocol_message::ProtocolMessage;
use serde::{Deserialize, Serialize};
use subxt::utils::AccountId32;
use synedrion::k256::ecdsa::{RecoveryId, Signature};

/// Identifies a party participating in a protocol session
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PartyId(AccountId32);

impl std::hash::Hash for PartyId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0 .0.hash(state);
    }
}

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
        let len = bytes.len();
        let arr: [u8; 32] =
            bytes.try_into().map_err(|_err| format!("Invalid party ID length: {}", len))?;
        let acc = arr.into();
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
/// Parameters used for the threshold signing scheme in production
#[cfg(not(test))]
pub type KeyParams = ProductionParams;

#[cfg(test)]
use synedrion::TestParams;
/// Parameters used for the threshold signing scheme in tests (faster but less secure)
#[cfg(test)]
pub type KeyParams = TestParams;

pub use synedrion::KeyShare;

/// A secp256k1 signature from which we can recover the public key of the keypair used to create it
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

/// Information from the validators in signing party
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ValidatorInfo {
    pub x25519_public_key: X25519PublicKey,
    pub ip_address: String,
    pub tss_account: AccountId32,
}
