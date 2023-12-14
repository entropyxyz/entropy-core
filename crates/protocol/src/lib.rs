//! Protocol execution and transport logic for the Entropy signing and DKG protocols
pub mod errors;
pub mod execute_protocol;
mod protocol_message;
pub mod protocol_transport;
pub mod sign_and_encrypt;
pub mod user;

extern crate alloc;
use std::{
    fmt,
    hash::{Hash, Hasher},
};

use entropy_shared::X25519PublicKey;
pub use protocol_message::ProtocolMessage;
use serde::{Deserialize, Serialize};
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32;
use synedrion::{
    k256::ecdsa::{RecoveryId, Signature},
    signature::{self, hazmat::PrehashVerifier},
};

/// Identifies a party participating in a protocol session
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
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

    fn to_public(&self) -> sr25519::Public {
        // TODO (#376): assuming that `Public` and `AccountId32` represent the same 32 bytes.
        // Ideally we should use only one of those throughout the code, probably `Public`.
        sr25519::Public(self.0 .0)
    }
}

impl From<sr25519::Public> for PartyId {
    fn from(public_key: sr25519::Public) -> Self {
        // TODO (#376): assuming that `Public` and `AccountId32` represent the same 32 bytes.
        // Ideally we should use only one of those throughout the code, probably `Public`.
        Self(AccountId32(public_key.0))
    }
}

impl PrehashVerifier<sr25519::Signature> for PartyId {
    fn verify_prehash(
        &self,
        prehash: &[u8],
        signature: &sr25519::Signature,
    ) -> Result<(), signature::Error> {
        if sr25519::Pair::verify(signature, prehash, &self.to_public()) {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
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

/// An identifier to specify and particular protocol session
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum SessionId {
    /// A distributed key generation protocol session for registering
    Dkg(AccountId32),
    /// A proactive refresh session
    ProactiveRefresh(AccountId32),
    /// A signing session
    Sign(SigningSessionInfo),
}

/// Information to identify a particular signing protocol session
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SigningSessionInfo {
    /// The signature request account ID
    pub account_id: AccountId32,
    /// Hash of the message to be signed
    pub message_hash: [u8; 32],
}

// This is needed because subxt's AccountId32 does not implement Hash
impl Hash for SessionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            SessionId::Dkg(account_id) => {
                account_id.0.hash(state);
            },
            SessionId::ProactiveRefresh(account_id) => {
                account_id.0.hash(state);
            },
            SessionId::Sign(signing_session_info) => {
                signing_session_info.account_id.0.hash(state);
                signing_session_info.message_hash.hash(state);
            },
        }
    }
}
