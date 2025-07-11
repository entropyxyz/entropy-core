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

//! Protocol execution and transport logic for the Entropy signing and DKG protocols
pub mod errors;
pub mod execute_protocol;
mod listener;
mod protocol_message;
pub mod protocol_transport;
pub mod sign_and_encrypt;

pub use entropy_shared::user::ValidatorInfo;
pub use listener::Listener;
pub use protocol_message::ProtocolMessage;

extern crate alloc;
use std::{
    fmt,
    hash::{Hash, Hasher},
};

use bincode::Options;
use blake2::{Blake2s256, Digest};
use errors::{ProtocolExecutionErr, VerifyingKeyError};
use k256::{
    ecdsa::{RecoveryId, Signature, VerifyingKey},
    EncodedPoint,
};
use manul::signature::DigestVerifier;
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use serde_persistent_deserializer::{AsTransientDeserializer, PersistentDeserializer};
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32;
use synedrion::{k256::ProductionParams112, signature, AuxInfo, ThresholdKeyShare};

/// The current version number of the protocol message format or protocols themselves
pub const PROTOCOL_MESSAGE_VERSION: u32 = 1;

/// Currently supported protocol message versions for backward compatibility
/// This must contain the current version
pub const SUPPORTED_PROTOCOL_MESSAGE_VERSIONS: [u32; 1] = [PROTOCOL_MESSAGE_VERSION];

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
        sr25519::Public::from(self.0 .0)
    }
}

impl From<sr25519::Public> for PartyId {
    fn from(public_key: sr25519::Public) -> Self {
        // TODO (#376): assuming that `Public` and `AccountId32` represent the same 32 bytes.
        // Ideally we should use only one of those throughout the code, probably `Public`.
        Self(AccountId32(public_key.0))
    }
}

impl DigestVerifier<Blake2s256, sr25519::Signature> for PartyId {
    fn verify_digest(
        &self,
        digest: Blake2s256,
        signature: &sr25519::Signature,
    ) -> Result<(), signature::Error> {
        if sr25519::Pair::verify(signature, digest.finalize(), &self.to_public()) {
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
            bytes.try_into().map_err(|_err| format!("Invalid party ID length: {len}"))?;
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

/// Session configuration used for manul sessions
pub struct EntropySessionParameters;

impl manul::session::SessionParameters for EntropySessionParameters {
    type Signer = execute_protocol::PairWrapper;
    type Verifier = PartyId;
    type Signature = sr25519::Signature;
    type Digest = Blake2s256;
    type WireFormat = BincodeWireFormat;
}

/// Specifies the serialization used for protocol messages
#[derive(Debug)]
pub struct BincodeWireFormat;

impl manul::session::WireFormat for BincodeWireFormat {
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, manul::protocol::LocalError> {
        Ok(bincode::config::DefaultOptions::new()
            .serialize(&value)
            .map_err(|e| manul::protocol::LocalError::new(format!("Serialization error: {e:?}")))?
            .into())
    }

    type Deserializer<'de> = PersistentDeserializer<BincodeDeserializer<'de>>;

    fn deserializer(bytes: &[u8]) -> Self::Deserializer<'_> {
        PersistentDeserializer::new(BincodeDeserializer(bincode::de::Deserializer::from_slice(
            bytes,
            bincode::config::DefaultOptions::new(),
        )))
    }
}

/// A wrapper for a bincode deserializer implementing the trait needed to use it as our WireFormat
#[allow(missing_debug_implementations)]
pub struct BincodeDeserializer<'de>(
    bincode::de::Deserializer<bincode::de::read::SliceReader<'de>, bincode::config::DefaultOptions>,
);

impl<'de> AsTransientDeserializer<'de> for BincodeDeserializer<'de> {
    type Error = bincode::Error;

    fn as_transient_deserializer<'a>(
        &'a mut self,
    ) -> impl serde::Deserializer<'de, Error = Self::Error> {
        &mut self.0
    }
}

/// Parameters used for the threshold signing scheme in production
pub type KeyParams = ProductionParams112;

pub use synedrion::KeyShare;

/// This is the keyshare payload which gets stored by entropy-tss
pub type KeyShareWithAuxInfo = (ThresholdKeyShare<KeyParams, PartyId>, AuxInfo<KeyParams, PartyId>);

/// A secp256k1 signature from which we can recover the public key of the keypair used to create it
#[derive(Clone, Debug)]
pub struct RecoverableSignature {
    pub signature: Signature,
    pub recovery_id: RecoveryId,
}

// This cannot be derived because [RecoveryId] does not implement Serialize
impl Serialize for RecoverableSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RecoverableSignature", 2)?;
        state.serialize_field("signature", &self.signature)?;
        state.serialize_field("recovery_id", &self.recovery_id.to_byte())?;
        state.end()
    }
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

/// An identifier to specify and particular protocol session
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum SessionId {
    /// A distributed key generation protocol session for initial network jumpstart
    Dkg { block_number: u32 },
    /// A proactive refresh session
    Reshare { verifying_key: Vec<u8>, block_number: u32 },
    /// A signing session
    Sign(SigningSessionInfo),
}

/// Information to identify a particular signing protocol session
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SigningSessionInfo {
    /// The signature request account ID
    pub signature_verifying_key: Vec<u8>,
    /// Hash of the message to be signed
    pub message_hash: [u8; 32],
    /// Account ID of the request author (in public access mode this may differ from the signature
    /// request account)
    pub request_author: AccountId32,
}

// This is needed because subxt's AccountId32 does not implement Hash
impl Hash for SessionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            SessionId::Dkg { block_number } => {
                block_number.hash(state);
            },
            SessionId::Reshare { verifying_key, block_number } => {
                verifying_key.hash(state);
                block_number.hash(state);
            },
            SessionId::Sign(signing_session_info) => {
                signing_session_info.signature_verifying_key.hash(state);
                signing_session_info.message_hash.hash(state);
                signing_session_info.request_author.0.hash(state);
            },
        }
    }
}

impl SessionId {
    /// Take the hash of the session ID - used as uniqueness in the protocol
    /// Optionally with some extra data used to identify a sub-session
    pub fn blake2(
        &self,
        sub_session: Option<Subsession>,
    ) -> Result<[u8; 32], ProtocolExecutionErr> {
        let mut hasher = Blake2s256::new();
        hasher.update(bincode::serialize(self)?);
        if let Some(session) = sub_session {
            hasher.update(format!("{session:?}").as_bytes());
        }
        Ok(hasher.finalize().into())
    }
}

/// A sub-protocol of the DKG or reshare protocols
#[derive(Debug)]
pub enum Subsession {
    /// The synedrion key init protocol
    KeyInit,
    /// The synedrion reshare protocol
    Reshare,
    /// The synedrion aux gen protocol
    AuxGen,
}

/// Decode a [VerifyingKey] from bytes
pub fn decode_verifying_key(
    verifying_key_encoded: &[u8; 33],
) -> Result<VerifyingKey, VerifyingKeyError> {
    let point = EncodedPoint::from_bytes(verifying_key_encoded)
        .map_err(|_| VerifyingKeyError::DecodeEncodedPoint)?;
    VerifyingKey::from_encoded_point(&point)
        .map_err(|_| VerifyingKeyError::EncodedPointToVerifyingKey)
}
