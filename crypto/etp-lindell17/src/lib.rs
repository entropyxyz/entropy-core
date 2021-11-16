pub mod common;
pub mod cryptoerror;
#[cfg(feature = "party_one")]
pub mod party_one;
pub mod party_two;

/// secp256k1 (K-256) secret key.
pub type SecretKey = common::SecretKey;

/// secp256k1 (K-256) public key. 
pub type PublicKey = common::PublicKey;

/// first message sent in the account creation, which sends a (sharded) keyshare to the entropy network
pub type RegistrationMessage = common::RegistrationMessage;
