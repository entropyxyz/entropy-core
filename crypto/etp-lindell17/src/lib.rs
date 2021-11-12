mod common;
pub mod cryptoerror;
pub mod party_one;
pub mod party_two;

/// secp256k1 (K-256) secret key.
pub type SecretKey = party_one::SecretKey;
//pub type SecretKey = k256::SecretKey;

/// secp256k1 (K-256) public key. 
// this is inconsistent with the definition of SecretKey above. why? is this necessary?
pub type PublicKey = k256::PublicKey;

/// first message sent in the account creation, which sends a (sharded) keyshare to the entropy network
pub type RegistrationMessage = common::RegistrationMessage;


