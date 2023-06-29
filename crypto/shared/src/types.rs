#![allow(dead_code)]
#[cfg(feature = "std")]
/// common structs etc, shared among the substrate-blockchain-code and the crypto-code
pub use crate::constraints::*;

/// X25519 public key used by the client in non-interactive ECDH to authenticate/encrypt
/// interactions with the threshold server (eg distributing threshold shares).
pub type X25519PublicKey = [u8; 32];
