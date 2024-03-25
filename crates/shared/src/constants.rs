use hex_literal::hex;
use lazy_static::lazy_static;
use sp_core::H256;
use sp_std::vec;
use sp_std::vec::Vec;

lazy_static! {
    pub static ref DEFAULT_VERIFYING_KEY_NOT_REGISTERED: Vec<u8> = vec![10; VERIFICATION_KEY_LENGTH as usize];
    pub static ref DAVE_VERIFYING_KEY: Vec<u8> = vec![1; VERIFICATION_KEY_LENGTH as usize];
    // this key is associated with a constant key share generation from DETERMINISTIC_KEY_SHARE
    pub static ref EVE_VERIFYING_KEY: Vec<u8> = vec![2, 78, 59, 129, 175, 156, 34, 52, 202, 208, 157, 103, 156, 230, 3, 94, 209, 57, 35, 71, 206, 100, 206, 64, 95, 93, 205, 54, 34, 138, 37, 222, 110];
    pub static ref FERDIE_VERIFYING_KEY: Vec<u8> = vec![3; VERIFICATION_KEY_LENGTH as usize];
    pub static ref DEFAULT_VERIFYING_KEY: Vec<u8> = vec![0; VERIFICATION_KEY_LENGTH as usize];
    // key used to create a deterministic key share taken from here https://docs.rs/k256/latest/k256/ecdsa/index.html
    pub static ref DETERMINISTIC_KEY_SHARE: [u8; 32] =  hex!("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");
    // hash used to find DEVICE_KEY_PROXY onchain
    pub static ref DEVICE_KEY_HASH: H256 =  H256::zero();
}

pub const SIGNING_PARTY_SIZE: usize = 2;

// min balance 12 decimal chain = 0.1
pub const MIN_BALANCE: u128 = 10000000000;

// 6 seconds a block this is one day
/// The amount of blocks before a tx request is pruned from the kvdb
pub const PRUNE_BLOCK: u32 = 14400;

/// Timeout for validators to wait for other validators to join protocol committees
pub const SETUP_TIMEOUT_SECONDS: u64 = 20;

/// The amount of proactive refreshes we do per session
pub const REFRESHES_PER_SESSION: u32 = 10;

/// Max instructions per wasm program
pub const MAX_INSTRUCTIONS_PER_PROGRAM: u64 = 100_000_000;

/// Blocks a transaction is valid for
pub const MORTALITY_BLOCKS: u64 = 32;

/// Size of the verification key
pub const VERIFICATION_KEY_LENGTH: u32 = 33;

/// `device_key_proxy.wasm` from the `programs` repo.
pub const DEVICE_KEY_PROXY: &[u8] = include_bytes!("../device_key_proxy.wasm");
