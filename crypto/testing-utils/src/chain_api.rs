#![allow(clippy::all)]
pub use subxt::config::PolkadotConfig as EntropyConfig;

#[subxt::subxt(runtime_metadata_path = "../server/entropy_metadata.scale")]
pub mod entropy {}
