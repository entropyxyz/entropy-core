use hex_literal::hex;
use crate::chain_spec::get_account_id_from_seed;
pub use node_primitives::{AccountId};
use sp_core::{sr25519};


pub fn endowed_accounts_dev() -> Vec<AccountId> {
	vec![
		get_account_id_from_seed::<sr25519::Public>("Alice"),
		get_account_id_from_seed::<sr25519::Public>("Bob"),
		get_account_id_from_seed::<sr25519::Public>("Charlie"),
		get_account_id_from_seed::<sr25519::Public>("Dave"),
		get_account_id_from_seed::<sr25519::Public>("Eve"),
		get_account_id_from_seed::<sr25519::Public>("Ferdie"),
		get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
		get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
		get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
		get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
		get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
		get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
	]
}

pub fn endowed_accounts_devnet() -> Vec<AccountId> {
	vec![
		// random placeholder
		// hex!["a617f1a88de5efbaefaafdf4d02818e00b6bb45c673c2dedca447b62dad2a26d"].into(),
	]
}
