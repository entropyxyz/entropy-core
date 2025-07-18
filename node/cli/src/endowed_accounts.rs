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

//! Pre-endowed accounts used for the development network
use crate::chain_spec::get_account_id_from_seed;
use entropy_runtime::AccountId;
use serde::{Deserialize, Serialize};
use sp_core::sr25519;
use std::str::FromStr;

include!(concat!(env!("OUT_DIR"), "/endowed_testnet_accounts.rs"));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressStruct {
    address: String,
    name: String,
}

/// Development accounts which correspond to our usual cast of characters (e.g `//Alice`, `//Bob`).
pub fn endowed_accounts_dev() -> Vec<AccountId> {
    vec![
        get_account_id_from_seed::<sr25519::Public>("Alice"),
        get_account_id_from_seed::<sr25519::Public>("Bob"),
        get_account_id_from_seed::<sr25519::Public>("Charlie"),
        get_account_id_from_seed::<sr25519::Public>("Dave"),
        get_account_id_from_seed::<sr25519::Public>("Eve"),
        get_account_id_from_seed::<sr25519::Public>("Ferdie"),
        get_account_id_from_seed::<sr25519::Public>("One"),
        get_account_id_from_seed::<sr25519::Public>("Two"),
        get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
        get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
        get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
        get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
        get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
        get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
        get_account_id_from_seed::<sr25519::Public>("One//stash"),
        get_account_id_from_seed::<sr25519::Public>("Two//stash"),
        crate::chain_spec::tss_account_id::ALICE.clone(),
        crate::chain_spec::tss_account_id::BOB.clone(),
        crate::chain_spec::tss_account_id::CHARLIE.clone(),
        crate::chain_spec::tss_account_id::DAVE.clone(),
    ]
}

pub fn endowed_accounts_testnet() -> Vec<AccountId> {
    ENDOWED_TESTNET_ACCOUNTS
        .iter()
        .map(|account_id| {
            AccountId::from_str(account_id).unwrap_or_else(|_| {
                panic!("Failed to convert an endowed account ID: {account_id:?}")
            })
        })
        .collect()
}
