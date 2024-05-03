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
use project_root::get_project_root;
use sp_core::{crypto::Ss58Codec, sr25519};
use std::{fs::File, io::Read};

pub fn endowed_accounts_dev() -> Vec<AccountId> {
    // handle user submitted file for tokens
    let mut externally_endowed_accounts: Vec<String> = Vec::new();
    let project_root = get_project_root();
    if let Ok(project_root) = project_root {
        let mut file = File::open(project_root.join("data/testnet/testnet-accounts.json"))
            .expect("unable to open testnet-accounts.json");
        let mut data = String::new();
        file.read_to_string(&mut data).expect("Unable to read file");
        let mut incoming_accounts: Vec<String> =
            serde_json::from_str(&data).expect("JSON parse error");
        externally_endowed_accounts.append(&mut incoming_accounts)
    };

    let mut inital_accounts = vec![
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
    ];

    for address in externally_endowed_accounts {
        inital_accounts.push(
            AccountId::from_string(&address).unwrap_or_else(|_| {
                panic!("failed to convert a testnet_address address: {}", address)
            }),
        )
    }

    inital_accounts
}
