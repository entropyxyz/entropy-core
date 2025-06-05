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

use std::{env, fs, path::Path};
use substrate_build_script_utils::{generate_cargo_keys, rerun_if_git_head_changed};

fn main() {
    generate_cargo_keys();

    rerun_if_git_head_changed();

    // Read testnet endowed accounts from file at compile time
    let testnet_accounts_file = "../../data/testnet/testnet-accounts.json";
    let json_str = fs::read_to_string(testnet_accounts_file)
        .unwrap_or_else(|e| panic!("Failed to read {testnet_accounts_file}: {e}"));
    let accounts_json: Vec<serde_json::Value> = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("Failed to parse {testnet_accounts_file} as JSON: {e}"));

    let num_accounts = accounts_json.len();

    let accounts: Vec<String> = accounts_json
        .into_iter()
        .map(|account| account["address"].as_str().unwrap().to_string())
        .collect();

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("endowed_testnet_accounts.rs");

    fs::write(
        &dest_path,
        format!(
            r#"
            pub static ENDOWED_TESTNET_ACCOUNTS: [&str; {num_accounts}] = {accounts:?};
            "#
        ),
    )
    .unwrap();
}
