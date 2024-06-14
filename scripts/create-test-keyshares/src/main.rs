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

//! Create threshold keyshares for use in tests
//! The base path for where to store keyshares is given as a single command line argument
//! If it is not given, the current working directory is used
use entropy_kvdb::kv_manager::helpers::serialize;
use entropy_shared::{DETERMINISTIC_KEY_SHARE_DAVE, DETERMINISTIC_KEY_SHARE_EVE};
use entropy_testing_utils::create_test_keyshares::create_test_keyshares;
use entropy_tss::helpers::{
    launch::{DEFAULT_ALICE_MNEMONIC, DEFAULT_BOB_MNEMONIC, DEFAULT_CHARLIE_MNEMONIC},
    validator::get_signer_and_x25519_secret_from_mnemonic,
};
use std::{env::args, path::PathBuf};
use synedrion::{ProductionParams, TestParams};

#[tokio::main]
async fn main() {
    let base_path = PathBuf::from(args().nth(1).unwrap_or_else(|| ".".to_string()));

    let (alice_pair, _) =
        get_signer_and_x25519_secret_from_mnemonic(DEFAULT_ALICE_MNEMONIC).unwrap();
    let (bob_pair, _) = get_signer_and_x25519_secret_from_mnemonic(DEFAULT_BOB_MNEMONIC).unwrap();
    let (charlie_pair, _) =
        get_signer_and_x25519_secret_from_mnemonic(DEFAULT_CHARLIE_MNEMONIC).unwrap();

    let names_and_secret_keys =
        [("dave", *DETERMINISTIC_KEY_SHARE_DAVE), ("eve", *DETERMINISTIC_KEY_SHARE_EVE)];

    for (name, secret_key) in names_and_secret_keys {
        let test_keyshares = create_test_keyshares::<TestParams>(
            secret_key,
            alice_pair.signer().clone(),
            bob_pair.signer().clone(),
            charlie_pair.signer().clone(),
        )
        .await;
        let test_keyshres_serialized =
            test_keyshares.iter().map(|k| serialize(k).unwrap()).collect();
        write_keyshares(base_path.join("test"), name, test_keyshres_serialized).await;

        let production_keyshares = create_test_keyshares::<ProductionParams>(
            secret_key,
            alice_pair.signer().clone(),
            bob_pair.signer().clone(),
            charlie_pair.signer().clone(),
        )
        .await;
        let production_keyshres_serialized =
            production_keyshares.iter().map(|k| serialize(k).unwrap()).collect();
        write_keyshares(base_path.join("production"), name, production_keyshres_serialized).await;
    }
}

async fn write_keyshares(base_path: PathBuf, name: &str, keyshares_bytes: Vec<Vec<u8>>) {
    let holder_names = ["alice", "bob", "charlie"];
    for (i, bytes) in keyshares_bytes.iter().enumerate() {
        let filename = format!("{}-keyshare-held-by-{}.keyshare", name, holder_names[i]);
        let mut filepath = base_path.clone();
        filepath.push(filename);
        println!("Writing keyshare file: {:?}", filepath);
        std::fs::write(filepath, bytes).unwrap();
    }
}
