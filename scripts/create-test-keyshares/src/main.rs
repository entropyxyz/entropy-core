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
use entropy_shared::DETERMINISTIC_KEY_SHARE_EVE;
use entropy_testing_utils::create_test_keyshares::create_test_keyshares;
use sp_keyring::AccountKeyring;
use std::{env::args, path::PathBuf};

#[tokio::main]
async fn main() {
    let base_path = PathBuf::from(args().nth(1).unwrap_or_else(|| ".".to_string()));

    let keyshares_with_aux_infos = create_test_keyshares(
        *DETERMINISTIC_KEY_SHARE_EVE,
        AccountKeyring::Alice.pair(),
        AccountKeyring::Bob.pair(),
        AccountKeyring::Charlie.pair(),
    )
    .await;
    let names = ["alice", "bob", "charlie"];
    for (i, keyshare_with_aux_info) in keyshares_with_aux_infos.iter().enumerate() {
        let keyshare_with_aux_info_bytes = serialize(&keyshare_with_aux_info).unwrap();
        let filename = format!("eve-keyshare-held-by-{}.keyshare", names[i]);
        let mut filepath = base_path.clone();
        filepath.push(filename);
        println!("Writing keyshare file: {:?}", filepath);
        std::fs::write(filepath, keyshare_with_aux_info_bytes).unwrap();
    }
}
