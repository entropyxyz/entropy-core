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

//! An encrypted key-value store used for storing keyshares and other private data
pub mod encrypted_sled;
pub mod kv_manager;
use std::{fs, path::PathBuf};

pub fn get_db_path(testing: bool) -> String {
    let mut root: PathBuf = std::env::current_dir().expect("could not get home directory");
    root.push(".entropy");
    if testing {
        root.push("testing");
    } else {
        root.push("production");
    }
    root.push("db");
    let result: String = root.clone().display().to_string();
    fs::create_dir_all(root)
        .unwrap_or_else(|_| panic!("could not create database path at: {}", result.clone()));
    result
}

pub fn clean_tests() {
    let db_path = get_db_path(true);
    if fs::metadata(db_path).is_ok() {
        let _result = std::fs::remove_dir_all(db_path);
    }
}
