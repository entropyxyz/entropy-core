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
use entropy_tss::helpers::{
    launch::{
        ValidatorName, DEFAULT_ALICE_MNEMONIC, DEFAULT_BOB_MNEMONIC, DEFAULT_CHARLIE_MNEMONIC,
        DEFAULT_DAVE_MNEMONIC,
    },
    validator::get_signer_and_x25519_secret_from_mnemonic,
};
use sp_core::sr25519;
use std::{env::args, iter::zip, path::PathBuf};
use synedrion::{ProductionParams, TestParams};

#[tokio::main]
async fn main() {
    let base_path = PathBuf::from(args().nth(1).unwrap_or_else(|| ".".to_string()));

    let keypairs_and_names: Vec<_> = [
        (DEFAULT_ALICE_MNEMONIC, ValidatorName::Alice),
        (DEFAULT_BOB_MNEMONIC, ValidatorName::Bob),
        (DEFAULT_CHARLIE_MNEMONIC, ValidatorName::Charlie),
        (DEFAULT_DAVE_MNEMONIC, ValidatorName::Dave),
    ]
    .into_iter()
    .map(|(mnemonic, name)| {
        let (pair, _) = get_signer_and_x25519_secret_from_mnemonic(mnemonic).unwrap();
        (pair.signer().clone(), name)
    })
    .collect();

    let secret_key = *DETERMINISTIC_KEY_SHARE_EVE;

    for (_keypair, name) in keypairs_and_names.iter() {
        let (keypairs_this_time, names_this_time): (Vec<sr25519::Pair>, Vec<ValidatorName>) =
            keypairs_and_names.iter().filter(|(_, n)| n != name).cloned().unzip();

        let keypairs_this_time: [sr25519::Pair; 3] = keypairs_this_time
            .try_into()
            .map_err(|_| "Cannot convert keypair vector to array")
            .unwrap();

        // Create and write test keyshares
        let test_keyshares =
            create_test_keyshares::<TestParams>(secret_key, keypairs_this_time.clone()).await;
        let test_keyshares_serialized: Vec<_> =
            test_keyshares.iter().map(|k| serialize(k).unwrap()).collect();
        let keyshares_and_names = zip(test_keyshares_serialized, names_this_time.clone()).collect();
        write_keyshares(base_path.join("test"), name, keyshares_and_names).await;

        // Create and write production keyshares
        let production_keyshares =
            create_test_keyshares::<ProductionParams>(secret_key, keypairs_this_time.clone()).await;
        let production_keyshres_serialized: Vec<_> =
            production_keyshares.iter().map(|k| serialize(k).unwrap()).collect();
        let keyshares_and_names = zip(production_keyshres_serialized, names_this_time).collect();
        write_keyshares(base_path.join("production"), name, keyshares_and_names).await;
    }
}

async fn write_keyshares(
    base_path: PathBuf,
    name_of_excluded: &ValidatorName,
    keyshares_and_names: Vec<(Vec<u8>, ValidatorName)>,
) {
    for (keyshare, name) in keyshares_and_names {
        let mut filepath = base_path.clone();
        filepath.push(name_of_excluded.to_string());
        let filename = format!("keyshare-held-by-{}.keyshare", name);
        filepath.push(filename);
        println!("Writing keyshare file: {:?}", filepath);
        std::fs::write(filepath, keyshare).unwrap();
    }
}
