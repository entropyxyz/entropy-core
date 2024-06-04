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

use hex_literal::hex;
use subxt::utils::AccountId32;

lazy_static! {
    pub static ref ALICE_STASH_ADDRESS: AccountId32 = hex!["be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f"].into();
    pub static ref RANDOM_ACCOUNT: AccountId32 = hex!["8676839ca1e196624106d17c56b1efbb90508a86d8053f7d4fcd21127a9f7565"].into();
    pub static ref VALIDATOR_1_STASH_ID: AccountId32 =
        hex!["be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f"].into(); // alice stash;
    pub static ref BOB_STASH_ADDRESS: AccountId32 =
        hex!["fe65717dad0447d715f660a0a58411de509b42e6efb8375f562f58a554d5860e"].into(); // subkey inspect //Bob//stash
    pub static ref TSS_ACCOUNTS: Vec<AccountId32> = vec![
        hex!["306bdb49cbbe7104e3621abab3c9d31698b159f48dafe567abb7ea5d872ed329"].into(),
        hex!["2cbc68e8bf0fbc1c28c282d1263fc9d29267dc12a1044fb730e8b65abc37524c"].into(),
        hex!["946140d3d5ddb980c74ffa1bb64353b5523d2d77cdf3dc617fd63de9d3b66338"].into(),
    ];
    pub static ref X25519_PUBLIC_KEYS: Vec<[u8; 32]> = vec![
        vec![
            8, 22, 19, 230, 107, 217, 249, 190, 14, 142, 155, 252, 156, 229, 120, 11, 180, 35, 83, 245,
            222, 11, 153, 201, 162, 29, 153, 13, 123, 126, 128, 32,
        ]
        .try_into()
        .unwrap(),
        vec![
            196, 53, 98, 10, 160, 169, 139, 48, 194, 230, 69, 64, 165, 48, 133, 110, 38, 64, 184, 113,
            255, 201, 253, 212, 217, 21, 252, 57, 253, 78, 0, 56,
        ]
        .try_into()
        .unwrap(),
        vec![
            131, 8, 162, 77, 237, 245, 226, 179, 250, 79, 121, 250, 174, 181, 227, 122, 205, 181, 188,
            4, 37, 87, 150, 250, 210, 151, 203, 137, 188, 134, 124, 108,
        ]
        .try_into()
        .unwrap(),
    ];
}

/// This is a random secret key for Ferdie used in some negative tests
pub const FERDIE_X25519_SECRET_KEY: [u8; 32] = [
    5, 221, 127, 62, 254, 131, 37, 194, 88, 126, 130, 15, 97, 249, 170, 40, 201, 135, 77, 213, 55,
    87, 243, 127, 175, 77, 251, 75, 157, 119, 41, 180,
];

/// The following constants are values used for integration testing specific to the
/// `example_barebones_with_auxilary.wasm` from the `programs` repo.
pub const TEST_PROGRAM_WASM_BYTECODE: &[u8] =
    include_bytes!("../example_barebones_with_auxilary.wasm");
/// `infinite_loop.wasm` from the `programs` repo.
pub const TEST_INFINITE_LOOP_BYTECODE: &[u8] = include_bytes!("../infinite_loop.wasm");
/// `template_basic_transaction.wasm` from the `programs` repo.
pub const TEST_BASIC_TRANSACTION: &[u8] = include_bytes!("../template_basic_transaction.wasm");
/// `example_custom_hash.wasm` from the `programs` repo.
pub const TEST_PROGRAM_CUSTOM_HASH: &[u8] = include_bytes!("../example_custom_hash.wasm");
pub const PREIMAGE_SHOULD_SUCCEED: &[u8] = "asdfasdfasdfasdf".as_bytes();
pub const PREIMAGE_SHOULD_FAIL: &[u8] = "asdf".as_bytes();
pub const AUXILARY_DATA_SHOULD_SUCCEED: &[u8] = "fdsafdsa".as_bytes();
pub const AUXILARY_DATA_SHOULD_FAIL: Option<&[u8]> = None;
