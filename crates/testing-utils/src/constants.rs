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
        hex!["e0543c102def9f6ef0e8b8ffa31aa259167a9391566929fd718a1ccdaabdb876"].into(),
        hex!["2a8200850770290c7ea3b50a8ff64c6761c882ff8393dc95fccb5d1475eff17f"].into()
    ];
    pub static ref X25519_PUBLIC_KEYS: Vec<[u8; 32]> = vec![
        vec![
            10, 192, 41, 240, 184, 83, 178, 59, 237, 101, 45, 109, 13, 230, 155, 124, 195, 141,
            148, 249, 55, 50, 238, 252, 133, 181, 134, 30, 144, 247, 58, 34,
        ]
        .try_into()
        .unwrap(),
        vec![
            225, 48, 135, 211, 227, 213, 170, 21, 1, 189, 118, 158, 255, 87, 245, 89, 36, 170, 169,
            181, 68, 201, 210, 178, 237, 247, 101, 80, 153, 136, 102, 10,
        ]
        .try_into()
        .unwrap(),
    ];
}

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
