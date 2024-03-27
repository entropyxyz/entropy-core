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
    // from entropy::chain_spec::tss_x25518_public_key::{ALICE, BOB}
    pub static ref X25519_PUBLIC_KEYS: Vec<[u8; 32]> = vec![
        vec![
        16, 111, 127, 91, 129, 204, 17, 200, 174, 180, 197, 116, 151, 176, 43, 99, 41, 1, 85, 15,
        97, 198, 204, 158, 146, 160, 225, 77, 93, 160, 9, 63,
        ]
        .try_into()
        .unwrap(),
        vec![
        14, 178, 119, 7, 68, 36, 76, 17, 46, 164, 28, 108, 235, 70, 235, 246, 242, 37, 17, 128,
        197, 129, 232, 161, 83, 27, 145, 116, 210, 180, 189, 125,
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
