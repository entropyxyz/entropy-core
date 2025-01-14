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

use crate::{
    helpers::tests::{initialize_test_logger, setup_client},
    key_provider::api::make_provider_request,
    SubxtAccountId32,
};
use entropy_kvdb::clean_tests;
use entropy_shared::ValidatorInfo;
use entropy_testing_utils::constants::{TSS_ACCOUNTS, X25519_PUBLIC_KEYS};
use serial_test::serial;
use sp_keyring::AccountKeyring;

#[tokio::test]
#[serial]
async fn key_provider_test() {
    clean_tests();
    initialize_test_logger().await;
    setup_client().await;
    let validator_info = ValidatorInfo {
        tss_account: TSS_ACCOUNTS[0].0.to_vec(),
        x25519_public_key: X25519_PUBLIC_KEYS[0],
        ip_address: b"127.0.0.1:3001".to_vec(),
    };
    let tss_account = SubxtAccountId32(AccountKeyring::Bob.to_raw_public());
    let _key = make_provider_request(validator_info, tss_account).await.unwrap();
    // TODO now do it a second time and check key is identical
}
