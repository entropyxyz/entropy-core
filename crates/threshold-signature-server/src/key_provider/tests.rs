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
    helpers::{
        tests::{initialize_test_logger, setup_client},
        validator::get_signer_and_x25519_secret_from_mnemonic,
    },
    key_provider::api::{
        make_key_backup, request_backup_encryption_key, request_recover_encryption_key,
        KeyProviderDetails,
    },
    launch::{development_mnemonic, ValidatorName},
    SubxtAccountId32,
};
use entropy_kvdb::clean_tests;
use entropy_shared::user::ValidatorInfo;
use entropy_testing_utils::{
    constants::{TSS_ACCOUNTS, X25519_PUBLIC_KEYS},
    helpers::spawn_tss_nodes_and_start_chain,
    ChainSpecType,
};
use serial_test::serial;
use sp_keyring::AccountKeyring;

#[tokio::test]
#[serial]
async fn key_provider_test() {
    clean_tests();
    initialize_test_logger().await;

    let (_ctx, api, rpc, _validator_ips, _validator_ids) =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    let storage_path = ".entropy/testing/test_db_validator1".into();
    let key = [0; 32]; // TODO this should be the actual key used. Since we dont have access to
                       // kvmanager, alice bob etc. should use known keys

    let mnemonic = development_mnemonic(&Some(ValidatorName::Alice));
    let (tss_signer, _static_secret) =
        get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();

    make_key_backup(&api, &rpc, key, tss_signer.signer(), storage_path).await.unwrap();
}

#[tokio::test]
#[serial]
async fn key_provider_unit_test() {
    clean_tests();
    initialize_test_logger().await;
    setup_client().await;
    let key_provider_details = KeyProviderDetails {
        provider: ValidatorInfo {
            tss_account: TSS_ACCOUNTS[0].clone(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            ip_address: "127.0.0.1:3001".to_string(),
        },
        tss_account: SubxtAccountId32(AccountKeyring::Bob.to_raw_public()),
    };
    let key = [1; 32];

    let mnemonic = development_mnemonic(&Some(ValidatorName::Bob));
    let (tss_signer, _static_secret) =
        get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();

    request_backup_encryption_key(key, key_provider_details.clone(), tss_signer.signer())
        .await
        .unwrap();
    let recovered_key = request_recover_encryption_key(key_provider_details).await.unwrap();
    assert_eq!(key, recovered_key);
}
