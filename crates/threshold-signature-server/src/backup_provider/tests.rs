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

use std::path::PathBuf;

use crate::{
    backup_provider::api::{
        get_key_provider_details, make_key_backup, request_backup_encryption_key,
        request_recover_encryption_key, BackupProviderDetails,
    },
    helpers::{
        tests::initialize_test_logger, validator::get_signer_and_x25519_secret_from_mnemonic,
    },
    launch::{development_mnemonic, ValidatorName},
};
use entropy_kvdb::clean_tests;
use entropy_shared::user::ValidatorInfo;
use entropy_testing_utils::{
    constants::{TSS_ACCOUNTS, X25519_PUBLIC_KEYS},
    helpers::{spawn_tss_nodes_and_start_chain, TssTestingResult},
    ChainSpecType,
};
use serial_test::serial;

/// This tests the whole process of selecting and using a backup provider
#[tokio::test]
#[serial]
async fn backup_provider_test() {
    clean_tests();
    initialize_test_logger().await;

    let TssTestingResult {
        substrate_context: _ctx,
        api,
        rpc,
        validator_ips: _validator_ips,
        validator_ids: _validator_ids,
    } = spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    let storage_path: PathBuf = ".entropy/testing/test_db_validator1".into();
    // For testing we use TSS account ID as the db encryption key
    let key = TSS_ACCOUNTS[0].0;

    let mnemonic = development_mnemonic(&Some(ValidatorName::Alice));
    let (tss_signer, _static_secret) =
        get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();

    make_key_backup(&api, &rpc, key, tss_signer.signer(), storage_path.clone()).await.unwrap();

    let key_provider_details = get_key_provider_details(storage_path).unwrap();
    let recovered_key = request_recover_encryption_key(key_provider_details).await.unwrap();
    assert_eq!(key, recovered_key);
}

/// More low-level version of key_backup_provider_test
#[tokio::test]
#[serial]
async fn backup_provider_unit_test() {
    clean_tests();
    initialize_test_logger().await;

    let _spawn_result =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    let key_provider_details = BackupProviderDetails {
        provider: ValidatorInfo {
            tss_account: TSS_ACCOUNTS[0].clone(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            ip_address: "127.0.0.1:3001".to_string(),
        },
        tss_account: TSS_ACCOUNTS[1].clone(),
    };
    // For testing we use TSS account ID as the db encryption key
    let key = TSS_ACCOUNTS[1].0;

    let mnemonic = development_mnemonic(&Some(ValidatorName::Bob));
    let (tss_signer, _static_secret) =
        get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();

    request_backup_encryption_key(key, key_provider_details.clone(), tss_signer.signer())
        .await
        .unwrap();
    let recovered_key = request_recover_encryption_key(key_provider_details).await.unwrap();
    assert_eq!(key, recovered_key);
}
