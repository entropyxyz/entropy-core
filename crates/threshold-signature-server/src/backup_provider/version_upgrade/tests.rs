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
    backup_provider::api::make_key_backup,
    chain_api::entropy,
    get_api, get_rpc,
    helpers::{
        tests::{create_clients, initialize_test_logger},
        validator::get_signer_and_x25519_secret_from_mnemonic,
    },
    launch::{development_mnemonic, ValidatorName},
    SubxtAccountId32,
};
use entropy_client::{
    client::request_backup_encrypted_db, request_recover_encrypted_db, substrate::query_chain,
};
use entropy_kvdb::clean_tests;
use entropy_testing_utils::test_node_process_testing_state;
use entropy_testing_utils::{
    constants::TSS_ACCOUNTS, helpers::spawn_tss_nodes_and_start_chain, ChainSpecType,
};
use serial_test::serial;
use sp_core::{sr25519, Pair};
use std::path::PathBuf;

#[test]
#[serial]
fn encrypted_db_backup_test() {
    clean_tests();

    // To simulate stopping the TSS node we make the backup in and starting a fresh one for recovery
    // we use one tokio runtime to make the backup which allows us to drop the TSS task before
    // starting another one for the recovery
    let (db_dump, stash_account, port) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            initialize_test_logger().await;

            let (_ctx, api, rpc, _validator_ips, _validator_ids) =
                spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

            // Db dumps can only be made by non-signers, so find who is not currently a signer and get
            // their stash stash_account
            let (non_signer_stash_account, position) = {
                let stash_accounts = vec![
                    sr25519::Pair::from_string("//Alice//stash", None).unwrap(),
                    sr25519::Pair::from_string("//Bob//stash", None).unwrap(),
                    sr25519::Pair::from_string("//Charlie//stash", None).unwrap(),
                    sr25519::Pair::from_string("//Dave//stash", None).unwrap(),
                ];
                // Get current signers
                let signer_query = entropy::storage().staking_extension().signers();
                let signer_stash_accounts =
                    query_chain(&api, &rpc, signer_query, None).await.unwrap().unwrap();

                let position = stash_accounts
                    .iter()
                    .position(|s| !signer_stash_accounts.contains(&SubxtAccountId32(s.public().0)))
                    .unwrap();
                let stash_account = stash_accounts[position].clone();
                (stash_account, position)
            };

            // Make an encryption key backup - without this we are unable to backup the encrypted db as it
            // expects to find the associated details
            let storage_path: PathBuf =
                format!(".entropy/testing/test_db_validator{}", position + 1).into();
            // For testing we use TSS account ID as the db encryption key
            let key = TSS_ACCOUNTS[position].0;

            let validator_name = match position {
                0 => ValidatorName::Alice,
                1 => ValidatorName::Bob,
                2 => ValidatorName::Charlie,
                3 => ValidatorName::Dave,
                _ => panic!("Unexpected position"),
            };
            let mnemonic = development_mnemonic(&Some(validator_name));
            let (tss_signer, _static_secret) =
                get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();

            make_key_backup(&api, &rpc, key, tss_signer.signer(), storage_path.clone())
                .await
                .unwrap();

            // Get a db dump
            let db_dump = request_backup_encrypted_db(&api, &rpc, non_signer_stash_account.clone())
                .await
                .unwrap();

            let port = 3001 + position;
            (db_dump, non_signer_stash_account, port)
        });

    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        // Start chain node
        let force_authoring = true;
        let context =
            test_node_process_testing_state(ChainSpecType::IntegrationJumpStarted, force_authoring)
                .await;
        let api = get_api(&context[0].ws_url).await.unwrap();
        let rpc = get_rpc(&context[0].ws_url).await.unwrap();

        // Start TSS node eve - who is not in the staking pallet chainspec
        let (axum, _kv, _id) =
            create_clients("validator5".to_string(), vec![], vec![], &Some(ValidatorName::Eve))
                .await;

        // We need to use the ip and port associated with the original TSS node
        let tcp_socket = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
            .await
            .expect("Unable to bind to given server address.");
        tokio::spawn(async move {
            axum::serve(tcp_socket, axum).await.unwrap();
        });

        // Attempt to recover
        request_recover_encrypted_db(&api, &rpc, stash_account, db_dump).await.unwrap();
    });
}
