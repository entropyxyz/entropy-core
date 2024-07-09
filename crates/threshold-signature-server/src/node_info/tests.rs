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
    chain_api::{get_api, get_rpc},
    helpers::tests::{initialize_test_logger, setup_client, spawn_testing_validators},
};
use entropy_client::user::get_current_subgroup_signers;
use entropy_testing_utils::substrate_context::test_context_stationary;

use entropy_kvdb::clean_tests;
use entropy_shared::types::HashingAlgorithm;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn version_test() {
    clean_tests();
    initialize_test_logger().await;
    setup_client().await;
    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:3001/version").send().await.unwrap();
    assert_eq!(
        response.text().await.unwrap(),
        format!("{}-{}", env!("CARGO_PKG_VERSION"), env!("VERGEN_GIT_DESCRIBE"))
    );
    clean_tests();
}

#[tokio::test]
#[serial]
async fn hashes_test() {
    clean_tests();
    initialize_test_logger().await;
    setup_client().await;
    let response = reqwest::get("http://127.0.0.1:3001/hashes").await.unwrap();

    let algorithms: Vec<HashingAlgorithm> = response.json().await.unwrap();
    assert_eq!(
        algorithms,
        vec![
            HashingAlgorithm::Sha1,
            HashingAlgorithm::Sha2,
            HashingAlgorithm::Sha3,
            HashingAlgorithm::Keccak,
            HashingAlgorithm::Blake2_256,
            HashingAlgorithm::Custom(0),
        ]
    );
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_get_subgroup() {
    initialize_test_logger().await;
    clean_tests();

    let _ = spawn_testing_validators(None, false, false).await;
    let substrate_context = test_context_stationary().await;
    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();
    let mock_client = reqwest::Client::new();
    // example keccak hash
    let message_hash = "06b3dfaec148fb1bb2b066f10ec285e7c9bf402ab32aa78a5d38e34566810cd2";
    let response = mock_client
        .post("http://127.0.0.1:3001/subgroup_signers")
        .header("Content-Type", "application/json")
        .body(message_hash)
        .send()
        .await;
    let mock_result = get_current_subgroup_signers(&api, &rpc, &message_hash).await.unwrap();
    assert_eq!(
        serde_json::to_string(&mock_result).unwrap(),
        response.unwrap().text().await.unwrap(),
        "subgroup data should match"
    );
    clean_tests();
}
