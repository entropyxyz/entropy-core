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
    helpers::tests::setup_client,
    node_info::api::{BuildDetails, VersionDetails},
};
use entropy_client::{forest::ServerPublicKeys, logger::initialize_test_logger};
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
    let response = client.get("http://127.0.0.1:3001/v1/version").send().await.unwrap();
    let version_details: VersionDetails =
        serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(
        version_details,
        VersionDetails {
            cargo_package_version: env!("CARGO_PKG_VERSION").to_string(),
            git_tag_commit: env!("VERGEN_GIT_DESCRIBE").to_string(),
            build: BuildDetails::NonProduction,
        }
    );
    clean_tests();
}

#[tokio::test]
#[serial]
async fn hashes_test() {
    clean_tests();
    initialize_test_logger().await;
    setup_client().await;
    let response = reqwest::get("http://127.0.0.1:3001/v1/hashes").await.unwrap();

    let algorithms: Vec<HashingAlgorithm> = response.json().await.unwrap();
    assert_eq!(
        algorithms,
        vec![
            HashingAlgorithm::Sha1,
            HashingAlgorithm::Sha2,
            HashingAlgorithm::Sha3,
            HashingAlgorithm::Keccak,
            HashingAlgorithm::Blake2_256,
            HashingAlgorithm::Identity,
            HashingAlgorithm::Custom(0),
        ]
    );
    clean_tests();
}

#[tokio::test]
#[serial]
async fn info_test() {
    clean_tests();
    initialize_test_logger().await;
    let app_state = setup_client().await;
    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:3001/v1/info").send().await.unwrap();
    let public_keys: ServerPublicKeys = response.json().await.unwrap();

    assert_eq!(public_keys.account_id, app_state.subxt_account_id());
    assert_eq!(public_keys.x25519_public_key, app_state.x25519_public_key());
    assert_eq!(public_keys.ready, Some(app_state.cache.is_ready()));

    clean_tests();
}
