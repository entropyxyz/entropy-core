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

use crate::helpers::tests::{initialize_test_logger, setup_client};
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
