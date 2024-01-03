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

use axum::http::StatusCode;
use entropy_kvdb::clean_tests;
use serial_test::serial;

use super::api::UnsafeQuery;
use crate::helpers::tests::{initialize_test_logger, setup_client};

#[tokio::test]
#[serial]
async fn test_unsafe_get_endpoint() {
    initialize_test_logger().await;
    setup_client().await;
    let client = reqwest::Client::new();

    let get_query = UnsafeQuery::new("MNEMONIC".to_string(), vec![10]).to_json();

    // Test that the get endpoint works
    let response = client
        .post("http://localhost:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let response_mnemonic = response.text().await.unwrap();
    assert!(!response_mnemonic.is_empty());

    // Update the mnemonic, testing the put endpoint works
    let put_response = client
        .post("http://localhost:3001/unsafe/put")
        .header("Content-Type", "application/json")
        .body(get_query.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(put_response.status(), StatusCode::OK);

    // Check the updated mnemonic is the new value
    let get_response = client
        .post("http://localhost:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query)
        .send()
        .await
        .unwrap();

    assert_eq!(get_response.status(), StatusCode::OK);
    let updated_response_mnemonic = get_response.text().await.unwrap();
    assert_eq!(updated_response_mnemonic.as_bytes().to_vec(), vec![10]);

    clean_tests();
}
