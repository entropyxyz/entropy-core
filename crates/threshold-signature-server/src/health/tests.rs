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
use serial_test::serial;

use crate::helpers::tests::{initialize_test_logger, setup_client};

#[tokio::test]
#[serial]
async fn health() {
    initialize_test_logger().await;
    setup_client().await;

    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:3001/healthz").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
