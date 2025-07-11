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

use entropy_client::logger::initialize_test_logger;
use entropy_kvdb::clean_tests;
use serial_test::serial;

use crate::{
    helpers::tests::{put_keyshares_in_state, setup_client, unsafe_get_network_keyshare},
    launch::ValidatorName,
};

#[tokio::test]
#[serial]
async fn test_unsafe_get_network_key() {
    clean_tests();
    initialize_test_logger().await;
    let app_state = setup_client().await;
    let client = reqwest::Client::new();

    assert!(unsafe_get_network_keyshare(&client, 3001).await.is_none());
    put_keyshares_in_state(ValidatorName::Alice, &app_state).await;
    assert!(unsafe_get_network_keyshare(&client, 3001).await.is_some());

    clean_tests();
}
