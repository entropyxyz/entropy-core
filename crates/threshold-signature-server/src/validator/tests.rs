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

use std::time::SystemTime;

use entropy_kvdb::clean_tests;
use entropy_shared::{DAVE_VERIFYING_KEY, EVE_VERIFYING_KEY, FERDIE_VERIFYING_KEY, MIN_BALANCE};
use entropy_testing_utils::{
    constants::{ALICE_STASH_ADDRESS, RANDOM_ACCOUNT},
    substrate_context::{
        test_context_stationary, test_node_process_testing_state, testing_context,
    },
};
use serial_test::serial;
use sp_core::{sr25519, Pair};
use subxt::tx::PairSigner;

use super::api::{check_balance_for_fees, check_forbidden_key};
use crate::{
    chain_api::{entropy, get_api, get_rpc, EntropyConfig},
    helpers::{
        launch::{
            ValidatorName, DEFAULT_ALICE_MNEMONIC, DEFAULT_BOB_MNEMONIC, DEFAULT_MNEMONIC,
            FORBIDDEN_KEYS,
        },
        substrate::{get_registered_details, get_stash_address, query_chain},
        tests::{create_clients, initialize_test_logger},
        validator::get_signer_and_x25519_secret_from_mnemonic,
    },
    validation::{mnemonic_to_pair, new_mnemonic, EncryptedSignedMessage, TIME_BUFFER},
    validator::errors::ValidatorErr,
};

#[tokio::test]
#[should_panic = "Account does not exist, add balance"]
async fn test_check_balance_for_fees() {
    initialize_test_logger().await;
    clean_tests();

    let cxt = testing_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();

    let result =
        check_balance_for_fees(&api, &rpc, ALICE_STASH_ADDRESS.to_string(), MIN_BALANCE).await.unwrap();

    assert!(result);

    let result_2 =
        check_balance_for_fees(&api, &rpc, ALICE_STASH_ADDRESS.to_string(), 10000000000000000000000u128)
            .await
            .unwrap();
    assert!(!result_2);

    let _ = check_balance_for_fees(&api, &rpc, RANDOM_ACCOUNT.to_string(), MIN_BALANCE).await.unwrap();
    clean_tests();
}

#[tokio::test]
async fn test_forbidden_keys() {
    initialize_test_logger().await;
    clean_tests();
    let should_fail = check_forbidden_key(FORBIDDEN_KEYS[0]);
    assert_eq!(should_fail.unwrap_err().to_string(), ValidatorErr::ForbiddenKey.to_string());

    let should_pass = check_forbidden_key("test");
    assert_eq!(should_pass.unwrap(), ());
    clean_tests();
}
