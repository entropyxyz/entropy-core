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
    chain_api::{entropy, get_api, get_rpc},
    helpers::{
        substrate::query_chain,
        tests::{initialize_test_logger, spawn_testing_validators, ChainSpecType},
    },
};
use entropy_kvdb::clean_tests;
use entropy_testing_utils::{
    constants::BOB_STASH_ADDRESS, substrate_context::test_node_process_stationary,
};
use serial_test::serial;
use subxt::utils::AccountId32;
use tdx_quote::{decode_verifying_key, Quote};

#[tokio::test]
#[serial]
async fn test_get_attest() {
    initialize_test_logger().await;
    clean_tests();

    let cxt = test_node_process_stationary().await;
    let (_validator_ips, _validator_ids) =
        spawn_testing_validators(ChainSpecType::Integration).await;

    let api = get_api(&cxt.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.ws_url).await.unwrap();

    let quote_bytes = reqwest::get("http://127.0.0.1:3002/v1/attest?context=validate")
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let quote = Quote::from_bytes(&quote_bytes).unwrap();

    let query =
        entropy::storage().staking_extension().threshold_servers(&AccountId32(BOB_STASH_ADDRESS.0));
    let server_info = query_chain(&api, &rpc, query, None).await.unwrap().unwrap();

    let provisioning_certification_key =
        decode_verifying_key(&server_info.provisioning_certification_key.0.try_into().unwrap())
            .unwrap();

    assert!(quote.verify_with_pck(&provisioning_certification_key).is_ok())
}
