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
use super::api::{check_balance_for_fees, check_forbidden_key};
use crate::{
    chain_api::{
        entropy::{self, runtime_types::bounded_collections::bounded_vec},
        get_api, get_rpc, EntropyConfig,
    },
    helpers::{
        launch::{development_mnemonic, ValidatorName, FORBIDDEN_KEYS},
        substrate::submit_transaction,
        tests::initialize_test_logger,
        validator::{get_hkdf_from_mnemonic, get_signer_from_hkdf},
    },
    r#unsafe::api::UnsafeQuery,
    validator::errors::ValidatorErr,
};
use entropy_kvdb::clean_tests;
use entropy_shared::{OcwMessageReshare, EVE_VERIFYING_KEY, MIN_BALANCE};
use entropy_testing_utils::{
    constants::{ALICE_STASH_ADDRESS, RANDOM_ACCOUNT},
    spawn_testing_validators,
    substrate_context::testing_context,
    test_context_stationary,
};
use parity_scale_codec::Encode;
use serial_test::serial;
use sp_keyring::AccountKeyring;
use subxt::{
    backend::legacy::LegacyRpcMethods, ext::sp_core::sr25519, tx::PairSigner, OnlineClient,
};

#[tokio::test]
#[serial]
async fn test_reshare() {
    initialize_test_logger().await;
    clean_tests();

    let alice = AccountKeyring::Alice;
    let alice_program = AccountKeyring::Charlie;
    let program_manager = AccountKeyring::Dave;

    let cxt = test_context_stationary().await;
    let (_validator_ips, _validator_ids) = spawn_testing_validators(true).await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();

    let client = reqwest::Client::new();
    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;

    let mut onchain_reshare_request =
        OcwMessageReshare { new_signer: alice.public().encode(), block_number };
    setup_for_reshare(&api, &rpc).await;
    // fails repeated data
    let _ = client
        .post("http://127.0.0.1:3001/validator/reshare")
        .body(onchain_reshare_request.clone().encode())
        .send()
        .await
        .unwrap();
    clean_tests();
}

async fn setup_for_reshare(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) {
    let client = reqwest::Client::new();
    let alice = AccountKeyring::Alice;
    let signer = PairSigner::<EntropyConfig, sr25519::Pair>::new(alice.clone().into());

    let jump_start_request = entropy::tx().registry().jump_start_network();
    let _result = submit_transaction(api, rpc, &signer, &jump_start_request, None).await.unwrap();

    let validators_names = vec![ValidatorName::Alice, ValidatorName::Bob];
    for validator_name in validators_names {
        let mnemonic = development_mnemonic(&Some(validator_name));
        let hkdf = get_hkdf_from_mnemonic(&mnemonic.to_string()).unwrap();
        let tss_signer = get_signer_from_hkdf(&hkdf).unwrap();

        let jump_start_confirm_request = entropy::tx()
            .registry()
            .confirm_jump_start(bounded_vec::BoundedVec(EVE_VERIFYING_KEY.to_vec()));

        submit_transaction(api, rpc, &tss_signer, &jump_start_confirm_request, None).await.unwrap();
    }
}
#[tokio::test]
#[should_panic = "Account does not exist, add balance"]
async fn test_check_balance_for_fees() {
    initialize_test_logger().await;
    let cxt = testing_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();

    let result = check_balance_for_fees(&api, &rpc, ALICE_STASH_ADDRESS.to_string(), MIN_BALANCE)
        .await
        .unwrap();

    assert!(result);

    let result_2 = check_balance_for_fees(
        &api,
        &rpc,
        ALICE_STASH_ADDRESS.to_string(),
        10000000000000000000000u128,
    )
    .await
    .unwrap();
    assert!(!result_2);

    let _ = check_balance_for_fees(&api, &rpc, (&RANDOM_ACCOUNT).to_string(), MIN_BALANCE)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_forbidden_keys() {
    initialize_test_logger().await;
    let should_fail = check_forbidden_key(FORBIDDEN_KEYS[0]);
    assert_eq!(should_fail.unwrap_err().to_string(), ValidatorErr::ForbiddenKey.to_string());

    let should_pass = check_forbidden_key("test");
    assert_eq!(should_pass.unwrap(), ());
}
