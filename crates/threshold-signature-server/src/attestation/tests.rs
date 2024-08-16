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
// use crate::helpers::tests::{initialize_test_logger, spawn_testing_validators};
// use entropy_kvdb::clean_tests;
// use entropy_shared::QuoteInputData;
// use entropy_testing_utils::{
//     constants::{TSS_ACCOUNTS, X25519_PUBLIC_KEYS},
//     substrate_context::test_node_process_testing_state,
// };
// use serial_test::serial;
//
// #[tokio::test]
// #[serial]
// async fn test_attest() {
//     initialize_test_logger().await;
//     clean_tests();
//
// let quote = create_quote(
//     block_number: u32,
//     nonce: [u8; 32],
//     signer: &PairSigner<EntropyConfig, sp_core::sr25519::Pair>,
//     x25519_secret: &StaticSecret,
// ).unwrap();
//     let _cxt = test_node_process_testing_state(false).await;
//     let (_validator_ips, _validator_ids) = spawn_testing_validators(false).await;
//
//     let nonce = [0; 32];
//     let client = reqwest::Client::new();
//     let res = client
//         .post(format!("http://127.0.0.1:3001/attest"))
//         .body(nonce.to_vec())
//         .send()
//         .await
//         .unwrap();
//     assert_eq!(res.status(), 200);
//     let quote = res.bytes().await.unwrap();
//
//     // This internally verifies the signature in the quote
//     let quote = tdx_quote::Quote::from_bytes(&quote).unwrap();
//
//     // Check the input data of the quote
//     let expected_input_data =
//         QuoteInputData::new(TSS_ACCOUNTS[0].0, X25519_PUBLIC_KEYS[0], nonce, 0);
//     assert_eq!(quote.report_input_data(), expected_input_data.0);
// }
