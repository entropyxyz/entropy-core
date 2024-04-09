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

//! Helper functions for integration tests
use entropy_protocol::KeyParams;
use entropy_testing_utils::constants::TSS_ACCOUNTS;
use synedrion::{
    k256::ecdsa::{RecoveryId, Signature as k256Signature, VerifyingKey},
    KeyShare,
};

use subxt::ext::sp_core::{sr25519, sr25519::Signature, Pair};

/// Verfiy a signature in a response from `/user/sign_tx`
pub async fn verify_signature(
    test_user_res: Vec<Result<reqwest::Response, reqwest::Error>>,
    message_should_succeed_hash: [u8; 32],
    keyshare_option: Option<KeyShare<KeyParams>>,
) {
    let mut i = 0;
    for res in test_user_res {
        let mut res = res.unwrap();

        assert_eq!(res.status(), 200);
        let chunk = res.chunk().await.unwrap().unwrap();
        let signing_result: Result<(String, Signature), String> =
            serde_json::from_slice(&chunk).unwrap();
        assert_eq!(signing_result.clone().unwrap().0.len(), 88);
        let mut decoded_sig = base64::decode(signing_result.clone().unwrap().0).unwrap();
        let recovery_digit = decoded_sig.pop().unwrap();
        let signature = k256Signature::from_slice(&decoded_sig).unwrap();
        let recover_id = RecoveryId::from_byte(recovery_digit).unwrap();
        let recovery_key_from_sig = VerifyingKey::recover_from_prehash(
            &message_should_succeed_hash,
            &signature,
            recover_id,
        )
        .unwrap();
        assert_eq!(keyshare_option.clone().unwrap().verifying_key(), recovery_key_from_sig);

        let sig_recovery = <sr25519::Pair as Pair>::verify(
            &signing_result.clone().unwrap().1,
            base64::decode(signing_result.unwrap().0).unwrap(),
            &sr25519::Public(TSS_ACCOUNTS[i].0),
        );
        assert!(sig_recovery);
        i += 1;
    }
}
