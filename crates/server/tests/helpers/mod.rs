//! Helper functions for integration tests
use entropy_protocol::KeyParams;
use server::launch::{DEFAULT_BOB_MNEMONIC, DEFAULT_MNEMONIC};
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
        let mnemonic = if i == 0 { DEFAULT_MNEMONIC } else { DEFAULT_BOB_MNEMONIC };
        let sk = <sr25519::Pair as Pair>::from_string(mnemonic, None).unwrap();
        let sig_recovery = <sr25519::Pair as Pair>::verify(
            &signing_result.clone().unwrap().1,
            base64::decode(signing_result.unwrap().0).unwrap(),
            &sr25519::Public(sk.public().0),
        );
        assert!(sig_recovery);
        i += 1;
    }
}
