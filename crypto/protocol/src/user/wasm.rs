use subxt::utils::AccountId32;
use subxt_signer::sr25519;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::user_participates_in_dkg_protocol;
use crate::ValidatorInfo;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub async fn run_dkg_protocol(
    _validators_info: Vec<u8>,
    user_signing_keypair_seed: Vec<u8>,
    x25519_private_key_vec: Vec<u8>,
) -> String {
    // ) -> Result<KeyShare<KeyParams>, UserRunningProtocolErr> {
    let validators_info = vec![ValidatorInfo {
        x25519_public_key: [0; 32],
        ip_address: "127.0.0.1:3001".parse().unwrap(),
        tss_account: AccountId32([0; 32]),
    }];

    let seed: [u8; 32] = user_signing_keypair_seed.try_into().unwrap();
    let user_signing_keypair = sr25519::Keypair::from_seed(seed).unwrap();

    let x25519_private_key_raw: [u8; 32] = x25519_private_key_vec.try_into().unwrap();
    let x25519_private_key: x25519_dalek::StaticSecret = x25519_private_key_raw.into();

    let result = user_participates_in_dkg_protocol(
        validators_info,
        &user_signing_keypair,
        &x25519_private_key,
    )
    .await;

    format!("{:?}", result)
}
