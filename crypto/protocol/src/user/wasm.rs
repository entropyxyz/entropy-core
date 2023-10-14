use js_sys::Error;
use subxt::utils::AccountId32;
use subxt_signer::sr25519;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use wasm_bindgen_derive::TryFromJsValue;

use super::user_participates_in_dkg_protocol;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub async fn run_dkg_protocol(
    validators_info_js: ValidatorInfoArray,
    user_signing_keypair_seed: Vec<u8>,
    x25519_private_key_vec: Vec<u8>,
) -> Result<String, Error> {
    // ) -> Result<KeyShare<KeyParams>, UserRunningProtocolErr> {
    let js_val: &JsValue = validators_info_js.as_ref();
    let array: &js_sys::Array =
        js_val.dyn_ref().ok_or_else(|| Error::new("The argument must be an array"))?;
    let length: usize = array.length().try_into().map_err(|err| Error::new(&format!("{}", err)))?;
    let mut validators_info = Vec::<ValidatorInfo>::with_capacity(length);
    for js in array.iter() {
        let typed_elem = ValidatorInfo::try_from(&js).map_err(|err| Error::new(&err))?;
        validators_info.push(typed_elem);
    }

    let seed: [u8; 32] = user_signing_keypair_seed.try_into().unwrap();
    let user_signing_keypair = sr25519::Keypair::from_seed(seed).unwrap();

    let x25519_private_key_raw: [u8; 32] = x25519_private_key_vec.try_into().unwrap();
    let x25519_private_key: x25519_dalek::StaticSecret = x25519_private_key_raw.into();
	unimplemented!();
    // let key_share = user_participates_in_dkg_protocol(
    //     validators_info.0,
    //     &user_signing_keypair,
    //     &x25519_private_key,
    // )
    // .await
    // .map_err(|err| Error::new(&format!("{}", err)))?;
    //
    // // TODO decide how to return KeyShare
    // Ok(format!("{:?}", key_share))
}

// #[cfg_attr(feature = "wasm", wasm_bindgen)]
// pub async fn run_signing_protocol(
//     key_share: &KeyShare<KeyParams>,
//     sig_uid: &str,
//     sig_hash: [u8; 32],
// validators_info: ValidatorInfoArray,
// user_signing_keypair_seed: Vec<u8>,
// x25519_private_key_vec: Vec<u8>,
// ) -> Result<RecoverableSignature, UserRunningProtocolErr> {

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "ValidatorInfo[]")]
    pub type ValidatorInfoArray;
}

/// Details of a validator
#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone)]
pub struct ValidatorInfo(crate::ValidatorInfo);

#[wasm_bindgen]
impl ValidatorInfo {
    #[wasm_bindgen(js_name = new)]
    pub fn new(
        x25519_public_key_vec: Vec<u8>,
        ip_address: String,
        tss_account: Vec<u8>,
    ) -> Result<ValidatorInfo, Error> {
        let x25519_public_key: [u8; 32] = x25519_public_key_vec.try_into().unwrap(); //.map_err(|err| Error::new(&format!("{}", err)))?;
        let validator_info = crate::ValidatorInfo {
            x25519_public_key,
            ip_address: ip_address.parse().map_err(|err| Error::new(&format!("{}", err)))?,
            tss_account: AccountId32(
                tss_account.try_into().unwrap(), //.map_err(|err| Error::new(&format!("{}", err)))?,
            ),
        };
        Ok(Self(validator_info))
    }
}
