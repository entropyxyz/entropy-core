//! Wrappers around functions to run dkg and signing protocols for JS
use std::net::SocketAddrV4;

use js_sys::Error;
use subxt::utils::AccountId32;
use subxt_signer::sr25519;
use synedrion::KeyShare;
use wasm_bindgen::prelude::*;
use wasm_bindgen_derive::TryFromJsValue;

use super::{user_participates_in_dkg_protocol, user_participates_in_signing_protocol};
use crate::KeyParams;

/// Run the DKG protocol on the client side
/// This returns the keypair as a JSON encoded string
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub async fn run_dkg_protocol(
    validators_info_js: ValidatorInfoArray,
    user_signing_keypair_seed: Vec<u8>,
    x25519_private_key_vec: Vec<u8>,
) -> Result<String, Error> {
    let validators_info = parse_validator_info(validators_info_js)?;

    let user_signing_keypair = {
        let seed: [u8; 32] = user_signing_keypair_seed
            .try_into()
            .map_err(|_| Error::new("User signing keypair seed must be 32 bytes"))?;
        sr25519::Keypair::from_seed(seed).map_err(|err| Error::new(&err.to_string()))?
    };

    let x25519_private_key: x25519_dalek::StaticSecret = {
        let x25519_private_key_raw: [u8; 32] = x25519_private_key_vec
            .try_into()
            .map_err(|_| Error::new("x25519 private key must be 32 bytes"))?;
        x25519_private_key_raw.into()
    };

    let key_share = user_participates_in_dkg_protocol(
        validators_info,
        &user_signing_keypair,
        &x25519_private_key,
    )
    .await
    .map_err(|err| Error::new(&format!("{}", err)))?;

    // TODO bincode would be better but it hides details from JS. Really we need a JS keyshare type
    Ok(serde_json::to_string(&key_share).map_err(|err| Error::new(&err.to_string()))?)
}

/// Run the signing protocol on the client side
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub async fn run_signing_protocol(
    key_share: String,
    sig_uid: String,
    validators_info_js: ValidatorInfoArray,
    user_signing_keypair_seed: Vec<u8>,
    x25519_private_key_vec: Vec<u8>,
) -> Result<String, Error> {
    let validators_info = parse_validator_info(validators_info_js)?;

    // sig_hash is the suffix of the sig_uid
    let sig_hash: [u8; 32] = {
        let sig_hash_hex = &sig_uid[65..];
        let sig_hash_vec =
            hex::decode(sig_hash_hex).map_err(|_| Error::new("Cannot parse sig_uid"))?;
        sig_hash_vec.try_into().map_err(|_| Error::new("Message hash must be 32 bytes"))?
    };

    let user_signing_keypair = {
        let seed: [u8; 32] = user_signing_keypair_seed
            .try_into()
            .map_err(|_| Error::new("User signing keypair seed must be 32 bytes"))?;
        sr25519::Keypair::from_seed(seed).map_err(|err| Error::new(&err.to_string()))?
    };

    let x25519_private_key: x25519_dalek::StaticSecret = {
        let x25519_private_key_raw: [u8; 32] = x25519_private_key_vec
            .try_into()
            .map_err(|_| Error::new("x25519 private key must be 32 bytes"))?;
        x25519_private_key_raw.into()
    };

    let key_share: KeyShare<KeyParams> =
        serde_json::from_str(&key_share).map_err(|err| Error::new(&err.to_string()))?;

    let signature = user_participates_in_signing_protocol(
        &key_share,
        &sig_uid,
        validators_info,
        &user_signing_keypair,
        sig_hash,
        &x25519_private_key,
    )
    .await
    .map_err(|err| Error::new(&format!("{}", err)))?;

    // TODO decide on a type
    Ok(format!("{:?}", signature))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "ValidatorInfo[]")]
    pub type ValidatorInfoArray;
}

/// Details of a validator
/// This differs from [crate::ValidatorInfo] only in that the fields must be private
#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone)]
pub struct ValidatorInfo {
    x25519_public_key: [u8; 32],
    ip_address: SocketAddrV4,
    tss_account: AccountId32,
}

#[wasm_bindgen]
impl ValidatorInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(
        x25519_public_key_vec: Vec<u8>,
        ip_address: String,
        tss_account: Vec<u8>,
    ) -> Result<ValidatorInfo, Error> {
        Ok(Self {
            x25519_public_key: x25519_public_key_vec
                .try_into()
                .map_err(|_| Error::new("x25519 public key must be 32 bytes"))?,
            ip_address: ip_address.parse().map_err(|err| Error::new(&format!("{}", err)))?,
            tss_account: AccountId32(
                tss_account
                    .try_into()
                    .map_err(|_| Error::new("TSS Account ID must be 32 bytes"))?,
            ),
        })
    }

    #[wasm_bindgen(js_name=getX25519PublicKey)]
    pub fn get_x25519_public_key(&self) -> Vec<u8> { self.x25519_public_key.to_vec() }

    #[wasm_bindgen(js_name=getIpAddress)]
    pub fn get_ip_address(&self) -> String { self.ip_address.to_string() }

    #[wasm_bindgen(js_name=getTssAccount)]
    pub fn get_tss_account(&self) -> Vec<u8> { self.tss_account.0.to_vec() }
}

// This is in a separate impl block as it is not exposed to wasm
impl ValidatorInfo {
    fn into_validator_info(self) -> crate::ValidatorInfo {
        crate::ValidatorInfo {
            x25519_public_key: self.x25519_public_key,
            ip_address: self.ip_address,
            tss_account: self.tss_account,
        }
    }
}

// Parse a JS array of JS ValidatorInfo
fn parse_validator_info(
    validators_info_js: ValidatorInfoArray,
) -> Result<Vec<crate::ValidatorInfo>, Error> {
    let js_val: &JsValue = validators_info_js.as_ref();
    let array: &js_sys::Array =
        js_val.dyn_ref().ok_or_else(|| Error::new("The argument must be an array"))?;
    let length: usize = array.length().try_into().map_err(|err| Error::new(&format!("{}", err)))?;
    let mut validators_info = Vec::<crate::ValidatorInfo>::with_capacity(length);
    for js in array.iter() {
        let typed_elem = ValidatorInfo::try_from(&js).map_err(|err| Error::new(&err))?;
        validators_info.push(typed_elem.into_validator_info());
    }
    Ok(validators_info)
}
