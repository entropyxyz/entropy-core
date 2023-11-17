//! Wrappers around functions to run dkg and signing protocols for JS
use js_sys::Error;
use subxt::utils::AccountId32;
use subxt_signer::sr25519;
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
) -> Result<KeyShare, Error> {
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

    Ok(KeyShare(key_share))
}

/// Run the signing protocol on the client side
/// `key_share` is given as a JSON encoded [synedrion::KeyShare]
/// Returns a recoverable signature as a base64 encoded string
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub async fn run_signing_protocol(
    key_share: KeyShare,
    sig_uid: String,
    validators_info_js: ValidatorInfoArray,
    user_signing_keypair_seed: Vec<u8>,
    x25519_private_key_vec: Vec<u8>,
) -> Result<String, Error> {
    let validators_info = parse_validator_info(validators_info_js)?;

    // sig_hash is the suffix of the sig_uid
    let sig_hash: [u8; 32] = {
        // 49 is the length of an ss58 encoded account id + 1 for the separator
        let sig_hash_hex = &sig_uid[49..];
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

    // let key_share: KeyShare<KeyParams> =
    //     serde_json::from_str(&key_share).map_err(|err| Error::new(&err.to_string()))?;

    let signature = user_participates_in_signing_protocol(
        &key_share.0,
        &sig_uid,
        validators_info,
        &user_signing_keypair,
        sig_hash,
        &x25519_private_key,
    )
    .await
    .map_err(|err| Error::new(&format!("{}", err)))?;

    Ok(base64::encode(signature.to_rsv_bytes()))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "ValidatorInfo[]")]
    pub type ValidatorInfoArray;
}

/// Details of a validator intended for use on JS
/// This differs from [crate::ValidatorInfo] only in that the fields must be private
#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone)]
pub struct ValidatorInfo {
    x25519_public_key: [u8; 32],
    ip_address: String,
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
            ip_address,
            tss_account: AccountId32(
                tss_account
                    .try_into()
                    .map_err(|_| Error::new("TSS Account ID must be 32 bytes"))?,
            ),
        })
    }

    #[wasm_bindgen(js_name=getX25519PublicKey)]
    pub fn get_x25519_public_key(&self) -> Vec<u8> {
        self.x25519_public_key.to_vec()
    }

    #[wasm_bindgen(js_name=getIpAddress)]
    pub fn get_ip_address(&self) -> String {
        self.ip_address.to_string()
    }

    #[wasm_bindgen(js_name=getTssAccount)]
    pub fn get_tss_account(&self) -> Vec<u8> {
        self.tss_account.0.to_vec()
    }
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

/// Parse a JS array of JS ValidatorInfo
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

/// Synedrion key share wrapped for wasm
#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone)]
pub struct KeyShare(synedrion::KeyShare<KeyParams>);

#[wasm_bindgen]
impl KeyShare {
    /// Serialize the keyshare to a JSON string
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> Result<String, Error> {
        serde_json::to_string(&self.0).map_err(|err| Error::new(&err.to_string()))
    }

    /// Deserialize a keyshare from a JSON string
    #[wasm_bindgen(js_name = fromString)]
    pub fn from_string(keyshare_json: String) -> Result<KeyShare, Error> {
        Ok(Self(serde_json::from_str(&keyshare_json).map_err(|err| Error::new(&err.to_string()))?))
    }

    /// Serialize the keyshare to a Uint8Array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        bincode::serialize(&self.0).map_err(|err| Error::new(&err.to_string()))
    }

    /// Deserialize a keyshare from a Uint8Array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(keyshare_serialized: Vec<u8>) -> Result<KeyShare, Error> {
        Ok(Self(
            bincode::deserialize(&keyshare_serialized)
                .map_err(|err| Error::new(&err.to_string()))?,
        ))
    }

    /// Get the verifying (public) key associated with this keyshare
    #[wasm_bindgen(js_name = verifyingKey)]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_encoded_point(true).as_bytes().to_vec()
    }

    /// Get the number of parties asssociated with this keyshare
    #[wasm_bindgen(js_name = numParties)]
    pub fn num_parties(&self) -> usize {
        self.0.num_parties()
    }

    /// Get the party index of this keyshare (a number indentiying which party we are)
    #[wasm_bindgen(js_name = partyIndex)]
    pub fn party_index(&self) -> usize {
        self.0.party_index().as_usize()
    }
}
