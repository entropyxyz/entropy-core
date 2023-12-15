//! Wrappers around functions to run dkg and signing protocols for JS
use js_sys::Error;
use sp_core::sr25519;
use subxt::utils::AccountId32;
use wasm_bindgen::prelude::*;
use wasm_bindgen_derive::TryFromJsValue;

use super::{user_participates_in_dkg_protocol, user_participates_in_signing_protocol};
use crate::KeyParams;

/// Run the DKG protocol on the client side and return a keyshare
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = runDkgProtocol))]
pub async fn run_dkg_protocol(
    validators_info_js: ValidatorInfoArray,
    user_signing_secret_key: Vec<u8>,
) -> Result<KeyShare, Error> {
    let validators_info = parse_validator_info(validators_info_js)?;

    let user_signing_keypair = sr25519_keypair_from_secret_key(user_signing_secret_key)?;

    let key_share = user_participates_in_dkg_protocol(validators_info, &user_signing_keypair)
        .await
        .map_err(|err| Error::new(&format!("{}", err)))?;

    Ok(KeyShare(key_share))
}

/// Run the signing protocol on the client side
/// Returns a recoverable signature as a base64 encoded string
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = runSigningProtocol))]
pub async fn run_signing_protocol(
    key_share: KeyShare,
    message_hash: Vec<u8>,
    validators_info_js: ValidatorInfoArray,
    user_signing_secret_key: Vec<u8>,
) -> Result<String, Error> {
    let validators_info = parse_validator_info(validators_info_js)?;

    let message_hash: [u8; 32] =
        message_hash.try_into().map_err(|_| Error::new("x25519 private key must be 32 bytes"))?;

    let user_signing_keypair = sr25519_keypair_from_secret_key(user_signing_secret_key)?;

    let signature = user_participates_in_signing_protocol(
        &key_share.0,
        validators_info,
        &user_signing_keypair,
        message_hash,
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
#[wasm_bindgen(inspectable)]
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
#[wasm_bindgen(inspectable)]
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
        self.0.party_index()
    }
}

// Make a sr25519 keypair given a secret key, using sp-core compatible key generation if
// in test mode, polkadot-js compatible otherwise
fn sr25519_keypair_from_secret_key(secret_key: Vec<u8>) -> Result<sr25519::Pair, Error> {
    if secret_key.len() != 64 {
        return Err(Error::new("Secret key must be 64 bytes"));
    }

    let secret = if cfg!(feature = "wasm-test") {
        schnorrkel::SecretKey::from_bytes(secret_key.as_slice())
    } else {
        schnorrkel::SecretKey::from_ed25519_bytes(secret_key.as_slice())
    }
    .map_err(|err| Error::new(&err.to_string()))?;

    let public = secret.to_public();
    Ok(sr25519::Pair::from(schnorrkel::Keypair { secret, public }))
}
