use crate::{
    chain_api::{
        entropy::runtime_types::{bounded_collections::bounded_vec::BoundedVec, pallet_registry},
        get_api, get_rpc, EntropyConfig,
    },
    client, VERIFYING_KEY_LENGTH,
};
use entropy_shared::KeyVisibility;
use js_sys::Error;
use sp_core::{sr25519, Pair};
use subxt::{backend::legacy::LegacyRpcMethods, utils::AccountId32, OnlineClient};
use wasm_bindgen::prelude::*;

/// A connection to an Entropy chain endpoint
#[wasm_bindgen]
pub struct EntropyApi {
    api: OnlineClient<EntropyConfig>,
    rpc: LegacyRpcMethods<EntropyConfig>,
}

#[wasm_bindgen]
impl EntropyApi {
    #[wasm_bindgen(constructor)]
    pub async fn new(url: String) -> Result<EntropyApi, Error> {
        Ok(Self {
            api: get_api(&url).await.map_err(|err| Error::new(&format!("{:?}", err)))?,
            rpc: get_rpc(&url).await.map_err(|err| Error::new(&format!("{:?}", err)))?,
        })
    }
}

/// An sr25519 signing keypair
#[wasm_bindgen]
pub struct Sr25519Pair(sr25519::Pair);

#[wasm_bindgen]
impl Sr25519Pair {
    #[wasm_bindgen(constructor)]
    pub fn new(mnemonic: String) -> Result<Sr25519Pair, Error> {
        let pair = sr25519::Pair::from_string(&mnemonic, None)
            .map_err(|err| Error::new(&format!("{:?}", err)))?;
        Ok(Self(pair))
    }

    /// Get the public key
    pub fn public(&self) -> Vec<u8> {
        self.0.public().0.to_vec()
    }
}

/// An instance of a program, with configuration (which may be empty)
#[wasm_bindgen]
pub struct ProgramInstance(pallet_registry::pallet::ProgramInstance);

#[wasm_bindgen]
impl ProgramInstance {
    #[wasm_bindgen(constructor)]
    pub fn new(hash: Vec<u8>, program_config: Vec<u8>) -> Result<ProgramInstance, Error> {
        let program_pointer: [u8; 32] =
            hash.try_into().map_err(|_| Error::new("Program hash must be 32 bytes"))?;
        Ok(ProgramInstance(pallet_registry::pallet::ProgramInstance {
            program_pointer: program_pointer.into(),
            program_config,
        }))
    }
}

/// The public key of a distributed Entropy keypair
#[wasm_bindgen]
pub struct VerifyingKey([u8; VERIFYING_KEY_LENGTH]);

#[wasm_bindgen]
impl VerifyingKey {
    #[wasm_bindgen(js_name=fromHexString)]
    pub fn from_hex_string(input: String) -> Result<VerifyingKey, Error> {
        let vec = hex::decode(input).map_err(|_| Error::new("Program hash must be 32 bytes"))?;
        VerifyingKey::from_bytes(vec)
    }

    #[wasm_bindgen(js_name=fromBytes)]
    pub fn from_bytes(input: Vec<u8>) -> Result<VerifyingKey, Error> {
        Ok(VerifyingKey(input.try_into().map_err(|_| Error::new("Program hash must be 32 bytes"))?))
    }

    #[wasm_bindgen(js_name=toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    #[wasm_bindgen(js_name=toHexString)]
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

/// Register an Entropy account
#[wasm_bindgen]
pub async fn register(
    entropy_api: &EntropyApi,
    user_keypair: &Sr25519Pair,
    program_account: Vec<u8>,
    // TODO this should be a js array of programs - for now allow just one program
    programs: ProgramInstance,
) -> Result<(), Error> {
    let program_account: [u8; 32] =
        program_account.try_into().map_err(|_| Error::new("Program account must be 32 bytes"))?;

    client::put_register_request_on_chain(
        &entropy_api.api,
        &entropy_api.rpc,
        user_keypair.0.clone(),
        AccountId32(program_account),
        KeyVisibility::Public,
        BoundedVec(vec![programs.0]),
    )
    .await
    .map_err(|err| Error::new(&format!("{:?}", err)))?;

    Ok(())
}

#[wasm_bindgen(js_name=pollForRegistration)]
pub async fn poll_for_registration(
    entropy_api: &EntropyApi,
    account_id: Vec<u8>,
) -> Result<Option<VerifyingKey>, Error> {
    let account_id: [u8; 32] =
        account_id.try_into().map_err(|_| Error::new("Account ID must be 32 bytes"))?;
    if let Ok((verifying_key, _)) =
        client::poll_for_registration(&entropy_api.api, &entropy_api.rpc, &AccountId32(account_id))
            .await
    {
        Ok(Some(VerifyingKey(verifying_key)))
    } else {
        Ok(None)
    }
}

/// Request to sign a message
#[wasm_bindgen]
pub async fn sign(
    entropy_api: &EntropyApi,
    user_keypair: &Sr25519Pair,
    verifying_key: &VerifyingKey,
    message: Vec<u8>,
    auxilary_data: Option<Vec<u8>>,
) -> Result<String, Error> {
    let recoverable_signature = client::sign(
        &entropy_api.api,
        &entropy_api.rpc,
        user_keypair.0.clone(),
        verifying_key.0,
        message,
        None,
        auxilary_data,
    )
    .await
    .map_err(|err| Error::new(&format!("{:?}", err)))?;

    // TODO type for signature
    Ok(format!("{:?}", recoverable_signature))
}

/// Store a given program binary and return its hash
#[wasm_bindgen(js_name=storeProgram)]
pub async fn store_program(
    entropy_api: &EntropyApi,
    deployer_pair: &Sr25519Pair,
    program: Vec<u8>,
    configuration_interface: Vec<u8>,
    auxiliary_data_interface: Vec<u8>,
    oracle_data_pointer: Vec<u8>,
) -> Result<String, Error> {
    let program_hash = client::store_program(
        &entropy_api.api,
        &entropy_api.rpc,
        &deployer_pair.0,
        program,
        configuration_interface,
        auxiliary_data_interface,
        oracle_data_pointer,
    )
    .await
    .map_err(|err| Error::new(&format!("{:?}", err)))?;

    Ok(program_hash.to_string())
}

/// Get a list of all registered Entropy accounts
#[wasm_bindgen(js_name=getAccounts)]
pub async fn get_accounts(entropy_api: &EntropyApi) -> Result<String, Error> {
    let accounts = client::get_accounts(&entropy_api.api, &entropy_api.rpc)
        .await
        .map_err(|err| Error::new(&format!("{:?}", err)))?;

    Ok(format!("{:?}", accounts))
}
