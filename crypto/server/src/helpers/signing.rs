use std::{collections::HashMap, sync::Mutex};

use kvdb::kv_manager::KvManager;
use rocket::{http::Status, State};
use tofn::sdk::api::RecoverableSignature;

use crate::{
    sign_init::SignInit,
    signing_client::{
        new_party::{Channels, Gg20Service},
        subscribe::{subscribe_to_them, Listener},
        SignerState, SigningErr,
    },
};

// TODO: JA Remove all below, temporary
/// The state used to temporarily store completed signatures
#[derive(Debug)]
pub struct SignatureState {
    pub signatures: Mutex<HashMap<String, RecoverableSignature>>,
}

impl SignatureState {
    pub fn new() -> SignatureState {
        let signatures = Mutex::new(HashMap::new());
        SignatureState { signatures }
    }

    pub fn insert(&self, key: [u8; 32], value: &RecoverableSignature) {
        let mut signatures = self.signatures.lock().unwrap_or_else(|e| e.into_inner());
        signatures.insert(hex::encode(key), *value);
    }

    pub fn get(&self, key: &String) -> [u8; 65] {
        let signatures = self.signatures.lock().unwrap_or_else(|e| e.into_inner());
        let result = *signatures.get(key).unwrap();
        result.as_ref().try_into().expect("slice with incorrect length")
    }

    pub fn drain(&self) {
        let mut signatures = self.signatures.lock().unwrap_or_else(|e| e.into_inner());
        let _ = signatures.drain();
    }
}

/// Start the signing protocol for a given message
pub async fn do_signing(
    message: entropy_shared::Message,
    state: &State<SignerState>,
    kv_manager: &State<KvManager>,
    signatures: &State<SignatureState>,
    key: String,
) -> Result<Status, SigningErr> {
    // todo: temporary hack, replace with correct data
    let info = SignInit::temporary_data(message.clone(), key);
    let gg20_service = Gg20Service::new(state, kv_manager);

    // set up context for signing protocol execution
    let sign_context = gg20_service.get_sign_context(info.clone()).await?;

    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, listener) = Listener::new();
    state
        .listeners
        .lock()
        .expect("lock shared data")
        .insert(sign_context.sign_init.party_uid.to_string(), listener);
    let channels = {
        let stream_in = subscribe_to_them(&sign_context).await?;
        let broadcast_out = rx_ready.await??;
        Channels(broadcast_out, stream_in)
    };

    let result = gg20_service.execute_sign(&sign_context, channels).await.unwrap();

    gg20_service.handle_result(
        &result,
        message.sig_request.sig_hash.as_slice().try_into().unwrap(),
        signatures,
    );
    Ok(Status::Ok)
}

/// Creates a unique tx Id by concatenating the user's signing key and message digest
pub fn create_unique_tx_id(account: &String, sig_hash: &String) -> String {
    format!("{}_{}", account, sig_hash)
}
