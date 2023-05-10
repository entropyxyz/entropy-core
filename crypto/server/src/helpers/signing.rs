use std::{collections::HashMap, sync::Mutex};

use cggmp21::k256::ecdsa::{RecoveryId, Signature};
use kvdb::kv_manager::KvManager;
use rocket::{http::Status, State};

use crate::{
    sign_init::SignInit,
    signing_client::{
        new_party::{Channels, ThresholdSigningService},
        subscribe::{subscribe_to_them, Listener},
        SignerState, SigningErr,
    },
};

#[derive(Clone, Debug)]
pub struct RecoverableSignature {
    pub signature: Signature,
    pub recovery_id: RecoveryId,
}

impl RecoverableSignature {
    pub fn to_rsv_bytes(&self) -> [u8; 65] {
        let mut res = [0u8; 65];

        let rs = self.signature.to_bytes();
        res[0..64].copy_from_slice(&rs);

        res[64] = self.recovery_id.to_byte();

        res
    }
}

// TODO: JA Remove all below, temporary
/// The state used to temporarily store completed signatures
#[derive(Debug)]
pub struct SignatureState {
    pub signatures: Mutex<HashMap<Box<[u8]>, RecoverableSignature>>,
}

impl SignatureState {
    pub fn new() -> SignatureState {
        let signatures = Mutex::new(HashMap::new());
        SignatureState { signatures }
    }

    pub fn insert(&self, prehashed_message: &[u8], value: &RecoverableSignature) {
        let mut signatures = self.signatures.lock().unwrap_or_else(|e| e.into_inner());
        signatures.insert(prehashed_message.into(), value.clone());
    }

    pub fn get(&self, prehashed_message: &[u8]) -> Option<RecoverableSignature> {
        let signatures = self.signatures.lock().unwrap_or_else(|e| e.into_inner());
        signatures.get(prehashed_message).cloned()
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
    let signing_service = ThresholdSigningService::new(state, kv_manager);

    // set up context for signing protocol execution
    let sign_context = signing_service.get_sign_context(info.clone()).await?;

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

    let result = signing_service.execute_sign(&sign_context, channels).await.unwrap();

    signing_service.handle_result(&result, message.sig_request.sig_hash.as_slice(), signatures);

    Ok(Status::Ok)
}

/// Creates a unique tx Id by concatenating the user's signing key and message digest
pub fn create_unique_tx_id(account: &String, sig_hash: &String) -> String {
    format!("{}_{}", account, sig_hash)
}
