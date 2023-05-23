use std::{collections::HashMap, sync::Mutex};

use kvdb::kv_manager::{KvManager, PartyId};
use rocket::{http::Status, State};
use synedrion::k256::ecdsa::{RecoveryId, Signature};
use subxt::ext::sp_core::{sr25519, Pair};

use crate::{
    get_signer,
    sign_init::SignInit,
    signing_client::{
        new_party::{Channels, ThresholdSigningService},
        subscribe::{subscribe_to_them, Listener},
        SignerState, SigningErr,
    },
	message::mnemonic_to_pair
};
use bip39::{Language, Mnemonic};

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
    tx_id: String,
) -> Result<Status, SigningErr> {
    let info = SignInit::new(message.clone(), tx_id);
    let signing_service = ThresholdSigningService::new(state, kv_manager);

    let my_id = PartyId::new(get_signer(kv_manager).await.unwrap().account_id().clone());

    // set up context for signing protocol execution
    let sign_context = signing_service.get_sign_context(info.clone()).await?;

    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, listener) = Listener::new();
    state
        .listeners
        .lock()
        .expect("lock shared data")
        // TODO: using signature ID as session ID. Correct?
        .insert(sign_context.sign_init.sig_uid.clone(), listener);
    let channels = {
        let stream_in = subscribe_to_them(&sign_context, &my_id).await?;
        let broadcast_out = rx_ready.await??;
        Channels(broadcast_out, stream_in)
    };

	let raw = kv_manager.kv().get("MNEMONIC").await.unwrap();
	let secret = core::str::from_utf8(&raw).unwrap();
	let mnemonic = Mnemonic::from_phrase(secret, Language::English).unwrap();
	let threshold_signer = mnemonic_to_pair(&mnemonic);

    let result = signing_service.execute_sign(&sign_context, channels, &threshold_signer).await.unwrap();

    signing_service.handle_result(&result, message.sig_request.sig_hash.as_slice(), signatures);

    Ok(Status::Ok)
}

/// Creates a unique tx Id by concatenating the user's signing key and message digest
pub fn create_unique_tx_id(account: &String, sig_hash: &String) -> String {
    format!("{}_{}", account, sig_hash)
}
