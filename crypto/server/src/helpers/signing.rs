use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use bip39::{Language, Mnemonic};
use entropy_shared::SETUP_TIMEOUT_SECONDS;
use kvdb::kv_manager::{KvManager, PartyId};
use sp_core::crypto::AccountId32;
use synedrion::k256::ecdsa::{RecoveryId, Signature};
use tokio::time::timeout;

use crate::{
    get_signer,
    sign_init::SignInit,
    signing_client::{
        new_party::{Channels, ThresholdSigningService},
        protocol_transport::{open_protocol_connections, Listener},
        SignerState, SigningErr,
    },
    user::api::UserTransactionRequest,
    validation::mnemonic_to_pair,
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
#[derive(Debug, Clone)]
pub struct SignatureState {
    pub signatures: Arc<Mutex<HashMap<Box<[u8]>, RecoverableSignature>>>,
}

impl SignatureState {
    pub fn new() -> SignatureState {
        let signatures = Arc::new(Mutex::new(HashMap::new()));
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

impl Default for SignatureState {
    fn default() -> Self { Self::new() }
}

/// Start the signing protocol for a given message
pub async fn do_signing(
    message: UserTransactionRequest,
    sig_hash: String,
    state: &SignerState,
    kv_manager: &KvManager,
    signatures: &SignatureState,
    tx_id: String,
    user_address: AccountId32,
) -> Result<RecoverableSignature, SigningErr> {
    let info = SignInit::new(message.clone(), sig_hash.clone(), tx_id.clone(), user_address)?;
    let signing_service = ThresholdSigningService::new(state, kv_manager);
    let signer =
        get_signer(kv_manager).await.map_err(|_| SigningErr::UserError("Error getting Signer"))?;
    let account_sp_core = AccountId32::new(*signer.account_id().clone().as_ref());
    let my_id = PartyId::new(account_sp_core.clone());
    // set up context for signing protocol execution
    let sign_context = signing_service.get_sign_context(info.clone()).await?;

    let tss_accounts: Vec<AccountId32> = message
        .validators_info
        .iter()
        .map(|validator_info| AccountId32::new(*validator_info.tss_account.clone().as_ref()))
        .collect();

    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, rx_from_others, listener) =
        Listener::new(message.validators_info, &account_sp_core);
    state
        .listeners
        .lock()
		.map_err(|_| SigningErr::SessionError("Error getting lock".to_string()))?
        // TODO: using signature ID as session ID. Correct?
        .insert(sign_context.sign_init.sig_uid.clone(), listener);

    open_protocol_connections(
        &sign_context.sign_init.validators_info,
        &sign_context.sign_init.sig_uid,
        &my_id,
        &signer,
        state,
    )
    .await?;
    let channels = {
        let ready = timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await?;
        let broadcast_out = ready??;
        Channels(broadcast_out, rx_from_others)
    };

    let raw = kv_manager.kv().get("MNEMONIC").await?;
    let secret = core::str::from_utf8(&raw)?;
    let mnemonic = Mnemonic::from_phrase(secret, Language::English)
        .map_err(|e| SigningErr::Mnemonic(e.to_string()))?;
    let threshold_signer =
        mnemonic_to_pair(&mnemonic).map_err(|_| SigningErr::SecretString("Secret String Error"))?;

    let result = signing_service
        .execute_sign(&sign_context, channels, &threshold_signer, tss_accounts)
        .await?;

    signing_service.handle_result(&result, &hex::decode(sig_hash.clone())?, signatures);

    Ok(result)
}

/// Creates a unique tx Id by concatenating the user's signing key and message digest
pub fn create_unique_tx_id(account: &String, sig_hash: &String) -> String {
    format!("{account}_{sig_hash}")
}
