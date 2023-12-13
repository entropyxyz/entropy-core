use std::time::Duration;

use entropy_protocol::RecoverableSignature;
use entropy_shared::{KeyVisibility, SETUP_TIMEOUT_SECONDS};
use sp_core::Pair;
use subxt::utils::AccountId32;
use tokio::time::timeout;

use crate::{
    get_signer,
    sign_init::SignInit,
    signing_client::{
        protocol_execution::{Channels, ThresholdSigningService},
        protocol_transport::open_protocol_connections,
        Listener, ProtocolErr,
    },
    user::api::UserSignatureRequest,
    validation::derive_static_secret,
    AppState,
};

/// Start the signing protocol for a given message
#[tracing::instrument(skip(app_state), level = tracing::Level::DEBUG)]
pub async fn do_signing(
    message: UserSignatureRequest,
    sig_hash: String,
    app_state: &AppState,
    tx_id: String,
    user_address: AccountId32,
    key_visibility: KeyVisibility,
) -> Result<RecoverableSignature, ProtocolErr> {
    tracing::debug!("Preparing to perform signing");

    let state = &app_state.listener_state;
    let kv_manager = &app_state.kv_store;

    let info =
        SignInit::new(message.clone(), sig_hash.clone(), tx_id.clone(), user_address.clone())?;
    let signing_service = ThresholdSigningService::new(state, kv_manager);
    let pair_signer =
        get_signer(kv_manager).await.map_err(|e| ProtocolErr::UserError(e.to_string()))?;
    let signer = pair_signer.signer();

    let x25519_secret_key = derive_static_secret(signer);

    let account_id = AccountId32(signer.public().0);

    // set up context for signing protocol execution
    let sign_context = signing_service.get_sign_context(info.clone()).await?;

    let mut tss_accounts: Vec<AccountId32> = message
        .validators_info
        .iter()
        .map(|validator_info| validator_info.tss_account.clone())
        .collect();

    // If key key visibility is private, add them to the list of parties and pass the user's ID to
    // the listener
    let user_details_option = if let KeyVisibility::Private(user_x25519_public_key) = key_visibility
    {
        tss_accounts.push(user_address.clone());
        Some((user_address, user_x25519_public_key))
    } else {
        None
    };

    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, rx_from_others, listener) =
        Listener::new(message.validators_info, &account_id, user_details_option);

    state
        .listeners
        .lock()
		.map_err(|_| ProtocolErr::SessionError("Error getting lock".to_string()))?
        // TODO: using signature ID as session ID. Correct?
        .insert(sign_context.sign_init.sig_uid.clone(), listener);

    open_protocol_connections(
        &sign_context.sign_init.validators_info,
        &sign_context.sign_init.sig_uid,
        signer,
        state,
        &x25519_secret_key,
    )
    .await?;
    let channels = {
        let ready = timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await?;
        let broadcast_out = ready??;
        Channels(broadcast_out, rx_from_others)
    };

    let result =
        signing_service.execute_sign(&sign_context, channels, signer, tss_accounts).await?;

    Ok(result)
}

/// Creates a unique tx Id by concatenating the user's signing key and message digest
pub fn create_unique_tx_id(account: &String, sig_hash: &String) -> String {
    format!("{account}_{sig_hash}")
}

/// Produces a specific hash on a given message
pub struct Hasher;

impl Hasher {
    /// Produces the Keccak256 hash on a given message.
    ///
    /// In practice, if `data` is an RLP-serialized Ethereum transaction, this should produce the
    /// corrosponding .
    pub fn keccak(data: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Keccak256};

        let mut keccak = Keccak256::new();
        keccak.update(data);
        keccak.finalize().into()
    }
}
