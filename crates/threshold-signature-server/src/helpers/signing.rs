// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Utiliities for executing the signing protocol
use std::time::Duration;

use entropy_protocol::{RecoverableSignature, SessionId, SigningSessionInfo};
use entropy_shared::{KeyVisibility, SETUP_TIMEOUT_SECONDS};
use sp_core::Pair;
use subxt::{backend::legacy::LegacyRpcMethods, utils::AccountId32};
use tokio::time::timeout;

use crate::{
    chain_api::EntropyConfig,
    get_signer,
    sign_init::SignInit,
    signing_client::{
        protocol_execution::{Channels, ThresholdSigningService},
        protocol_transport::open_protocol_connections,
        Listener, ProtocolErr,
    },
    user::api::{increment_or_wipe_request_limit, UserSignatureRequest},
    validation::derive_x25519_static_secret,
    AppState,
};

/// Start the signing protocol for a given message
#[tracing::instrument(skip(app_state), level = tracing::Level::DEBUG)]
pub async fn do_signing(
    rpc: &LegacyRpcMethods<EntropyConfig>,
    user_signature_request: UserSignatureRequest,
    sig_hash: String,
    app_state: &AppState,
    signing_session_info: SigningSessionInfo,
    key_visibility: KeyVisibility,
    request_limit: u32,
) -> Result<RecoverableSignature, ProtocolErr> {
    tracing::debug!("Preparing to perform signing");

    let state = &app_state.listener_state;
    let kv_manager = &app_state.kv_store;

    let info = SignInit::new(user_signature_request.clone(), signing_session_info.clone());
    let signing_service = ThresholdSigningService::new(state, kv_manager);
    let pair_signer =
        get_signer(kv_manager).await.map_err(|e| ProtocolErr::UserError(e.to_string()))?;
    let signer = pair_signer.signer();

    let x25519_secret_key = derive_x25519_static_secret(signer);

    let account_id = AccountId32(signer.public().0);

    // set up context for signing protocol execution
    let sign_context = signing_service.get_sign_context(info.clone()).await?;

    let mut tss_accounts: Vec<AccountId32> = user_signature_request
        .validators_info
        .iter()
        .map(|validator_info| validator_info.tss_account.clone())
        .collect();

    // If key key visibility is private, add them to the list of parties and pass the user's ID to
    // the listener
    let user_details_option = if let KeyVisibility::Private(user_x25519_public_key) = key_visibility
    {
        tss_accounts.push(info.signing_session_info.account_id.clone());
        Some((info.signing_session_info.account_id.clone(), user_x25519_public_key))
    } else {
        None
    };

    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, rx_from_others, listener) =
        Listener::new(user_signature_request.validators_info, &account_id, user_details_option);

    let session_id = SessionId::Sign(sign_context.sign_init.signing_session_info.clone());

    state
        .listeners
        .lock()
        .map_err(|_| ProtocolErr::SessionError("Error getting lock".to_string()))?
        .insert(session_id.clone(), listener);

    open_protocol_connections(
        &sign_context.sign_init.validators_info,
        &session_id,
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
    increment_or_wipe_request_limit(
        rpc,
        kv_manager,
        info.signing_session_info.account_id.to_string(),
        request_limit,
    )
    .await
    .map_err(|e| ProtocolErr::UserError(e.to_string()))?;

    Ok(result)
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
