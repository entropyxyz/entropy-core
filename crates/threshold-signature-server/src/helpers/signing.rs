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
pub use entropy_client::Hasher;
use std::time::Duration;

use entropy_client::user::RelayerSignatureRequest;
use entropy_protocol::{Listener, RecoverableSignature, SessionId, SigningSessionInfo};
use entropy_shared::SETUP_TIMEOUT_SECONDS;
use sp_core::Pair;
use subxt::{backend::legacy::LegacyRpcMethods, utils::AccountId32};
use tokio::time::timeout;

use crate::{
    chain_api::EntropyConfig,
    sign_init::SignInit,
    signing_client::{
        protocol_execution::{Channels, ThresholdSigningService},
        protocol_transport::open_protocol_connections,
        ProtocolErr,
    },
    user::api::increment_or_wipe_request_limit,
    AppState,
};

/// Start the signing protocol for a given message
#[tracing::instrument(skip(app_state), level = tracing::Level::DEBUG)]
pub async fn do_signing(
    rpc: &LegacyRpcMethods<EntropyConfig>,
    relayer_signature_request: RelayerSignatureRequest,
    app_state: &AppState,
    signing_session_info: SigningSessionInfo,
    request_limit: u32,
    derivation_path: bip32::DerivationPath,
) -> Result<RecoverableSignature, ProtocolErr> {
    tracing::debug!("Preparing to perform signing");

    let state = &app_state.cache.listener_state;

    let info = SignInit::new(relayer_signature_request.clone(), signing_session_info.clone());
    let network_key_share = app_state.network_key_share()?.ok_or(ProtocolErr::NoKeyShare)?;
    let signing_service = ThresholdSigningService::new(state, network_key_share);
    let x25519_secret_key = &app_state.x25519_secret;
    let signer = &app_state.pair;

    let account_id = AccountId32(signer.public().0);

    // Set up context for signing protocol execution
    let sign_context = signing_service.get_sign_context(info.clone(), derivation_path).await?;

    let tss_accounts: Vec<AccountId32> = relayer_signature_request
        .validators_info
        .iter()
        .map(|validator_info| validator_info.tss_account.clone())
        .collect();

    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, rx_from_others, listener) =
        Listener::new(relayer_signature_request.validators_info, &account_id);

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
        x25519_secret_key,
    )
    .await?;

    let channels = {
        match timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await {
            Ok(ready) => {
                let broadcast_out = ready??;
                Channels(broadcast_out, rx_from_others)
            },
            Err(e) => {
                let unsubscribed_peers = app_state.cache.unsubscribed_peers(&session_id)?;
                return Err(ProtocolErr::Timeout { source: e, inactive_peers: unsubscribed_peers });
            },
        }
    };

    let result = signing_service
        .execute_sign(
            session_id,
            &sign_context.key_share,
            &sign_context.aux_info,
            channels,
            signer,
            tss_accounts,
        )
        .await?;
    increment_or_wipe_request_limit(
        &app_state.cache,
        hex::encode(info.signing_session_info.signature_verifying_key),
        request_limit,
    )
    .await
    .map_err(|e| ProtocolErr::UserError(e.to_string()))?;

    Ok(result)
}
