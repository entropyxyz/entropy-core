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

//! Handling of websocket connections used for protocol messages
use axum::extract::ws::WebSocket;
pub use entropy_protocol::protocol_transport::SubscribeMessage;
use entropy_protocol::{
    protocol_transport::{
        errors::WsError,
        noise::{noise_handshake_initiator, noise_handshake_responder},
        ws_to_channels, WsChannels,
    },
    PartyId, ValidatorInfo,
};
use entropy_shared::X25519PublicKey;
use futures::future;
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32;
use tokio_tungstenite::connect_async;

use super::ProtocolErr;
use crate::{
    signing_client::{SessionId, SubscribeErr},
    AppState, ListenerState, SUBSCRIBE_TIMEOUT_SECONDS,
};

/// Set up websocket connections to other members of the signing committee
#[tracing::instrument(
    skip_all,
    fields(validator_info, session_uid, signer)
    level = tracing::Level::DEBUG
)]
pub async fn open_protocol_connections(
    validators_info: &[ValidatorInfo],
    session_id: &SessionId,
    signer: &sr25519::Pair,
    state: &ListenerState,
    x25519_secret_key: &x25519_dalek::StaticSecret,
) -> Result<(), ProtocolErr> {
    tracing::debug!("Opening protocol connections");

    let connect_to_validators = validators_info
        .iter()
        .filter(|validators_info| {
            // Decide whether to initiate a connection by comparing account IDs, otherwise we wait
            // for them to connect to us
            let initiate_connection = signer.public().0 > validators_info.tss_account.0;
            if !initiate_connection {
                tracing::debug!(
                    "Waiting for {:?} to open a connection with us.",
                    validators_info.tss_account.0
                );
            }

            initiate_connection
        })
        .map(|validator_info| async move {
            tracing::debug!(
                "Attempting to open protocol connections with {:?}",
                validator_info.tss_account.0.clone()
            );

            // Open a ws connection
            let ws_endpoint = format!("ws://{}/ws", validator_info.ip_address);
            let (ws_stream, _response) =
                connect_async(ws_endpoint).await.map_err(|e| ProtocolErr::ConnectionError {
                    source: e,
                    account_id: validator_info.tss_account.clone(),
                })?;

            // Send a SubscribeMessage in the payload of the final handshake message
            let subscribe_message_vec =
                bincode::serialize(&SubscribeMessage::new(session_id.clone(), signer)?)?;

            let mut encrypted_connection = noise_handshake_initiator(
                ws_stream,
                x25519_secret_key,
                validator_info.x25519_public_key,
                subscribe_message_vec,
            )
            .await
            .map_err(|e| ProtocolErr::EncryptedConnection {
                source: e,
                account_id: validator_info.tss_account.clone(),
            })?;

            // Check the response as to whether they accepted our SubscribeMessage
            let response_message = encrypted_connection.recv().await.map_err(|e| {
                ProtocolErr::EncryptedConnection {
                    source: e,
                    account_id: validator_info.tss_account.clone(),
                }
            })?;

            let subscribe_response: Result<(), String> = bincode::deserialize(&response_message)?;
            if let Err(error_message) = subscribe_response {
                // In future versions, we can check here if the error is VersionTooNew(version)
                // and if possible the downgrade protocol messages used to be backward compatible
                return Err(ProtocolErr::BadSubscribeMessage {
                    message: error_message,
                    account_id: validator_info.tss_account.clone(),
                });
            }

            // Setup channels
            let ws_channels = get_ws_channels(state, session_id, &validator_info.tss_account)
                .map_err(|e| ProtocolErr::Subscribe {
                    source: e,
                    account_id: validator_info.tss_account.clone(),
                })?;

            let remote_party_id = PartyId::new(validator_info.tss_account.clone());
            let account_id = validator_info.tss_account.clone();

            // Handle protocol messages
            tokio::spawn(async move {
                ws_to_channels(encrypted_connection, ws_channels, remote_party_id).await.map_err(
                    |err| {
                        tracing::warn!("{:?}", err);
                        Err::<(), ProtocolErr>(ProtocolErr::EncryptedConnection {
                            source: err.into(),
                            account_id,
                        })
                    },
                )
            });

            Ok::<_, ProtocolErr>(())
        })
        .collect::<Vec<_>>();

    future::try_join_all(connect_to_validators).await?;

    Ok(())
}

/// Handle an incoming websocket connection
pub async fn handle_socket(socket: WebSocket, app_state: AppState) -> Result<(), WsError> {
    if !app_state.cache.is_ready() {
        return Err(WsError::NotReady);
    }

    let (mut encrypted_connection, serialized_signed_message) =
        noise_handshake_responder(socket, &app_state.x25519_secret)
            .await
            .map_err(|e| WsError::EncryptedConnection(e.to_string()))?;

    let remote_public_key = encrypted_connection
        .remote_public_key()
        .map_err(|e| WsError::EncryptedConnection(e.to_string()))?;

    let (subscribe_response, ws_channels_option) = match handle_initial_incoming_ws_message(
        serialized_signed_message,
        remote_public_key,
        app_state,
    )
    .await
    {
        Ok((ws_channels, party_id)) => (Ok(()), Some((ws_channels, party_id))),
        Err(err) => (Err(format!("{err:?}")), None),
    };
    // Send them a response as to whether we are happy with their subscribe message
    let subscribe_response_vec = bincode::serialize(&subscribe_response)?;
    encrypted_connection
        .send(subscribe_response_vec)
        .await
        .map_err(|e| WsError::EncryptedConnection(e.to_string()))?;

    // If it was successful, proceed with relaying signing protocol messages
    let (ws_channels, remote_party_id) = ws_channels_option.ok_or(WsError::BadSubscribeMessage)?;
    ws_to_channels(encrypted_connection, ws_channels, remote_party_id).await?;

    Ok(())
}

/// Handle a subscribe message
async fn handle_initial_incoming_ws_message(
    serialized_subscribe_message: Vec<u8>,
    remote_public_key: X25519PublicKey,
    app_state: AppState,
) -> Result<(WsChannels, PartyId), SubscribeErr> {
    let msg: SubscribeMessage = bincode::deserialize(&serialized_subscribe_message)?;
    tracing::info!("Got ws connection, with message: {msg:?}");

    // In future versions we may have backwards compatibility with the
    // old version and be able to recover here
    msg.check_supported()?;

    if !msg.verify()? {
        return Err(SubscribeErr::InvalidSignature("Invalid signature."));
    }

    if !app_state.cache.listener_state.contains_listener(&msg.session_id)? {
        // Chain node hasn't yet informed this node of the party. Wait for a timeout and proceed
        // or fail below
        tracing::warn!("Cannot find associated listener - waiting");
        tokio::time::sleep(std::time::Duration::from_secs(SUBSCRIBE_TIMEOUT_SECONDS)).await;
    };

    {
        // Check that the given public key is of the ones we are expecting for this protocol session
        let mut listeners = app_state
            .cache
            .listener_state
            .listeners
            .lock()
            .map_err(|e| SubscribeErr::LockError(e.to_string()))?;
        let listener =
            listeners.get(&msg.session_id).ok_or(SubscribeErr::NoListener("no listener"))?;

        if !listener.validators.iter().any(|(validator_account_id, validator_x25519_pk)| {
            validator_account_id == &msg.account_id().0 && validator_x25519_pk == &remote_public_key
        }) {
            // Make the signing process fail, since one of the commitee has misbehaved
            listeners.remove(&msg.session_id);
            return Err(SubscribeErr::Decryption(
                "Public key does not match any of those expected for this protocol session"
                    .to_string(),
            ));
        }
    }
    let ws_channels =
        get_ws_channels(&app_state.cache.listener_state, &msg.session_id, &msg.account_id())?;

    Ok((ws_channels, PartyId::new(msg.account_id())))
}

/// Inform the listener we have made a ws connection to another signing party, and get channels to
/// the signing protocol
fn get_ws_channels(
    state: &ListenerState,
    session_id: &SessionId,
    tss_account: &AccountId32,
) -> Result<WsChannels, SubscribeErr> {
    let mut listeners =
        state.listeners.lock().map_err(|e| SubscribeErr::LockError(e.to_string()))?;
    let listener = listeners
        .get_mut(session_id)
        .ok_or(SubscribeErr::NoListener("No listener when getting ws channels"))?;
    let ws_channels = listener.subscribe(tss_account)?;

    if ws_channels.is_final {
        // all subscribed, wake up the waiting listener to execute the protocol
        let listener =
            listeners.remove(session_id).ok_or(SubscribeErr::NoListener("listener remove"))?;
        let (tx, broadcaster) = listener.into_broadcaster();
        let _ = tx.send(Ok(broadcaster));
    };
    Ok(ws_channels)
}
