use axum::extract::ws::WebSocket;
pub use entropy_protocol::protocol_transport::{Broadcaster, SubscribeMessage};
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
use sp_core::crypto::AccountId32;
use subxt::{ext::sp_core::sr25519, tx::PairSigner};
use tokio_tungstenite::connect_async;

use super::ProtocolErr;
use crate::{
    chain_api::EntropyConfig, get_signer, signing_client::SubscribeErr, AppState, ListenerState,
    SUBSCRIBE_TIMEOUT_SECONDS,
};

/// Set up websocket connections to other members of the signing committee
pub async fn open_protocol_connections(
    validators_info: &[ValidatorInfo],
    session_uid: &str,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    state: &ListenerState,
) -> Result<(), ProtocolErr> {
    let connect_to_validators = validators_info
        .iter()
        .filter(|validators_info| {
            // Decide whether to initiate a connection by comparing accound ids
            // otherwise, we wait for them to connect to us
            signer.account_id() > &validators_info.tss_account.clone().into()
        })
        .map(|validator_info| async move {
            // Open a ws connection
            let ws_endpoint = format!("ws://{}/ws", validator_info.ip_address);
            let (ws_stream, _response) = connect_async(ws_endpoint).await?;

            // Send a SubscribeMessage in the payload of the final handshake message
            let subscribe_message_vec =
                serde_json::to_vec(&SubscribeMessage::new(session_uid, signer.signer()))?;

            let mut encrypted_connection = noise_handshake_initiator(
                ws_stream,
                signer.signer(),
                validator_info.x25519_public_key,
                subscribe_message_vec,
            )
            .await
            .map_err(|e| ProtocolErr::EncryptedConnection(e.to_string()))?;

            // Check the response as to whether they accepted our SubscribeMessage
            let response_message = encrypted_connection
                .recv()
                .await
                .map_err(|e| ProtocolErr::EncryptedConnection(e.to_string()))?;
            let subscribe_response: Result<(), String> = serde_json::from_str(&response_message)?;
            if let Err(error_message) = subscribe_response {
                return Err(ProtocolErr::BadSubscribeMessage(error_message));
            }

            // Setup channels
            let ws_channels = get_ws_channels(state, session_uid, &validator_info.tss_account)?;

            let remote_party_id = PartyId::new(validator_info.tss_account.clone());

            // Handle protocol messages
            tokio::spawn(async move {
                if let Err(err) =
                    ws_to_channels(encrypted_connection, ws_channels, remote_party_id).await
                {
                    tracing::warn!("{:?}", err);
                };
            });

            Ok::<_, ProtocolErr>(())
        })
        .collect::<Vec<_>>();

    future::try_join_all(connect_to_validators).await?;

    Ok(())
}

/// Handle an incoming websocket connection
pub async fn handle_socket(socket: WebSocket, app_state: AppState) -> Result<(), WsError> {
    let signer = get_signer(&app_state.kv_store).await.map_err(|_| WsError::SignerFromAppState)?;

    let (mut encrypted_connection, serialized_signed_message) =
        noise_handshake_responder(socket, signer.signer())
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
    let subscribe_response_json =
        serde_json::to_string(&subscribe_response).map_err(|_| WsError::ConnectionClosed)?;
    encrypted_connection
        .send(subscribe_response_json)
        .await
        .map_err(|e| WsError::EncryptedConnection(e.to_string()))?;

    // If it was successful, proceed with relaying signing protocol messages
    let (ws_channels, remote_party_id) = ws_channels_option.ok_or(WsError::BadSubscribeMessage)?;
    ws_to_channels(encrypted_connection, ws_channels, remote_party_id).await?;

    Ok(())
}

/// Handle a subscribe message
async fn handle_initial_incoming_ws_message(
    serialized_subscribe_message: String,
    remote_public_key: X25519PublicKey,
    app_state: AppState,
) -> Result<(WsChannels, PartyId), SubscribeErr> {
    let msg: SubscribeMessage = serde_json::from_str(&serialized_subscribe_message)?;
    tracing::info!("Got ws connection, with message: {msg:?}");

    if !msg.verify() {
        return Err(SubscribeErr::InvalidSignature("Invalid signature."));
    }

    if !app_state.listener_state.contains_listener(&msg.session_id)? {
        // Chain node hasn't yet informed this node of the party. Wait for a timeout and proceed
        // or fail below
        tracing::warn!("Cannot find associated listener - waiting");
        tokio::time::sleep(std::time::Duration::from_secs(SUBSCRIBE_TIMEOUT_SECONDS)).await;
    };

    {
        // Check that the given public key matches the public key we got in the
        // UserTransactionRequest
        let mut listeners = app_state
            .listener_state
            .listeners
            .lock()
            .map_err(|e| SubscribeErr::LockError(e.to_string()))?;
        let listener =
            listeners.get(&msg.session_id).ok_or(SubscribeErr::NoListener("no listener"))?;

        if !listener.validators.iter().any(|(validator_account_id, validator_x25519_pk)| {
            validator_account_id == &msg.account_id() && validator_x25519_pk == &remote_public_key
        }) {
            // Make the signing process fail, since one of the commitee has misbehaved
            listeners.remove(&msg.session_id);
            return Err(SubscribeErr::Decryption(
                "Public key does not match that given in UserTransactionRequest".to_string(),
            ));
        }
    }
    let ws_channels =
        get_ws_channels(&app_state.listener_state, &msg.session_id, &msg.account_id())?;

    Ok((ws_channels, PartyId::new(msg.account_id())))
}

/// Inform the listener we have made a ws connection to another signing party, and get channels to
/// the signing protocol
fn get_ws_channels(
    state: &ListenerState,
    sig_uid: &str,
    tss_account: &AccountId32,
) -> Result<WsChannels, SubscribeErr> {
    let mut listeners =
        state.listeners.lock().map_err(|e| SubscribeErr::LockError(e.to_string()))?;
    let listener = listeners
        .get_mut(sig_uid)
        .ok_or(SubscribeErr::NoListener("No listener when getting ws channels"))?;
    let ws_channels = listener.subscribe(tss_account)?;

    if ws_channels.is_final {
        // all subscribed, wake up the waiting listener to execute the protocol
        let listener =
            listeners.remove(sig_uid).ok_or(SubscribeErr::NoListener("listener remove"))?;
        let (tx, broadcaster) = listener.into_broadcaster();
        let _ = tx.send(Ok(broadcaster));
    };
    Ok(ws_channels)
}
