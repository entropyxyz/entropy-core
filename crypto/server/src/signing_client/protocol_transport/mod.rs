//! Connect to other threshold servers over websocket for exchanging protocol messages
mod broadcaster;
mod listener;
mod message;
pub mod noise;

use axum::extract::ws::{self, WebSocket};
use entropy_shared::X25519PublicKey;
use futures::{future, SinkExt, StreamExt};
use kvdb::kv_manager::PartyId;
pub(super) use listener::WsChannels;
use sp_core::{crypto::AccountId32, Bytes};
use subxt::{ext::sp_core::sr25519, tx::PairSigner};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use x25519_dalek::PublicKey;

use self::noise::{noise_handshake_initiator, noise_handshake_responder, EncryptedWsConnection};
pub use self::{broadcaster::Broadcaster, listener::Listener, message::SubscribeMessage};
use super::SigningErr;
use crate::{
    chain_api::EntropyConfig,
    get_signer,
    signing_client::{SigningMessage, SubscribeErr, WsError},
    user::api::ValidatorInfo,
    validation::SignedMessage,
    AppState, SignerState, SUBSCRIBE_TIMEOUT_SECONDS,
};

/// Set up websocket connections to other members of the signing committee
pub async fn open_protocol_connections(
    validators_info: &[ValidatorInfo],
    session_uid: &str,
    my_id: &PartyId,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    state: &SignerState,
) -> Result<(), SigningErr> {
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
            let ws_stream = WsConnection::WsStream(ws_stream);

            // Send a SubscribeMessage in the payload of the final handshake message
            let server_public_key = PublicKey::from(validator_info.x25519_public_key);
            let signed_message = SignedMessage::new(
                signer.signer(),
                &Bytes(serde_json::to_vec(&SubscribeMessage::new(session_uid, my_id.clone()))?),
                &server_public_key,
            )?;
            let subscribe_message_vec = serde_json::to_vec(&signed_message)?;

            let mut encrypted_connection = noise_handshake_initiator(
                ws_stream,
                signer.signer(),
                validator_info.x25519_public_key,
                subscribe_message_vec,
            )
            .await
            .map_err(|e| SigningErr::EncryptedConnection(e.to_string()))?;

            // Check the response as to whether they accepted our SubscribeMessage
            let response_message = encrypted_connection
                .recv()
                .await
                .map_err(|e| SigningErr::EncryptedConnection(e.to_string()))?;
            let subscribe_response: Result<(), String> = serde_json::from_str(&response_message)?;
            if let Err(error_message) = subscribe_response {
                return Err(SigningErr::BadSubscribeMessage(error_message));
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

            Ok::<_, SigningErr>(())
        })
        .collect::<Vec<_>>();

    future::try_join_all(connect_to_validators).await?;

    Ok(())
}

/// Handle an incoming websocket connection
pub async fn handle_socket(socket: WebSocket, app_state: AppState) -> Result<(), WsError> {
    let ws_stream = WsConnection::AxumWs(socket);

    let signer = get_signer(&app_state.kv_store).await?;

    let (mut encrypted_connection, serialized_signed_message) =
        noise_handshake_responder(ws_stream, signer.signer())
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
    serialized_signed_message: String,
    remote_public_key: X25519PublicKey,
    app_state: AppState,
) -> Result<(WsChannels, PartyId), SubscribeErr> {
    let signed_msg: SignedMessage = serde_json::from_str(&serialized_signed_message)?;
    if !signed_msg.verify() {
        return Err(SubscribeErr::InvalidSignature("Invalid signature."));
    }
    let signer = get_signer(&app_state.kv_store)
        .await
        .map_err(|e| SubscribeErr::UserError(e.to_string()))?;

    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| SubscribeErr::Decryption(e.to_string()))?;
    let msg: SubscribeMessage = serde_json::from_slice(&decrypted_message)?;
    tracing::info!("Got ws connection, with message: {msg:?}");

    let party_id = msg.party_id().map_err(SubscribeErr::InvalidPartyId)?;

    let signing_address = signed_msg.account_id();

    if PartyId::new(signing_address) != party_id {
        return Err(SubscribeErr::InvalidSignature("Signature does not match party id."));
    }

    if !app_state.signer_state.contains_listener(&msg.session_id)? {
        // Chain node hasn't yet informed this node of the party. Wait for a timeout and proceed
        // or fail below
        tokio::time::sleep(std::time::Duration::from_secs(SUBSCRIBE_TIMEOUT_SECONDS)).await;
    };

    {
        // Check that the given public key matches the public key we got in the
        // UserTransactionRequest
        let mut listeners = app_state
            .signer_state
            .listeners
            .lock()
            .map_err(|e| SubscribeErr::LockError(e.to_string()))?;
        let listener =
            listeners.get(&msg.session_id).ok_or(SubscribeErr::NoListener("no listener"))?;

        let validators_info = &listener.validators_info;
        if !validators_info.iter().any(|validator_info| {
            validator_info.x25519_public_key == remote_public_key
                && validator_info.tss_account == signed_msg.account_id()
        }) {
            // Make the signing process fail, since one of the commitee has misbehaved
            listeners.remove(&msg.session_id);
            return Err(SubscribeErr::Decryption(
                "Public key does not match that given in UserTransactionRequest".to_string(),
            ));
        }
    }

    let ws_channels =
        get_ws_channels(&app_state.signer_state, &msg.session_id, &signed_msg.account_id())?;

    Ok((ws_channels, party_id))
}

/// Subscribe to get channels
fn get_ws_channels(
    state: &SignerState,
    sig_uid: &str,
    tss_account: &AccountId32,
) -> Result<WsChannels, SubscribeErr> {
    let mut listeners =
        state.listeners.lock().map_err(|e| SubscribeErr::LockError(e.to_string()))?;
    let listener = listeners.get_mut(sig_uid).ok_or(SubscribeErr::NoListener("no listener"))?;
    let ws_channels = listener.subscribe(tss_account)?;

    if ws_channels.is_final {
        // all subscribed, wake up the waiting listener in new_party
        let listener =
            listeners.remove(sig_uid).ok_or(SubscribeErr::NoListener("listener remove"))?;
        let (tx, broadcaster) = listener.into_broadcaster();
        let _ = tx.send(Ok(broadcaster));
    };
    Ok(ws_channels)
}

/// Send singing protocol messages over websocket, and websocket messages to signing protocol
async fn ws_to_channels(
    mut connection: EncryptedWsConnection,
    mut ws_channels: WsChannels,
    remote_party_id: PartyId,
) -> Result<(), WsError> {
    loop {
        tokio::select! {
            // Incoming message from remote peer
            signing_message_result = connection.recv() => {
                let serialized_signing_message = signing_message_result.map_err(|e| WsError::EncryptedConnection(e.to_string()))?;
                let msg = SigningMessage::try_from(&serialized_signing_message)?;
                ws_channels.tx.send(msg).await.map_err(|_| WsError::MessageAfterProtocolFinish)?;
            }
            // Outgoing message (from signing protocol to remote peer)
            Ok(msg) = ws_channels.broadcast.recv() => {
                // Check that the message is for this peer
                if let Some(party_id) = &msg.to {
                    if party_id != &remote_party_id {
                        continue;
                    }
                }
                let message_string = serde_json::to_string(&msg)?;
                // TODO if this fails, the ws connection has been dropped during the protocol
                // we should inform the chain of this.
                connection.send(message_string).await.map_err(|e| WsError::EncryptedConnection(e.to_string()))?;
            }
        }
    }
}

// A wrapper around incoming and outgoing Websocket types
pub enum WsConnection {
    WsStream(WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>),
    AxumWs(WebSocket),
}

impl WsConnection {
    pub async fn recv(&mut self) -> Result<Vec<u8>, WsError> {
        match self {
            WsConnection::WsStream(ref mut ws_stream) => {
                if let Message::Binary(msg) =
                    ws_stream.next().await.ok_or(WsError::ConnectionClosed)??
                {
                    Ok(msg)
                } else {
                    Err(WsError::UnexpectedMessageType)
                }
            },
            WsConnection::AxumWs(ref mut axum_ws) => {
                if let ws::Message::Binary(msg) =
                    axum_ws.recv().await.ok_or(WsError::ConnectionClosed)??
                {
                    Ok(msg)
                } else {
                    Err(WsError::UnexpectedMessageType)
                }
            },
        }
    }

    pub async fn send(&mut self, msg: Vec<u8>) -> Result<(), WsError> {
        match self {
            WsConnection::WsStream(ref mut ws_stream) =>
                ws_stream.send(Message::Binary(msg)).await.map_err(|_| WsError::ConnectionClosed),
            WsConnection::AxumWs(ref mut axum_ws) =>
                axum_ws.send(ws::Message::Binary(msg)).await.map_err(|_| WsError::ConnectionClosed),
        }
    }
}
