//! Connect to other threshold servers over websocket for exchanging protocol messages
mod broadcaster;
mod listener;
mod message;

use axum::extract::ws::{self, WebSocket};
use futures::{future, SinkExt, StreamExt};
use kvdb::kv_manager::PartyId;
pub(super) use listener::WsChannels;
use sp_core::{crypto::AccountId32, Bytes};
use subxt::{ext::sp_core::sr25519, tx::PairSigner};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use x25519_dalek::PublicKey;

pub use self::{broadcaster::Broadcaster, listener::Listener, message::SubscribeMessage};
use super::{new_party::SignContext, SigningErr};
use crate::{
    chain_api::EntropyConfig,
    get_signer,
    signing_client::{SigningMessage, SubscribeErr, WsError},
    validation::SignedMessage,
    AppState, SignerState, SUBSCRIBE_TIMEOUT_SECONDS,
};

/// Set up websocket connections to other members of the signing committee
pub async fn open_protocol_connections(
    ctx: &SignContext,
    my_id: &PartyId,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    state: &SignerState,
) -> Result<(), SigningErr> {
    let sig_uid = &ctx.sign_init.sig_uid;

    let connect_to_validators = ctx
        .sign_init
        .validators_info
        .iter()
        .filter(|validators_info| {
            // Decide whether to initiate a connection by comparing accound ids
            // otherwise, we wait for them to connect to us
            signer.account_id() > &validators_info.tss_account
        })
        .map(|validator_info| async move {
            // Open a ws connection
            let ws_endpoint = format!("ws://{}/ws", validator_info.ip_address);
            let (mut ws_stream, _response) = connect_async(ws_endpoint).await?;

            // Send a SubscribeMessage
            let server_public_key = PublicKey::from(validator_info.x25519_public_key);
            let signed_message = SignedMessage::new(
                signer.signer(),
                &Bytes(serde_json::to_vec(&SubscribeMessage::new(sig_uid, my_id.clone()))?),
                &server_public_key,
            )?;
            let message_string = serde_json::to_string(&signed_message)?;
            ws_stream.send(Message::Text(message_string)).await?;

            // Check the response from the remote party
            let response_message = ws_stream.next().await.ok_or(SigningErr::ConnectionClosed)?;
            if let Ok(Message::Text(res)) = response_message {
                let subscribe_response: Result<(), String> = serde_json::from_str(&res)?;
                if let Err(error_message) = subscribe_response {
                    return Err(SigningErr::BadSubscribeMessage(error_message));
                }
            } else {
                return Err(SigningErr::UnexpectedEvent(format!(
                    "Unexpected response message {response_message:?}"
                )));
            }

            // Setup channels
            let ws_channels = get_ws_channels(state, sig_uid, &validator_info.tss_account)?;

            let remote_party_id = PartyId::new(validator_info.tss_account.clone());

            // Handle protocol messages
            tokio::spawn(async move {
                if let Err(err) =
                    ws_to_channels(WsConnection::WsStream(ws_stream), ws_channels, remote_party_id)
                        .await
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
pub async fn handle_socket(mut socket: WebSocket, app_state: AppState) -> Result<(), WsError> {
    // Get the first message which we expect to be a SubscribeMessage
    if let Some(Ok(ws::Message::Text(serialized_signed_message))) = socket.recv().await {
        let (subscribe_response, ws_channels_option) =
            match handle_initial_incoming_ws_message(serialized_signed_message, app_state).await {
                Ok((ws_channels, party_id)) => (Ok(()), Some((ws_channels, party_id))),
                Err(err) => (Err(format!("{err:?}")), None),
            };

        // Send them a response as to whether we are happy with their subscribe message
        let subscribe_response_json =
            serde_json::to_string(&subscribe_response).map_err(|_| WsError::ConnectionClosed)?;
        socket.send(ws::Message::Text(subscribe_response_json)).await?;

        // If it was successful, proceed with relaying signing protocol messages
        if let Some((ws_channels, remote_party_id)) = ws_channels_option {
            ws_to_channels(WsConnection::AxumWs(socket), ws_channels, remote_party_id).await?;
        };
    };
    Ok(())
}

/// Handle a subscribe message
async fn handle_initial_incoming_ws_message(
    serialized_signed_message: String,
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

        let validators_info = &listener.user_transaction_request.validators_info;
        if !validators_info.iter().any(|validator_info| {
            &validator_info.x25519_public_key == signed_msg.sender().as_bytes()
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
    mut connection: WsConnection,
    mut ws_channels: WsChannels,
    remote_party_id: PartyId,
) -> Result<(), WsError> {
    loop {
        tokio::select! {
            // Incoming message from remote peer
            Some(serialized_signing_message) = connection.recv() => {
                if let Ok(msg) = SigningMessage::try_from(&serialized_signing_message) {
                    ws_channels.tx.send(msg).await.map_err(|_| WsError::MessageAfterProtocolFinish)?;
                } else {
                    tracing::warn!("Could not deserialize signing protocol message - ignoring");
                    // close connection?
                };
            }
            // Outgoing message (from signing protocol to remote peer)
            Ok(msg) = ws_channels.broadcast.recv() => {
                // Check that the message is for this peer
                if let Some(party_id) = &msg.to {
                    if party_id != &remote_party_id {
                        continue;
                    }
                }
                if let Ok(message_string) = serde_json::to_string(&msg) {
                    // TODO if this fails, the ws connection has been dropped during the protocol
                    // we should inform the chain of this.
                    connection.send(message_string).await?;
                };
            }
        }
    }
}

// A wrapper around incoming and outgoing Websocket types
enum WsConnection {
    WsStream(WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>),
    AxumWs(WebSocket),
}

impl WsConnection {
    pub async fn recv(&mut self) -> Option<String> {
        match self {
            WsConnection::WsStream(ref mut ws_stream) => {
                if let Some(Ok(Message::Text(msg))) = ws_stream.next().await {
                    Some(msg)
                } else {
                    None
                }
            },
            WsConnection::AxumWs(ref mut axum_ws) => {
                if let Some(Ok(ws::Message::Text(msg))) = axum_ws.recv().await {
                    Some(msg)
                } else {
                    None
                }
            },
        }
    }

    pub async fn send(&mut self, msg: String) -> Result<(), WsError> {
        match self {
            WsConnection::WsStream(ref mut ws_stream) =>
                ws_stream.send(Message::Text(msg)).await.map_err(|_| WsError::ConnectionClosed),
            WsConnection::AxumWs(ref mut axum_ws) =>
                axum_ws.send(ws::Message::Text(msg)).await.map_err(|_| WsError::ConnectionClosed),
        }
    }
}
