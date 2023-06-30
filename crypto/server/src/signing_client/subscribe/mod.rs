mod broadcaster;
mod listener;
mod message;

use axum::extract::ws::{self, WebSocket};
use entropy_shared::X25519PublicKey;
use futures::{SinkExt, StreamExt};
use kvdb::kv_manager::PartyId;
pub(super) use listener::WsChannels;
use sp_core::Bytes;
use subxt::{ext::sp_core::sr25519, tx::PairSigner};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use x25519_dalek::PublicKey;

pub use self::{broadcaster::Broadcaster, listener::Listener, message::SubscribeMessage};
use super::{new_party::SignContext, SigningErr};
use crate::{
    chain_api::EntropyConfig,
    get_signer,
    signing_client::{SigningMessage, SubscribeErr},
    validation::SignedMessage,
    AppState, SignerState, SUBSCRIBE_TIMEOUT_SECONDS,
};

/// Set up websocket connections to other members of the signing committee
pub async fn subscribe_to_them(
    ctx: &SignContext,
    my_id: &PartyId,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    state: &SignerState,
    x25519_public_key: X25519PublicKey,
) -> Result<(), SigningErr> {
    let sig_uid = ctx.sign_init.sig_uid.clone();
    let validators_to_connect_to =
        ctx.sign_init.validators_info.iter().filter(|validators_info| {
            // Decide whether to initiate a connection by comparing public keys
            validators_info.x25519_public_key < x25519_public_key
        });

    for validators_info in validators_to_connect_to {
        let ws_endpoint = format!("ws://{}/ws", validators_info.ip_address);
        let (mut ws_stream, _response) = connect_async(ws_endpoint).await.unwrap();

        let server_public_key = PublicKey::from(validators_info.x25519_public_key);
        let signed_message = SignedMessage::new(
            signer.signer(),
            &Bytes(serde_json::to_vec(&SubscribeMessage::new(
                &ctx.sign_init.sig_uid,
                my_id.clone(),
            ))?),
            &server_public_key,
        )?;

        let message_string = serde_json::to_string(&signed_message)?;
        ws_stream.send(Message::Text(message_string)).await.unwrap();

        if let Some(response_message) = ws_stream.next().await {
            if let Ok(Message::Text(res)) = response_message {
                let subscribe_response: Result<(), String> = serde_json::from_str(&res).unwrap();
                match subscribe_response {
                    Ok(()) => {
                        let mut ws_channels = {
                            let mut listeners = state.listeners.lock().unwrap();
                            // .map_err(|e| SubscribeErr::LockError(e.to_string()))?;
                            let listener = listeners
                                .get_mut(&sig_uid)
                                .ok_or(SubscribeErr::NoListener("no listener"))?;
                            let ws_channels = listener.subscribe();

                            if ws_channels.is_final {
                                // all subscribed, wake up the waiting listener in new_party
                                let listener = listeners
                                    .remove(&sig_uid)
                                    .ok_or(SubscribeErr::NoListener("listener remove"))?;
                                let (tx, broadcaster) = listener.into_broadcaster();
                                let _ = tx.send(Ok(broadcaster));
                            };
                            ws_channels
                        };

                        tokio::spawn(async move {
                            loop {
                                tokio::select! {
                                    Some(msg) = ws_stream.next() => {
                                        if let Ok(msg) = msg {
                                            match msg {
                                                Message::Text(serialized_signed_message) => {
                                                    // deserialize it
                                                    let msg = SigningMessage::try_from(&serialized_signed_message).ok().unwrap();
                                                    if let Err(_err) = ws_channels.tx.send(msg).await {
                                                        // log err
                                                        break;
                                                    };
                                                }
                                                _ => {
                                                    // log that we got unexpected message type
                                                }
                                            }
                                        } else {
                                            // client disconnected
                                            break;
                                        };
                                    }
                                    Ok(msg) = ws_channels.broadcast.recv() => {
                                        let message_string = serde_json::to_string(&msg).unwrap();
                                        if ws_stream.send(Message::Text(message_string)).await.is_err() {
                                            // client disconnected
                                            break;
                                        }
                                    }
                                }
                            }
                        });
                    },
                    Err(error_message) => {
                        return Err(SigningErr::BadSubscribeMessage(error_message));
                    },
                }
            } else {
                return Err(SigningErr::UnexpectedEvent(format!(
                    "Unexpected response message {:?}",
                    response_message
                )));
            }
        } else {
            return Err(SigningErr::ConnectionClosed);
        }
    }
    Ok(())
}

/// Handle an incoming websocket connection
pub async fn handle_socket(mut socket: WebSocket, app_state: AppState) {
    // Get the first message which we expect to be a SubscribeMessage
    if let Some(Ok(ws::Message::Text(serialized_signed_message))) = socket.recv().await {
        let (subscribe_response, ws_channels_option) =
            match handle_initial_incoming_ws_message(serialized_signed_message, app_state).await {
                Ok(ws_channels) => (Ok(()), Some(ws_channels)),
                Err(err) => (Err(format!("{:?}", err)), None),
            };

        // Send them a response as to whether we are happy with their subscribe message
        let subscribe_response_json = serde_json::to_string(&subscribe_response).unwrap();
        if socket.send(ws::Message::Text(subscribe_response_json)).await.is_err() {
            // Cannot send response message as they have closed connection
            return;
        };

        // If it was successful, proceed with relaying signing protocol messages
        if let Some(mut ws_channels) = ws_channels_option {
            loop {
                tokio::select! {
                    Some(msg) = socket.recv() => {
                        if let Ok(msg) = msg {
                            match msg {
                                ws::Message::Text(serialized_signed_message) => {
                                    // deserialize it
                                    let msg = SigningMessage::try_from(&serialized_signed_message).ok().unwrap();
                                    if let Err(_err) = ws_channels.tx.send(msg).await {
                                        // log the error
                                        break;
                                    };
                                }
                                _ => {
                                    // log that we got unexpected message type
                                }
                            }
                        } else {
                            // client disconnected
                            break;
                        };
                    }
                    Ok(msg) = ws_channels.broadcast.recv() => {
                        let message_string = serde_json::to_string(&msg).unwrap();
                        if socket.send(ws::Message::Text(message_string)).await.is_err() {
                            // client disconnected
                            break;
                        }
                    }
                }
            }
        };
    };
}

async fn handle_initial_incoming_ws_message(
    serialized_signed_message: String,
    app_state: AppState,
) -> Result<WsChannels, SubscribeErr> {
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

    tracing::info!("got ws connection, with message: {msg:?}");

    let party_id = msg.party_id().map_err(SubscribeErr::InvalidPartyId)?;

    let signing_address = signed_msg.account_id();

    // TODO: should we also check if party_id is in signing group -> limited spots in steam so yes
    if PartyId::new(signing_address) != party_id {
        return Err(SubscribeErr::InvalidSignature("Signature does not match party id."));
    }

    if !app_state.signer_state.contains_listener(&msg.session_id)? {
        // Chain node hasn't yet informed this node of the party. Wait for a timeout and proceed
        // or fail below
        tokio::time::sleep(std::time::Duration::from_secs(SUBSCRIBE_TIMEOUT_SECONDS)).await;
    };

    let ws_channels = {
        let mut listeners = app_state
            .signer_state
            .listeners
            .lock()
            .map_err(|e| SubscribeErr::LockError(e.to_string()))?;
        let listener =
            listeners.get_mut(&msg.session_id).ok_or(SubscribeErr::NoListener("no listener"))?;
        let ws_channels = listener.subscribe();

        if ws_channels.is_final {
            // all subscribed, wake up the waiting listener in new_party
            let listener = listeners
                .remove(&msg.session_id)
                .ok_or(SubscribeErr::NoListener("listener remove"))?;
            let (tx, broadcaster) = listener.into_broadcaster();
            let _ = tx.send(Ok(broadcaster));
        };
        ws_channels
    };

    Ok(ws_channels)
}
