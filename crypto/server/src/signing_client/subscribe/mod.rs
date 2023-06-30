mod broadcaster;
mod listener;
mod message;

use axum::extract::ws::{self, WebSocket};
use entropy_shared::X25519PublicKey;
use futures::{future, SinkExt, StreamExt};
use kvdb::kv_manager::PartyId;
pub(super) use listener::WsChannels;
use sp_core::{crypto::AccountId32, Bytes};
use subxt::{ext::sp_core::sr25519, tx::PairSigner};
use tokio_tungstenite::{connect_async, tungstenite::Message};
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

// type BoxSink<'a, T> = Pin<std::boxed::Box<dyn Sink<T, Error=SubscribeErr> + Send + 'a>>;

/// Set up websocket connections to other members of the signing committee
pub async fn subscribe_to_them(
    ctx: &SignContext,
    my_id: &PartyId,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    state: &SignerState,
    x25519_public_key: X25519PublicKey,
) -> Result<(), SigningErr> {
    let sig_uid = &ctx.sign_init.sig_uid;
    let connect_to_validators = ctx.sign_init.validators_info.iter().filter(|validators_info| {
        // Decide whether to initiate a connection by comparing public keys
        validators_info.x25519_public_key < x25519_public_key
    }).map(|validator_info| async move {
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

        // Check the response
        if let Some(response_message) = ws_stream.next().await {
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
        } else {
            return Err(SigningErr::ConnectionClosed);
        }

        // Setup channels
        let mut ws_channels = get_ws_channels(state, sig_uid, &validator_info.tss_account)?;

		let remote_party_id = PartyId::new(validator_info.tss_account.clone());

        // Handling incoming / outgoing messages
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(msg) = ws_stream.next() => {
                        if let Ok(msg) = msg {
							if let Message::Text(serialized_signed_message) = msg {
								// deserialize it
								if let Ok(msg) = SigningMessage::try_from(&serialized_signed_message) {
									if let Err(_err) = ws_channels.tx.send(msg).await {
										// log err
										break;
									};
								} else {
									// log that we couldnt deserialize the
									// message
								};
							}
							else {
								// log that we got unexpected message type
							}
						} else {
                            // client disconnected
                            break;
                        };
                    }
                    Ok(msg) = ws_channels.broadcast.recv() => {
						if let Some(party_id) = &msg.to {
							if party_id != &remote_party_id {
								continue;
							}
						}
                        let message_string = serde_json::to_string(&msg).unwrap();
                        if ws_stream.send(Message::Text(message_string)).await.is_err() {
                            // client disconnected
                            break;
                        }
                    }
                }
            }
        });
		Ok::<_, SigningErr>(())
	})
	.collect::<Vec<_>>();

    future::try_join_all(connect_to_validators).await?;

    Ok(())
}

/// Handle an incoming websocket connection
/// This is opened in a separate task for each connection
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
        if let Some((mut ws_channels, remote_party_id)) = ws_channels_option {
            loop {
                tokio::select! {
                    Some(msg) = socket.recv() => {
                        if let Ok(msg) = msg {
                            if let ws::Message::Text(serialized_signed_message) = msg {
                                // deserialize it
                                let msg = SigningMessage::try_from(&serialized_signed_message).ok().unwrap();
                                if let Err(_err) = ws_channels.tx.send(msg).await {
                                    // TODO here we could send the remote peer an error message
                                    // to tell them the signing protocol has finished already
                                    break;
                                };
                            } else {
                                // log that we got unexpected message type
                            }
                        } else {
                            // client disconnected
                            break;
                        };
                    }
                    Ok(msg) = ws_channels.broadcast.recv() => {
                        if let Some(party_id) = &msg.to {
                            if party_id != &remote_party_id {
                                continue;
                            }
                        }
                        let message_string = serde_json::to_string(&msg).unwrap();
                        socket.send(ws::Message::Text(message_string)).await?
                    }
                }
            }
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

    // TODO: should we also check if party_id is in signing group -> limited spots in steam so yes
    if PartyId::new(signing_address) != party_id {
        return Err(SubscribeErr::InvalidSignature("Signature does not match party id."));
    }

    // TODO fix this by having a pending state
    if !app_state.signer_state.contains_listener(&msg.session_id)? {
        // Chain node hasn't yet informed this node of the party. Wait for a timeout and proceed
        // or fail below
        tokio::time::sleep(std::time::Duration::from_secs(SUBSCRIBE_TIMEOUT_SECONDS)).await;

        // add a pending entry
    };

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
