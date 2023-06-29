mod broadcaster;
mod listener;
mod message;

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
    signing_client::{SigningMessage, SubscribeErr},
    validation::SignedMessage,
    SignerState,
};

/// Call `subscribe` on every other node with a reqwest client. Merge the streamed responses
/// into a single stream.
pub async fn subscribe_to_them(
    ctx: &SignContext,
    my_id: &PartyId,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    state: &SignerState,
    x25519_public_key: X25519PublicKey,
) -> Result<(), SigningErr> {
    let sig_uid = ctx.sign_init.sig_uid.clone();
    let validators_to_connect_to =
        ctx.sign_init.validator_send_info.iter().filter(|validator_send_info| {
            // Decide whether to initiate a connection by comparing public keys
            validator_send_info.x25519_public_key > x25519_public_key
        });

    for validator_send_info in validators_to_connect_to {
        let ws_endpoint = format!("ws://{}/ws", validator_send_info.ip_address);
        let (mut ws_stream, _response) = connect_async(ws_endpoint).await.unwrap();

        let server_public_key = PublicKey::from(validator_send_info.x25519_public_key);
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
        let mut ws_channels = {
            let mut listeners = state.listeners.lock().unwrap();
            // .map_err(|e| SubscribeErr::LockError(e.to_string()))?;
            let listener =
                listeners.get_mut(&sig_uid).ok_or(SubscribeErr::NoListener("no listener"))?;
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
    }
    Ok(())
}
