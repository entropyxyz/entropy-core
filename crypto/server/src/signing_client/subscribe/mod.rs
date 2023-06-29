mod broadcaster;
mod listener;
mod message;

use kvdb::kv_manager::PartyId;
pub(super) use listener::WsChannels;
use sp_core::Bytes;
use subxt::{ext::sp_core::sr25519, tx::PairSigner};
use x25519_dalek::PublicKey;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use futures::SinkExt;

pub use self::{broadcaster::Broadcaster, listener::Listener, message::SubscribeMessage};
use super::{new_party::SignContext, SigningErr};
use crate::{chain_api::EntropyConfig, validation::SignedMessage, SignerState, signing_client::SubscribeErr};


// pub async fn handle_ws_connection(ws: Box<dyn Stream<Item = SigningMessage> + Sink<Item = SigningMessage>>,  ws_channels: WsChannels) {
	// let msg = SigningMessage::try_from(&message.data).ok()?;
// }
// 	// loop {
// 	// tokio::select! {
// 	// 	 Some(msg) = socket.recv() => {
// 	// 		 if let Ok(msg) = msg {
// 	// 			// deserialize i
// 	// 			// wrap it together with sender info
// 	// 			// send it on the tx channel
// 	// 			tx.send(msg)
// 	// 		 } else {
// 	// 			 // client disconnected
// 	// 			 return;
// 	// 		 };
// 	// 	 }
// 	// 	 Some(msg) rx_from_sign_protocol_to_ws.recv() => {
// 	// 		 if socket.send(msg).await.is_err() {
// 	// 			 // client disconnected
// 	// 			 return;
// 	// 		 }
// 	// 	 }
// 	// }
// 	// }
// }


/// Call `subscribe` on every other node with a reqwest client. Merge the streamed responses
/// into a single stream.
pub async fn subscribe_to_them(
    ctx: &SignContext,
    my_id: &PartyId,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
	state: &SignerState,
) -> Result<(), SigningErr> {
	let sig_uid = ctx.sign_init.sig_uid.clone();
    let validators_to_connect_to = ctx
        .sign_init
        .validator_send_info
        .iter()
		.filter(|validator_send_info| {
			// compare send into, decide if to connect
			true
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

		let message_string = serde_json::to_string(&signed_message).unwrap();
		ws_stream.send(Message::Text(message_string)).await.unwrap();
		let ws_channels = {
				let mut listeners = state
					.listeners
					.lock()
					.unwrap();
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

		if ws_channels.is_final {
			// convert listener to broadcaster
		}
		// spawn a task
		// call handle_ws_connection(sender, recv, ws_channels)
	};



    Ok(())
}
