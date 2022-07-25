#![allow(dead_code)]
#![allow(unused_imports)]
use futures::Stream;
use rocket::{
	response::stream::EventStream,
	serde::{json::Json, Deserialize, Serialize},
	tokio::{
		select,
		sync::broadcast::{error::RecvError, Sender},
	},
	Shutdown, State,
};
use tokio::sync::{
	broadcast::{self, Receiver},
	mpsc, oneshot,
};
use tracing::{info, instrument};

use crate::{Global, PartyId};

use self::context::{PartyInfo, ProtocolCommunication, SignInitSanitized};

mod context;
mod init_party_info;
mod types;
pub(crate) use init_party_info::InitPartyInfo;
pub(crate) use types::SigningParty;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SubscribingMessage {
	pub party_id: PartyId,
}

impl SubscribingMessage {
	pub(crate) fn new(party_id: PartyId) -> Self {
		Self { party_id }
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SigningMessage {
	pub party_id: PartyId,
}

// /// Handles initiation procedure for the signing protocol before handing off the state to
// /// `execute_sign`. 1. Unpack first message to hand to `handle_sign_init`, which sanitizes the
// /// message 2. Create a channel for communication between protocol and final result aggregator
// /// 3. Retrieve the local `Context` for the signing protocol
// /// 4. Hand off all context to `execute_sign`
// // #[instrument]
// pub(crate) async fn handle_sign(
// 	tx: Sender<SigningMessage>,
// 	rx_channels: Vec<EventStream<SigningMessage>>,
// ) -> anyhow::Result<()> {
// 	// info!("handle_sign");
// 	// TODO(TK): most of this is copy-pasted from tofnd, with adapted types. Run over it with a test
// 	// comb. 1. Unpack first message to hand to `handle_sign_init`, which sanitizes the message
// 	let (sign_init, party_info) = handle_sign_init(tx, rx_channels).await?;

// 	// 2. channel for communication between protocol and final result (seems suss)
// 	let (aggr_tx, aggr_rx): (oneshot::Sender<SigningMessage>, oneshot::Receiver<SigningMessage>) =
// 		oneshot::channel();

// 	// 3. Retrieve Context
// 	let todo_subindex = 0; // TODO(TK): placeholder
// 	let ctx = context::Context::new(sign_init.clone(), party_info.clone(), todo_subindex)?;
// 	// wrap channels needed by internal threads; receiver chan for router and sender

// 	// channels for communication between router (sender) and protocol threads (receivers)
// 	// let (sign_sender, sign_receiver) = mpsc::unbounded_channel();
// 	// let chans = ProtocolCommunication::new(sign_receiver, rx_channels.clone());

// 	// 4. Hand off all context to execute sign
// 	// let signature = execute_sign(chans, &ctx).await;
// 	// let _ = aggr_tx.send(signature);

// 	// 5. handle results

// 	Ok(())
// }

// // async fn execute_sign(chans: _, ctx: _) -> _ {
// //     todo!()
// // }

// // #[instrument]
// async fn handle_sign_init(
// 	tx: Sender<SigningMessage>, // should actually be a stream of messages in
// 	rx_channels: Vec<EventStream<SigningMessage>>,
// ) -> anyhow::Result<(SignInitSanitized, PartyInfo)> {
// 	// info!("handle_sign_init");
// 	todo!()
// }

// /// Validate `SigningRegistrationMessage`
// fn validate_registration(msg: &SubscribingMessage) {
// 	todo!();
// }
// impl SubscribingMessage {
// 	pub(crate) fn new(party_id: usize) -> Self {
// 		Self { party_id }
// 	}
// }
