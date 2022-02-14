//! The Node requests the client to open a communication manager in order to
//! manage communication between the signing parties.

use parity_scale_codec::{Decode, Encode};

// ToDo: Should we move declaration of structs to /crypto/common/ ?
//       If those types are necessary for the node's OCW, then maybe we should

/// This is the data transmitted in the signature generation request.
#[derive(Debug, Encode, Decode, FromForm)]
pub struct ComManagerReq {
	/// temporary dummy, delete this later
	pub demo: u8,
	/* hmmmm, what data does the Communication Manager need to know??
	 * do we want to limit ports or whatever?? */
}

/// Response of the Communication Manager
#[derive(Debug, Encode)]
struct UnencodedComManagerRes {
	pub demo: u8,
	// what is the ComManager's response??
}

/// Response to the node if the signature was created.
/// i.e. a signature that the data was stored successfully or Error Code.
#[derive(Responder)]
#[response(status = 200, content_type = "application/x-parity-scale-codec")]
pub struct ComManagerRes(Vec<u8>);

//ToDo: receive keyshare and store locally
#[post("/com_manager", format = "application/x-parity-scale-codec", data = "<encoded_data>")]
pub fn start_com_manager(encoded_data: Vec<u8>) -> ComManagerRes {
	let _data = ComManagerReq::decode(&mut encoded_data.as_ref()).ok().unwrap();
	todo!();
	ComManagerRes(UnencodedComManagerRes { demo: 1 }.encode());
}
// ///////////////////////////
// /// 


use anyhow::Result;
use std::{
	collections::hash_map::{Entry, HashMap},
	sync::{
		atomic::{AtomicU16, Ordering},
		Arc,
	},
};

use futures::Stream;
use rocket::{
	data::ToByteUnit,
	http::Status,
	request::{FromRequest, Outcome, Request},
	response::stream::{stream, Event, EventStream},
	serde::json::Json,
	State,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock};

#[rocket::get("/rooms/<room_id>/subscribe")]
pub async fn subscribe(
	db: &State<Db>,
	mut shutdown: rocket::Shutdown,
	last_seen_msg: LastEventId,
	room_id: &str,
) -> EventStream<impl Stream<Item = Event>> {
	let room = db.get_room_or_create_empty(room_id).await;
	let mut subscription = room.subscribe(last_seen_msg.0);
	EventStream::from(stream! {
		loop {
			let (id, msg) = tokio::select! {
				message = subscription.next() => message,
				_ = &mut shutdown => return,
			};
			yield Event::data(msg)
				.event("new-message")
				.id(id.to_string())
		}
	})
}

#[rocket::post("/rooms/<room_id>/issue_unique_idx")]
pub async fn issue_idx(db: &State<Db>, room_id: &str) -> Json<IssuedUniqueIdx> {
	let room = db.get_room_or_create_empty(room_id).await;
	let idx = room.issue_unique_idx();
	Json::from(IssuedUniqueIdx { unique_idx: idx })
}

#[rocket::post("/rooms/<room_id>/broadcast", data = "<message>")]
pub async fn broadcast(db: &State<Db>, room_id: &str, message: String) -> Status {
	let room = db.get_room_or_create_empty(room_id).await;
	room.publish(message).await;
	Status::Ok
}

pub struct Db {
	rooms: RwLock<HashMap<String, Arc<Room>>>,
}

pub struct Room {
	messages: RwLock<Vec<String>>,
	message_appeared: Notify,
	subscribers: AtomicU16,
	next_idx: AtomicU16,
}

impl Db {
	pub fn empty() -> Self {
		Self { rooms: RwLock::new(HashMap::new()) }
	}

	pub async fn get_room_or_create_empty(&self, room_id: &str) -> Arc<Room> {
		let rooms = self.rooms.read().await;
		if let Some(room) = rooms.get(room_id) {
			// If no one is watching this room - we need to clean it up first
			if !room.is_abandoned() {
				return room.clone()
			}
		}
		drop(rooms);

		let mut rooms = self.rooms.write().await;
		match rooms.entry(room_id.to_owned()) {
			Entry::Occupied(entry) if !entry.get().is_abandoned() => entry.get().clone(),
			Entry::Occupied(entry) => {
				let room = Arc::new(Room::empty());
				*entry.into_mut() = room.clone();
				room
			},
			Entry::Vacant(entry) => entry.insert(Arc::new(Room::empty())).clone(),
		}
	}
}

impl Room {
	pub fn empty() -> Self {
		Self {
			messages: RwLock::new(vec![]),
			message_appeared: Notify::new(),
			subscribers: AtomicU16::new(0),
			next_idx: AtomicU16::new(1),
		}
	}

	pub async fn publish(self: &Arc<Self>, message: String) {
		let mut messages = self.messages.write().await;
		messages.push(message);
		self.message_appeared.notify_waiters();
	}

	pub fn subscribe(self: Arc<Self>, last_seen_msg: Option<u16>) -> Subscription {
		self.subscribers.fetch_add(1, Ordering::SeqCst);
		Subscription { room: self, next_event: last_seen_msg.map(|i| i + 1).unwrap_or(0) }
	}

	pub fn is_abandoned(&self) -> bool {
		self.subscribers.load(Ordering::SeqCst) == 0
	}

	pub fn issue_unique_idx(&self) -> u16 {
		self.next_idx.fetch_add(1, Ordering::Relaxed)
	}
}

pub struct Subscription {
	room: Arc<Room>,
	next_event: u16,
}

impl Subscription {
	pub async fn next(&mut self) -> (u16, String) {
		loop {
			let history = self.room.messages.read().await;
			if let Some(msg) = history.get(usize::from(self.next_event)) {
				let event_id = self.next_event;
				self.next_event = event_id + 1;
				return (event_id, msg.clone())
			}
			let notification = self.room.message_appeared.notified();
			drop(history);
			notification.await;
		}
	}
}

impl Drop for Subscription {
	fn drop(&mut self) {
		self.room.subscribers.fetch_sub(1, Ordering::SeqCst);
	}
}

/// Represents a header Last-Event-ID
pub struct LastEventId(Option<u16>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for LastEventId {
	type Error = &'static str;

	async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
		let header = request.headers().get_one("Last-Event-ID").map(|id| id.parse::<u16>());
		match header {
			Some(Ok(last_seen_msg)) => Outcome::Success(LastEventId(Some(last_seen_msg))),
			Some(Err(_parse_err)) =>
				Outcome::Failure((Status::BadRequest, "last seen msg id is not valid")),
			None => Outcome::Success(LastEventId(None)),
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IssuedUniqueIdx {
	unique_idx: u16,
}

