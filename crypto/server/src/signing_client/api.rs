use std::str;

use entropy_shared::OCWMessage;
use kvdb::kv_manager::KvManager;
use parity_scale_codec::Decode;
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use tracing::instrument;

use crate::{
    helpers::signing::SignatureState,
    signing_client::{
        subscribe::{Listener, Receiver},
        SignerState, SigningErr, SubscribeErr, SubscribeMessage,
    },
};

const SUBSCRIBE_TIMEOUT_SECONDS: u64 = 10;

/// https://github.com/axelarnetwork/tofnd/blob/117a35b808663ceebfdd6e6582a3f0a037151198/src/gg20/sign/mod.rs#L39
/// Execute a signing protocol with a new party.
/// This endpoint is called by the blockchain.
#[instrument(skip(kv))]
#[post("/new_party", data = "<encoded_data>")]
pub async fn new_party(
    encoded_data: Vec<u8>,
    kv: &State<KvManager>,
) -> Result<Status, SigningErr> {
    // TODO encryption and authentication.
    let data = OCWMessage::decode(&mut encoded_data.as_ref())?;

    for message in data {
        let sighash = hex::encode(&message.sig_request.sig_hash);

        match kv.kv().reserve_key(sighash).await {
            Ok(reservation) => {
                // TODO we should really Serialize this but `put()` needs to get refactored first
                let value = serde_json::to_string(&message).unwrap();

                kv.kv().put(reservation, value.into()).await?;
            },

            Err(_) => {
                println!("OCW submitted a sighash that was already reserved. Weird. Skipping...");
                return Ok(Status::Ok);
            },
        }
    }

    Ok(Status::Ok)
}

/// Other nodes in the party call this method to subscribe to this node's broadcasts.
/// The SigningProtocol begins when all nodes in the party have called this method on this node.
#[post("/subscribe_to_me", data = "<msg>")]
pub async fn subscribe_to_me(
    msg: Json<SubscribeMessage>,
    end: Shutdown,
    state: &State<SignerState>,
) -> Result<EventStream![], SubscribeErr> {
    let msg = msg.into_inner();
    msg.validate_registration()?;
    info!("got subscribe, with message: {msg:?}");

    if !state.contains_listener(&msg.party_id) {
        // CM hasn't yet informed this node of the party. Wait for a timeout and procede (or fail
        // below)
        tokio::time::sleep(std::time::Duration::from_secs(SUBSCRIBE_TIMEOUT_SECONDS)).await;
    };

    let rx = {
        let mut listeners = state.listeners.lock().expect("lock shared data");
        let listener =
            listeners.get_mut(&msg.party_id).ok_or(SubscribeErr::NoListener("no listener"))?;
        let rx_outcome = listener.subscribe(&msg)?;

        // If this is the last subscriber, remove the listener from state
        match rx_outcome {
            Receiver::Receiver(rx) => rx,
            Receiver::FinalReceiver(rx) => {
                // all subscribed, wake up the waiting listener in new_party
                let listener = listeners
                    .remove(&msg.party_id)
                    .ok_or(SubscribeErr::NoListener("listener remove"))?;
                let (tx, broadcaster) = listener.into_broadcaster();
                let _ = tx.send(Ok(broadcaster));
                rx
            },
        }
    };

    Ok(Listener::create_event_stream(rx, end))
}


use rocket::response::status;
use serde::{Deserialize, Serialize};

// TODO: JA remove all below temporary
#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
#[derive(Clone)]
pub struct Message {
    pub message: String,
}

/// Returns the signature of the requested sighash
///
/// This will be removed when after client participates in signing
#[post("/signature", data = "<msg>")]
pub async fn get_signature(
    msg: Json<Message>,
    signatures: &State<SignatureState>,
) -> status::Accepted<String> {
    let sig = signatures.get(&msg.message);
    status::Accepted(Some(base64::encode(sig.as_ref())))
}

/// Drains all signatures from the state
/// Client calls this after they receive the signature at `/signature`
///
/// This will be removed when after client participates in signing
#[get("/drain")]
pub async fn drain(signatures: &State<SignatureState>) -> Result<Status, ()> {
    signatures.drain();
    Ok(Status::Ok)
}
