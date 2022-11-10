use std::{io, str};

use kvdb::kv_manager::KvManager;
use parity_scale_codec::Decode;
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use substrate_common::OCWMessage;
use subxt::ext::sp_runtime::AccountId32;
use tracing::instrument;

use crate::{
    sign_init::{MessageDigest, SignInit},
    signing_client::{
        new_party::{Channels, Gg20Service},
        subscribe::{subscribe_to_them, Listener, Receiver},
        SignerState, SigningErr, SubscribeErr, SubscribeMessage,
    },
    utils::SignatureState,
};

const SUBSCRIBE_TIMEOUT_SECONDS: u64 = 10;

/// https://github.com/axelarnetwork/tofnd/blob/117a35b808663ceebfdd6e6582a3f0a037151198/src/gg20/sign/mod.rs#L39
/// Execute a signing protocol with a new party.
/// This endpoint is called by the blockchain.
#[instrument(skip(kv_manager))]
#[post("/new_party", data = "<encoded_data>")]
pub async fn new_party(
    encoded_data: Vec<u8>,
    state: &State<SignerState>,
    kv_manager: &State<KvManager>,
    signatures: &State<SignatureState>,
) -> Result<Status, SigningErr> {
    let data = OCWMessage::decode(&mut encoded_data.as_ref())?;

    for message in data {
        // todo: temporary hack, replace with correct data
        let info = SignInit::temporary_data(message.clone());
        let gg20_service = Gg20Service::new(state, kv_manager);

        // set up context for signing protocol execution
        let sign_context = gg20_service.get_sign_context(info.clone()).await?;

        // subscribe to all other participating parties. Listener waits for other subscribers.
        let (rx_ready, listener) = Listener::new();
        state
            .listeners
            .lock()
            .expect("lock shared data")
            .insert(sign_context.sign_init.party_uid.to_string(), listener);
        let channels = {
            let stream_in = subscribe_to_them(&sign_context).await?;
            let broadcast_out = rx_ready.await??;
            Channels(broadcast_out, stream_in)
        };

        let result = gg20_service.execute_sign(&sign_context, channels).await;
        match result {
            Err(e) => {
                warn!("{}", e.to_string());
            },
            Ok(v) => {
                gg20_service.handle_result(
                    &v,
                    message.sig_request.sig_hash.as_slice().try_into().unwrap(),
                    signatures,
                );
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
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Message {
    pub message: String,
}

#[post("/signature", data = "<msg>")]
pub async fn get_signature(
    msg: Json<Message>,
    signatures: &State<SignatureState>,
) -> status::Accepted<String> {
    let sig = signatures.get(&msg.message);
    status::Accepted(Some(base64::encode(sig.as_ref())))
}

#[get("/drain")]
pub async fn drain(signatures: &State<SignatureState>) -> Result<Status, ()> {
    signatures.drain();
    Ok(Status::Ok)
}
