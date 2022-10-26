use std::str;

use k256::ecdsa::recoverable;
use kvdb::kv_manager::KvManager;
use parity_scale_codec::Decode;
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use substrate_common::OCWMessage;
use subxt::sp_runtime::AccountId32;
use tofn::sdk::api::Signature;
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
) -> Result<Status, ()> {
    let data = OCWMessage::decode(&mut encoded_data.as_ref()).unwrap();

    for message in data {
        // todo: temporary hack, replace with correct data
        let info = SignInit::temporary_data(message.clone());
        let gg20_service = Gg20Service::new(state, kv_manager);

        // set up context for signing protocol execution
        let sign_context = gg20_service.get_sign_context(info.clone()).await.unwrap();

        // subscribe to all other participating parties. Listener waits for other subscribers.
        let (rx_ready, listener) = Listener::new();
        state
            .listeners
            .lock()
            .unwrap()
            .insert(sign_context.sign_init.party_uid.to_string(), listener);
        let channels = {
            let stream_in = subscribe_to_them(&sign_context).await.unwrap();
            let broadcast_out = rx_ready.await.unwrap().unwrap();
            Channels(broadcast_out, stream_in)
        };

        let result = gg20_service.execute_sign(&sign_context, channels).await.unwrap();
        use k256::{ecdsa::VerifyingKey, elliptic_curve::sec1::FromEncodedPoint};
        let pubkey_bytes = sign_context.party_info.common.encoded_pubkey();
        let ep = k256::EncodedPoint::from_bytes(pubkey_bytes).unwrap();
        let pubkey = VerifyingKey::from_encoded_point(&ep).unwrap();

        let rec_sig0 =
            recoverable::Signature::new(&result, recoverable::Id::new(0).unwrap()).unwrap();
        let msg: &[u8] = message.sig_request.sig_hash.as_ref();
        let recovered_key =
            rec_sig0.recover_verify_key_from_digest_bytes(msg.try_into().unwrap()).unwrap();
        let rec_sig = if recovered_key == pubkey {
            rec_sig0
        } else {
            recoverable::Signature::new(&result, recoverable::Id::new(1).unwrap()).unwrap()
        };
        let key = message.sig_request.sig_hash.as_slice().try_into().unwrap();

        gg20_service.handle_result(&rec_sig, key, signatures);
    }

    Ok(Status::Ok)
}

/// Other nodes in the party call this method to subscribe to this node's broadcasts.
/// The SigningProtocol begins when all nodes in the party have called this method on this node.
#[instrument]
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
        let mut listeners = state.listeners.lock().unwrap();
        let listener = listeners.get_mut(&msg.party_id).ok_or(SubscribeErr::NoListener("no"))?;
        let rx_outcome = listener.subscribe(&msg)?;

        // If this is the last subscriber, remove the listener from state
        match rx_outcome {
            Receiver::Receiver(rx) => rx,
            Receiver::FinalReceiver(rx) => {
                // all subscribed, wake up the waiting listener in new_party
                let listener = listeners.remove(&msg.party_id).unwrap();
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
    let sig = signatures.get(&msg.message).to_vec();
    status::Accepted(Some(base64::encode(sig)))
}

#[get("/drain")]
pub async fn drain(signatures: &State<SignatureState>) -> Result<Status, ()> {
    signatures.drain();
    Ok(Status::Ok)
}
