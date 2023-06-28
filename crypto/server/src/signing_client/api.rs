use std::{convert::TryInto, str};

use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::sse::{Event, Sse},
    Json,
};
use entropy_shared::{PRUNE_BLOCK};
use futures::stream::Stream;
use kvdb::kv_manager::{KvManager, PartyId};
use parity_scale_codec::Decode;
use sp_core::crypto::Ss58Codec;
use subxt::OnlineClient;
use tracing::instrument;

use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    get_signer,
    helpers::signing::create_unique_tx_id,
    signing_client::{
        subscribe::{Listener, Receiver},
        SigningErr, SubscribeErr, SubscribeMessage,
    },
    validation::SignedMessage,
    AppState,
};

const SUBSCRIBE_TIMEOUT_SECONDS: u64 = 10;

// /// Other nodes in the party call this method to subscribe to this node's broadcasts.
// /// The SigningProtocol begins when all nodes in the party have called this method on this node.
#[axum_macros::debug_handler]
pub async fn subscribe_to_me(
    State(app_state): State<AppState>,
    signed_msg: Json<SignedMessage>,
) -> Result<Sse<impl Stream<Item = Result<Event, SubscribeErr>>>, SubscribeErr> {
    if !signed_msg.verify() {
        return Err(SubscribeErr::InvalidSignature("Invalid signature."));
    }
    let signer = get_signer(&app_state.kv_store)
        .await
        .map_err(|e| SubscribeErr::UserError(e.to_string()))?;

    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| SubscribeErr::Decryption(e.to_string()))?;
    let msg: SubscribeMessage = serde_json::from_slice(&decrypted_message)?;

    tracing::info!("got subscribe, with message: {msg:?}");

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

    let rx = {
        let mut listeners = app_state
            .signer_state
            .listeners
            .lock()
            .map_err(|e| SubscribeErr::LockError(e.to_string()))?;
        let listener =
            listeners.get_mut(&msg.session_id).ok_or(SubscribeErr::NoListener("no listener"))?;
        let rx_outcome = listener.subscribe(party_id)?;

        // If this is the last subscriber, remove the listener from state
        match rx_outcome {
            Receiver::Receiver(rx) => rx,
            Receiver::FinalReceiver(rx) => {
                // all subscribed, wake up the waiting listener in new_party
                let listener = listeners
                    .remove(&msg.session_id)
                    .ok_or(SubscribeErr::NoListener("listener remove"))?;
                let (tx, broadcaster) = listener.into_broadcaster();
                let _ = tx.send(Ok(broadcaster));
                rx
            },
        }
    };

    Ok(Listener::create_event_stream(rx))
}

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
pub async fn get_signature(
    State(app_state): State<AppState>,
    Json(msg): Json<Message>,
) -> (StatusCode, String) {
    let sig = match app_state.signature_state.get(&hex::decode(msg.message).unwrap()) {
        Some(sig) => sig,
        None => return (StatusCode::NO_CONTENT, "".to_string()),
    };
    (StatusCode::ACCEPTED, base64::encode(sig.to_rsv_bytes()))
}

/// Drains all signatures from the state
/// Client calls this after they receive the signature at `/signature`
///
/// This will be removed when after client participates in signing
pub async fn drain(State(app_state): State<AppState>) -> Result<StatusCode, ()> {
    app_state.signature_state.drain();
    Ok(StatusCode::OK)
}
