use std::{convert::TryInto, str};

use blake2::{Blake2s256, Digest};
use entropy_shared::OCWMessage;
use kvdb::kv_manager::KvManager;
use parity_scale_codec::{Decode, Encode};
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use sp_core::crypto::Ss58Codec;
use subxt::OnlineClient;
use tracing::instrument;

use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    helpers::signing::{create_unique_tx_id, SignatureState},
    signing_client::{
        subscribe::{Listener, Receiver},
        SignerState, SigningErr, SubscribeErr, SubscribeMessage,
    },
    Configuration,
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
    config: &State<Configuration>,
) -> Result<Status, SigningErr> {
    let data = OCWMessage::decode(&mut encoded_data.as_ref())?;
    if data.messages.is_empty() {
        return Ok(Status::NoContent);
    }
    let api = get_api(&config.endpoint).await?;
    validate_new_party(&data, &api).await?;
    for message in data.messages {
        let address_slice: &[u8; 32] = &message
            .account
            .clone()
            .try_into()
            .map_err(|_| SigningErr::AddressConversionError("Invalid Length".to_string()))?;
        let user = sp_core::crypto::AccountId32::new(*address_slice);
        let address = user.to_ss58check();

        let tx_id = create_unique_tx_id(&address, &hex::encode(&message.sig_request.sig_hash));
        let reservation = kv.kv().reserve_key(tx_id).await?;
        let value = serde_json::to_string(&message)?;
        kv.kv().put(reservation, value.into()).await?;
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

/// Validates new party endpoint
/// Checks the chain for validity of data and block number of data matches current block
pub async fn validate_new_party(
    chain_data: &OCWMessage,
    api: &OnlineClient<EntropyConfig>,
) -> Result<(), SigningErr> {
    let latest_block_number = api.rpc().block(None).await.unwrap().unwrap().block.header.number;
    // we subtract 1 as the message info is coming from the previous block
    if latest_block_number.saturating_sub(1) != chain_data.block_number {
        return Err(SigningErr::StaleData);
    }

    let mut hasher_chain_data = Blake2s256::new();
    hasher_chain_data.update(chain_data.messages.encode());
    let chain_data_hash = hasher_chain_data.finalize();
    let mut hasher_verifying_data = Blake2s256::new();

    let verifying_data_query = entropy::storage().relayer().messages(chain_data.block_number);
    let verifying_data = api
        .storage()
        .fetch(&verifying_data_query, None)
        .await?
        .ok_or_else(|| SigningErr::OptionUnwrapError("Failed to get verifying data"))?;

    hasher_verifying_data.update(verifying_data.encode());

    let verifying_data_hash = hasher_verifying_data.finalize();

    if verifying_data_hash != chain_data_hash {
        return Err(SigningErr::InvalidData);
    }
    Ok(())
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
