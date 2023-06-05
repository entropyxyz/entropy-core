use std::{convert::TryInto, str};

use blake2::{Blake2s256, Digest};
use entropy_shared::{OCWMessage, PRUNE_BLOCK};
use kvdb::kv_manager::KvManager;
use parity_scale_codec::{Decode, Encode};
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use sp_core::crypto::Ss58Codec;
use subxt::OnlineClient;
use tracing::instrument;

use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    get_signer,
    helpers::signing::{create_unique_tx_id, SignatureState},
    signing_client::{
        subscribe::{Listener, Receiver},
        SignerState, SigningErr, SubscribeErr, SubscribeMessage,
    },
    validation::SignedMessage,
    Configuration,
};

const SUBSCRIBE_TIMEOUT_SECONDS: u64 = 10;
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
    let api = get_api(&config.endpoint).await?;
    if data.messages.is_empty() {
        prune_old_tx_from_kvdb(&api, kv, data.block_number).await?;
        return Ok(Status::NoContent);
    }
    validate_new_party(&data, &api).await?;
    for message in data.messages {
        let address_slice: &[u8; 32] = &message
            .account
            .clone()
            .try_into()
            .map_err(|_| SigningErr::AddressConversionError("Invalid Length".to_string()))?;
        let user = sp_core::crypto::AccountId32::new(*address_slice);

        // TODO: get proper ss58 number when chosen
        let address = user.to_ss58check();

        let tx_id = create_unique_tx_id(&address, &hex::encode(&message.sig_request.sig_hash));
        let reservation = kv.kv().reserve_key(tx_id).await?;
        let value = serde_json::to_string(&message)?;
        kv.kv().put(reservation, value.into()).await?;
    }
    prune_old_tx_from_kvdb(&api, kv, data.block_number).await?;
    Ok(Status::Ok)
}

/// Other nodes in the party call this method to subscribe to this node's broadcasts.
/// The SigningProtocol begins when all nodes in the party have called this method on this node.
#[post("/subscribe_to_me", data = "<msg>")]
pub async fn subscribe_to_me(
    msg: Json<SignedMessage>,
    end: Shutdown,
    state: &State<SignerState>,
    kv: &State<KvManager>,
) -> Result<EventStream![], SubscribeErr> {
    let signed_msg: SignedMessage = msg.into_inner();
    if !signed_msg.verify() {
        return Err(SubscribeErr::InvalidSignature("Invalid signature."));
    }
    let signer = get_signer(kv).await.map_err(|e| SubscribeErr::UserError(e.to_string()))?;
    // TODO: handle ss58 check when number chosen
    let _signing_address = signed_msg.account_id().to_ss58check();
    // TODO: validate signing address against current message signers
    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| SubscribeErr::Decryption(e.to_string()))?;
    let msg: SubscribeMessage = serde_json::from_slice(&decrypted_message)?;

    info!("got subscribe, with message: {msg:?}");

    let party_id = msg.party_id().map_err(SubscribeErr::InvalidPartyId)?;

    if !state.contains_listener(&msg.session_id)? {
        // Chain node hasn't yet informed this node of the party. Wait for a timeout and procede (or
        // fail below)
        tokio::time::sleep(std::time::Duration::from_secs(SUBSCRIBE_TIMEOUT_SECONDS)).await;
    };

    let rx = {
        let mut listeners = state.listeners.lock().expect("lock shared data");
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

    Ok(Listener::create_event_stream(rx, end))
}

/// Validates new party endpoint
/// Checks the chain for validity of data and block number of data matches current block
pub async fn validate_new_party(
    chain_data: &OCWMessage,
    api: &OnlineClient<EntropyConfig>,
) -> Result<(), SigningErr> {
    let latest_block_number = api
        .rpc()
        .block(None)
        .await?
        .ok_or_else(|| SigningErr::OptionUnwrapError("Failed to get block number"))?
        .block
        .header
        .number;

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

/// Prunes old tx from DB
pub async fn prune_old_tx_from_kvdb(
    api: &OnlineClient<EntropyConfig>,
    kv: &State<KvManager>,
    block_number: u32,
) -> Result<(), SigningErr> {
    if block_number < PRUNE_BLOCK {
        return Ok(());
    }
    let chain_data_query =
        entropy::storage().relayer().messages(block_number.saturating_sub(PRUNE_BLOCK));
    let chain_data = api.storage().fetch(&chain_data_query, None).await?;

    if chain_data.is_none() {
        return Ok(());
    }

    for message in
        chain_data.ok_or_else(|| SigningErr::OptionUnwrapError("Failed to get verifying data"))?
    {
        let address_slice: &[u8; 32] = &message
            .account
            .clone()
            .try_into()
            .map_err(|_| SigningErr::AddressConversionError("Invalid Length".to_string()))?;
        let user = sp_core::crypto::AccountId32::new(*address_slice);
        // TODO: get proper ss58 number when chosen
        let address = user.to_ss58check();
        let tx_id = create_unique_tx_id(&address, &hex::encode(&message.sig_request.sig_hash));
        let exists_result = kv.kv().exists(&tx_id).await?;
        if exists_result {
            kv.kv().delete(&tx_id).await?;
        }
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
) -> Option<status::Accepted<String>> {
    let sig = match signatures.get(&hex::decode(&msg.message).unwrap()) {
        Some(sig) => sig,
        None => return None,
    };
    Some(status::Accepted(Some(base64::encode(sig.to_rsv_bytes()))))
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
