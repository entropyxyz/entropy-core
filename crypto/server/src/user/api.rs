use std::{net::SocketAddrV4, str::FromStr, sync::Arc};

use axum::{
    body::StreamBody,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use bip39::{Language, Mnemonic};
use entropy_constraints::{
    Architecture, Error as ConstraintsError, Evaluate, Evm, GetReceiver, GetSender, Parse,
};
use entropy_shared::{
    types::{Acl, AclKind, Arch, Constraints, KeyVisibility},
    X25519PublicKey, SIGNING_PARTY_SIZE,
};
use futures::{
    channel::mpsc,
    future::{join_all, FutureExt},
    Stream,
};
use kvdb::kv_manager::{
    error::{InnerKvError, KvError},
    value::PartyInfo,
    KvManager,
};
use log::info;
use num::{bigint::BigInt, FromPrimitive, Num, ToPrimitive};
use parity_scale_codec::DecodeAll;
use serde::{Deserialize, Serialize};
use sp_core::crypto::AccountId32;
use subxt::{
    ext::sp_core::{crypto::Ss58Codec, sr25519, Pair},
    tx::PairSigner,
    utils::AccountId32 as SubxtAccountId32,
    Config, OnlineClient,
};
use tracing::instrument;
use zeroize::Zeroize;

use super::{ParsedUserInputPartyInfo, UserErr, UserInputPartyInfo};
use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    helpers::{
        signing::{create_unique_tx_id, do_signing, SignatureState},
        substrate::{get_constraints, get_key_visibility, get_subgroup},
        validator::get_signer,
    },
    signing_client::{SignerState, SigningErr},
    validation::SignedMessage,
    AppState, Configuration,
};

/// Information from the validators in signing party
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorInfo {
    pub x25519_public_key: X25519PublicKey,
    pub ip_address: SocketAddrV4,
    pub tss_account: AccountId32,
}

/// Represents an unparsed, transaction request coming from the client.
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct UserTransactionRequest {
    /// 'eth', etc.
    pub arch: String,
    /// ETH: RLP encoded transaction request
    pub transaction_request: String,
    /// Information from the validators in signing party
    pub validators_info: Vec<ValidatorInfo>,
}

/// Called by a user to initiate the signing process for a message
///
/// Takes an encrypted [SignedMessage] containing a JSON serialized [UserTransactionRequest]
pub async fn sign_tx(
    State(app_state): State<AppState>,
    Json(signed_msg): Json<SignedMessage>,
) -> Result<(StatusCode, StreamBody<impl Stream<Item = Result<String, serde_json::Error>>>), UserErr>
{
    let signer = get_signer(&app_state.kv_store).await?;
    let signing_address = signed_msg.account_id().to_ss58check();

    let signing_address_converted =
        AccountId32::from_str(&signing_address).map_err(UserErr::StringError)?;
    // TODO go back over to simplify accountID type
    let second_signing_address_conversion = SubxtAccountId32::from_str(&signing_address)
        .map_err(|_| UserErr::StringError("Account Conversion"))?;

    let api = get_api(&app_state.configuration.endpoint).await?;
    let key_visibility = get_key_visibility(&api, &second_signing_address_conversion).await?;

    if key_visibility != KeyVisibility::Public {
        if !signed_msg.verify() {
            return Err(UserErr::InvalidSignature("Invalid signature."));
        }
    }
    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| UserErr::Decryption(e.to_string()))?;

    let user_tx_req: UserTransactionRequest = serde_json::from_slice(&decrypted_message)?;
    let parsed_tx =
        <Evm as Architecture>::TransactionRequest::parse(user_tx_req.transaction_request.clone())?;
    let sig_hash = hex::encode(parsed_tx.sighash());
    let subgroup_signers = get_current_subgroup_signers(&api, &sig_hash).await?;
    check_signing_group(subgroup_signers, signer.account_id())?;
    let tx_id = create_unique_tx_id(&signing_address, &sig_hash);
    match user_tx_req.arch.as_str() {
        "evm" => {
            let evm_acl = get_constraints(&api, &second_signing_address_conversion)
                .await?
                .evm_acl
                .ok_or(UserErr::Parse("No constraints found for this account."))?;

            evm_acl.eval(parsed_tx)?;

            let (mut response_tx, response_rx) = mpsc::channel(1);

            // Do the signing protocol in another task, so we can already respond
            tokio::spawn(async move {
                let signing_protocol_output = do_signing(
                    user_tx_req,
                    sig_hash,
                    &app_state.signer_state,
                    &app_state.kv_store,
                    &app_state.signature_state,
                    tx_id,
                    signing_address_converted,
                )
                .await
                .map(|signature| base64::encode(signature.to_rsv_bytes()))
                .map_err(|error| error.to_string());

                // This response chunk is sent later with the result of the signing protocol
                if response_tx.try_send(serde_json::to_string(&signing_protocol_output)).is_err() {
                    tracing::warn!("Cannot send signing protocol output - connection is closed")
                };
            });

            // This indicates that the signing protocol is starting successfully
            Ok((StatusCode::OK, StreamBody::new(response_rx)))
        },
        _ => Err(UserErr::Parse("Unknown \"arch\". Must be one of: [\"evm\"]")),
    }
}

/// HTTP POST endoint called by the user when registering.
///
/// This adds a new Keyshare to this node's set of known Keyshares and stores the it in the [kvdb].
///
/// The http request takes a [SignedMessage] containing a bincode-encoded
/// [KeyShare](synedrion::KeyShare).
pub async fn new_user(
    State(app_state): State<AppState>,
    Json(signed_msg): Json<SignedMessage>,
) -> Result<StatusCode, UserErr> {
    let api = get_api(&app_state.configuration.endpoint).await?;
    // Verifies the message contains a valid sr25519 signature from the sender.
    if !signed_msg.verify() {
        return Err(UserErr::InvalidSignature("Invalid signature."));
    }
    let signer = get_signer(&app_state.kv_store).await?;
    // Checks if the user has registered onchain first.
    let key = signed_msg.account_id();
    let signing_address_conversion = SubxtAccountId32::from_str(&key.to_ss58check())
        .map_err(|_| UserErr::StringError("Account Conversion"))?;

    let is_swapping = register_info(&api, &signing_address_conversion).await?;

    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| UserErr::Decryption(e.to_string()))?;
    // store new user data in kvdb or deletes and replaces it if swapping
    let subgroup = get_subgroup(&api, &signer)
        .await?
        .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
    if is_swapping {
        app_state.kv_store.kv().delete(&key.to_string()).await?;
    }
    let reservation = app_state.kv_store.kv().reserve_key(key.to_string()).await?;
    app_state.kv_store.kv().put(reservation, decrypted_message).await?;
    // TODO: Error handling really complex needs to be thought about.
    confirm_registered(&api, key.into(), subgroup, &signer).await?;
    Ok(StatusCode::OK)
}
/// Returns wether an account is registering or swapping. If it is not, it returns error
pub async fn register_info(
    api: &OnlineClient<EntropyConfig>,
    who: &<EntropyConfig as Config>::AccountId,
) -> Result<bool, UserErr> {
    let registering_info_query = entropy::storage().relayer().registering(who);
    let register_info = api
        .storage()
        .at_latest()
        .await?
        .fetch(&registering_info_query)
        .await?
        .ok_or_else(|| UserErr::NotRegistering("Register Onchain first"))?;
    if !register_info.is_swapping && !register_info.is_registering {
        return Err(UserErr::NotRegistering("Declare swap Onchain first"));
    }

    Ok(register_info.is_swapping)
}

/// Confirms that a address has finished registering on chain.
pub async fn confirm_registered(
    api: &OnlineClient<EntropyConfig>,
    who: SubxtAccountId32,
    subgroup: u8,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
) -> Result<(), subxt::error::Error> {
    // TODO error handling + return error
    // TODO fire and forget, or wait for in block maybe Ddos error
    // TODO: Understand this better, potentially use sign_and_submit_default
    // or other method under sign_and_*
    let registration_tx = entropy::tx().relayer().confirm_register(who, subgroup);
    let _ = api
        .tx()
        .sign_and_submit_then_watch_default(&registration_tx, signer)
        .await?
        .wait_for_in_block()
        .await?
        .wait_for_success()
        .await?;
    Ok(())
}
/// Gets the current signing committee
/// The signing committee is composed as the validators at the index into each subgroup
/// Where the index is computed as the user's sighash as an integer modulo the number of subgroups
pub async fn get_current_subgroup_signers(
    api: &OnlineClient<EntropyConfig>,
    sig_hash: &str,
) -> Result<Vec<SubxtAccountId32>, UserErr> {
    let mut subgroup_signers = vec![];
    let number = Arc::new(BigInt::from_str_radix(sig_hash, 16)?);
    let futures = (0..SIGNING_PARTY_SIZE)
        .map(|i| {
            let owned_number = Arc::clone(&number);
            async move {
                let subgroup_info_query =
                    entropy::storage().staking_extension().signing_groups(i as u8);
                let subgroup_info = api
                    .storage()
                    .at_latest()
                    .await?
                    .fetch(&subgroup_info_query)
                    .await?
                    .ok_or(UserErr::SubgroupError("Subgroup Fetch Error"))?;

                let index_of_signer_big = &*owned_number % subgroup_info.len();
                let index_of_signer =
                    index_of_signer_big.to_usize().ok_or(UserErr::Usize("Usize error"))?;

                let threshold_address_query = entropy::storage()
                    .staking_extension()
                    .threshold_servers(subgroup_info[index_of_signer].clone());
                let threshold_address = api
                    .storage()
                    .at_latest()
                    .await?
                    .fetch(&threshold_address_query)
                    .await?
                    .ok_or(UserErr::SubgroupError("Stash Fetch Error"))?
                    .tss_account;

                Ok::<_, UserErr>(threshold_address)
            }
        })
        .collect::<Vec<_>>();
    let results = join_all(futures).await;
    for result in results.into_iter() {
        subgroup_signers.push(result?);
    }
    Ok(subgroup_signers)
}
/// Checks if a validator is in the current selected signing committee
pub fn check_signing_group(
    subgroup_signers: Vec<SubxtAccountId32>,
    validator_address: &<EntropyConfig as Config>::AccountId,
) -> Result<(), UserErr> {
    // TODO Check that subgroup_signers matches UserTransactionRequest.validators_info
    let is_proper_signer = subgroup_signers.contains(validator_address);
    if !is_proper_signer {
        return Err(UserErr::InvalidSigner("Invalid Signer in Signing group"));
    }
    Ok(())
}
