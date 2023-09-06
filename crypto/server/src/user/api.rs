use std::{net::SocketAddrV4, str::FromStr, sync::Arc};

use axum::{
    body::{Bytes, StreamBody},
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use bip39::{Language, Mnemonic};
use blake2::{Blake2s256, Digest};
use entropy_constraints::{
    Architecture, Error as ConstraintsError, Evaluate, Evm, GetReceiver, GetSender, Parse,
};
use entropy_shared::{
    types::{Acl, AclKind, Arch, Constraints, KeyVisibility},
    OcwMessage, X25519PublicKey, SIGNING_PARTY_SIZE,
};
use futures::{
    channel::mpsc,
    future::{join_all, FutureExt},
    Stream,
};
use kvdb::kv_manager::{
    error::{InnerKvError, KvError},
    helpers::serialize as key_serialize,
    value::PartyInfo,
    KvManager,
};
use log::info;
use num::{bigint::BigInt, FromPrimitive, Num, ToPrimitive};
use parity_scale_codec::{Decode, DecodeAll, Encode};
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
        substrate::{
            get_constraints, get_key_visibility, get_subgroup, return_all_addresses_of_subgroup,
        },
        user::{do_dkg, send_key},
        validator::get_signer,
    },
    signing_client::{ListenerState, ProtocolErr},
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

/// Type for validators to send user key's back and forth
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct UserRegistrationInfo {
    /// Signing request key (also kvdb key)
    pub key: String,
    /// User threshold signing key
    pub value: Vec<u8>,
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

    let users_x25519_public_key = signed_msg.sender(); //.as_bytes();

    let api = get_api(&app_state.configuration.endpoint).await?;
    let key_visibility = get_key_visibility(&api, &second_signing_address_conversion).await?;

    if key_visibility != KeyVisibility::Public && !signed_msg.verify() {
        return Err(UserErr::InvalidSignature("Invalid signature."));
    }
    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| UserErr::Decryption(e.to_string()))?;

    let user_tx_req: UserTransactionRequest = serde_json::from_slice(&decrypted_message)?;
    let parsed_tx =
        <Evm as Architecture>::TransactionRequest::parse(user_tx_req.transaction_request.clone())?;
    let sig_hash = hex::encode(parsed_tx.sighash());
    let subgroup_signers = get_current_subgroup_signers(&api, &sig_hash).await?;
    check_signing_group(subgroup_signers, &user_tx_req.validators_info, signer.account_id())?;
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
                    &app_state,
                    tx_id,
                    signing_address_converted,
                    users_x25519_public_key.as_bytes(),
                    key_visibility,
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

/// HTTP POST endpoint called by the off-chain worker (propagation pallet) during user registration.
/// The http request takes a parity scale encoded [OcwMessage] which tells us which validators are
/// in the registration group and will perform a DKG.
pub async fn new_user(
    State(app_state): State<AppState>,
    encoded_data: Bytes,
) -> Result<StatusCode, UserErr> {
    let data = OcwMessage::decode(&mut encoded_data.as_ref())?;
    if data.registering_users.is_empty() {
        return Ok(StatusCode::NO_CONTENT);
    }

    let api = get_api(&app_state.configuration.endpoint).await?;
    let signer = get_signer(&app_state.kv_store).await?;

    check_in_registration_group(&data.validators_info, signer.account_id())?;
    validate_new_user(&data, &api, &app_state.kv_store).await?;

    let (subgroup, stash_address) = get_subgroup(&api, &signer).await?;
    let my_subgroup = subgroup.ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
    let mut addresses_in_subgroup = return_all_addresses_of_subgroup(&api, my_subgroup).await?;

    for registering_user in data.registering_users {
        let address_slice: &[u8; 32] = &registering_user
            .sig_request_account
            .clone()
            .try_into()
            .map_err(|_| UserErr::AddressConversionError("Invalid Length".to_string()))?;
        let sig_request_address = AccountId32::new(*address_slice);

        let key_share = do_dkg(
            &data.validators_info,
            &signer,
            &app_state.listener_state,
            sig_request_address.to_string(),
            &my_subgroup,
        )
        .await?;
        let serialized_key_share = key_serialize(&key_share)
            .map_err(|_| UserErr::KvSerialize("Kv Serialize Error".to_string()))?;

        let reservation =
            app_state.kv_store.kv().reserve_key(sig_request_address.to_string()).await?;
        app_state.kv_store.kv().put(reservation, serialized_key_share.clone()).await?;

        let user_registration_info = UserRegistrationInfo {
            key: sig_request_address.to_string(),
            value: serialized_key_share,
        };
        send_key(&api, &stash_address, &mut addresses_in_subgroup, user_registration_info, &signer)
            .await?;
        // TODO: Error handling really complex needs to be thought about.
        confirm_registered(&api, sig_request_address.into(), my_subgroup, &signer).await?;
    }
    Ok(StatusCode::OK)
}

/// HTTP POST endpoint to recieve a keyshare from another threshold server in the same
/// signing subgroup. Takes a [UserRegistrationInfo] wrapped in a [SignedMessage].
pub async fn receive_key(
    State(app_state): State<AppState>,
    Json(signed_msg): Json<SignedMessage>,
) -> Result<StatusCode, UserErr> {
    let signing_address = signed_msg.account_id();
    if !signed_msg.verify() {
        return Err(UserErr::InvalidSignature("Invalid signature."));
    }
    let signer = get_signer(&app_state.kv_store).await?;
    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| UserErr::Decryption(e.to_string()))?;

    let user_registration_info: UserRegistrationInfo = serde_json::from_slice(&decrypted_message)?;
    let api = get_api(&app_state.configuration.endpoint).await?;
    let my_subgroup = get_subgroup(&api, &signer)
        .await?
        .0
        .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
    let addresses_in_subgroup = return_all_addresses_of_subgroup(&api, my_subgroup).await?;

    let signing_address_converted = SubxtAccountId32::from_str(&signing_address.to_ss58check())
        .map_err(|_| UserErr::StringError("Account Conversion"))?;

    // check message is from the person sending the message (get stash key from threshold key)
    let stash_address_query =
        entropy::storage().staking_extension().threshold_to_stash(signing_address_converted);
    let stash_address = api
        .storage()
        .at_latest()
        .await?
        .fetch(&stash_address_query)
        .await?
        .ok_or_else(|| UserErr::SubgroupError("Stash Fetch Error"))?;
    if !addresses_in_subgroup.contains(&stash_address) {
        return Err(UserErr::NotInSubgroup);
    }

    let exists_result =
        app_state.kv_store.kv().exists(&user_registration_info.key.to_string()).await?;
    if exists_result {
        return Err(UserErr::AlreadyRegistered);
    }
    let reservation =
        app_state.kv_store.kv().reserve_key(user_registration_info.key.to_string()).await?;
    app_state.kv_store.kv().put(reservation, user_registration_info.value).await?;
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
    validators_info: &Vec<ValidatorInfo>,
    my_id: &<EntropyConfig as Config>::AccountId,
) -> Result<(), UserErr> {
    // Check that validators given by the user match those from get_current_subgroup_signers
    for validator in validators_info {
        if !subgroup_signers.contains(&validator.tss_account.clone().into()) {
            return Err(UserErr::InvalidSigner("Invalid Signer in Signing group"));
        }
    }
    // Finally, check that we ourselves are in the signing group
    if !subgroup_signers.contains(my_id) {
        return Err(UserErr::InvalidSigner(
            "Signing group is valid, but this threshold server is not in the group",
        ));
    }
    Ok(())
}

/// Validates new user endpoint
/// Checks the chain for validity of data and block number of data matches current block
pub async fn validate_new_user(
    chain_data: &OcwMessage,
    api: &OnlineClient<EntropyConfig>,
    kv_manager: &KvManager,
) -> Result<(), UserErr> {
    let last_block_number_recorded = kv_manager.kv().get("LATEST_BLOCK_NUMBER").await?;
    if u32::from_be_bytes(
        last_block_number_recorded
            .try_into()
            .map_err(|_| UserErr::Conversion("Account Conversion"))?,
    ) >= chain_data.block_number
    {
        // change error
        return Err(UserErr::RepeatedData);
    }
    let latest_block_number = api
        .rpc()
        .block(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Failed to get block number"))?
        .block
        .header
        .number;

    // we subtract 1 as the message info is coming from the previous block
    if latest_block_number.saturating_sub(1) != chain_data.block_number {
        return Err(UserErr::StaleData);
    }

    let mut hasher_chain_data = Blake2s256::new();
    hasher_chain_data.update(chain_data.registering_users.encode());
    let chain_data_hash = hasher_chain_data.finalize();
    let mut hasher_verifying_data = Blake2s256::new();

    let verifying_data_query = entropy::storage().relayer().dkg(chain_data.block_number);
    let verifying_data = api
        .storage()
        .at_latest()
        .await?
        .fetch(&verifying_data_query)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Failed to get verifying data"))?;

    hasher_verifying_data.update(verifying_data.encode());

    let verifying_data_hash = hasher_verifying_data.finalize();
    if verifying_data_hash != chain_data_hash {
        return Err(UserErr::InvalidData);
    }
    kv_manager.kv().delete("LATEST_BLOCK_NUMBER").await?;
    let reservation = kv_manager.kv().reserve_key("LATEST_BLOCK_NUMBER".to_string()).await?;
    kv_manager.kv().put(reservation, chain_data.block_number.to_be_bytes().to_vec()).await?;
    Ok(())
}

/// Checks if a validator is in the current selected registration committee
pub fn check_in_registration_group(
    validators_info: &[entropy_shared::ValidatorInfo],
    validator_address: &SubxtAccountId32,
) -> Result<(), UserErr> {
    let is_proper_signer = validators_info
        .iter()
        .any(|validator_info| validator_info.tss_account == validator_address.encode());
    if !is_proper_signer {
        return Err(UserErr::InvalidSigner("Invalid Signer in Signing group"));
    }
    Ok(())
}
