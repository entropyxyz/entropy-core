use std::{net::SocketAddrV4, str::FromStr, time::Duration};

use entropy_protocol::{
    execute_protocol::{execute_dkg, Channels},
    KeyParams, ValidatorInfo,
};
use entropy_shared::{KeyVisibility, SETUP_TIMEOUT_SECONDS};
use parity_scale_codec::Encode;
use sp_core::crypto::AccountId32;
use subxt::{
    backend::legacy::LegacyRpcMethods,
    ext::sp_core::{sr25519, Bytes},
    tx::PairSigner,
    utils::AccountId32 as SubxtAccountId32,
    OnlineClient,
};
use synedrion::KeyShare;
use tokio::time::timeout;
use x25519_dalek::PublicKey;

use crate::{
    chain_api::{entropy, EntropyConfig},
    signing_client::{protocol_transport::open_protocol_connections, Listener, ListenerState},
    user::{api::UserRegistrationInfo, errors::UserErr},
    validation::{derive_static_secret, SignedMessage},
};
/// complete the dkg process for a new user
pub async fn do_dkg(
    validators_info: &Vec<entropy_shared::ValidatorInfo>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    state: &ListenerState,
    sig_request_account: AccountId32,
    my_subgroup: &u8,
    key_visibility: KeyVisibility,
    subxt_signer: &subxt_signer::sr25519::Keypair,
) -> Result<KeyShare<KeyParams>, UserErr> {
    let session_uid = sig_request_account.to_string();
    let account_id = SubxtAccountId32(*signer.account_id().clone().as_ref());
    let mut converted_validator_info = vec![];
    let mut tss_accounts = vec![];
    for validator_info in validators_info {
        let address_slice: &[u8; 32] = &validator_info
            .tss_account
            .clone()
            .try_into()
            .map_err(|_| UserErr::AddressConversionError("Invalid Length".to_string()))?;
        let tss_account = SubxtAccountId32(*address_slice);
        let validator_info = ValidatorInfo {
            x25519_public_key: validator_info.x25519_public_key,
            ip_address: SocketAddrV4::from_str(std::str::from_utf8(&validator_info.ip_address)?)?,
            tss_account: tss_account.clone(),
        };
        converted_validator_info.push(validator_info);
        tss_accounts.push(tss_account);
    }

    // If key key visibility is private, include them in the list of connecting parties and pass
    // their ID to the listener
    let user_details_option =
        if let KeyVisibility::Private(users_x25519_public_key) = key_visibility {
            let account_id_arr: [u8; 32] = *sig_request_account.as_ref();
            let user_account_id = SubxtAccountId32(account_id_arr);
            tss_accounts.push(user_account_id.clone());
            Some((user_account_id, users_x25519_public_key))
        } else {
            None
        };

    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, rx_from_others, listener) =
        Listener::new(converted_validator_info.clone(), &account_id, user_details_option);
    state
	.listeners
	.lock()
	.map_err(|_| UserErr::SessionError("Error getting lock".to_string()))?
	// TODO: using signature ID as session ID. Correct?
	.insert(session_uid.clone(), listener);

    let x25519_secret_key = derive_static_secret(signer.signer());
    open_protocol_connections(
        &converted_validator_info,
        &session_uid,
        subxt_signer,
        state,
        &x25519_secret_key,
    )
    .await?;
    let channels = {
        let ready = timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await?;
        let broadcast_out = ready??;
        Channels(broadcast_out, rx_from_others)
    };

    let result = execute_dkg(channels, subxt_signer, tss_accounts, my_subgroup).await?;
    Ok(result)
}

/// Send's user key share to other members of signing subgroup
pub async fn send_key(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    stash_address: &SubxtAccountId32,
    addresses_in_subgroup: &mut Vec<SubxtAccountId32>,
    user_registration_info: UserRegistrationInfo,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
) -> Result<(), UserErr> {
    addresses_in_subgroup.remove(
        addresses_in_subgroup
            .iter()
            .position(|address| *address == *stash_address)
            .ok_or_else(|| UserErr::OptionUnwrapError("Validator not in subgroup"))?,
    );
    let block_hash = rpc.chain_get_block_hash(None).await?.ok_or_else(|| UserErr::OptionUnwrapError("Errir getting block hash"))?;

    for validator in addresses_in_subgroup {
        let server_info_query = entropy::storage().staking_extension().threshold_servers(validator);
        let server_info = api
            .storage()
            .at(block_hash)
            .fetch(&server_info_query)
            .await?
            .ok_or_else(|| UserErr::OptionUnwrapError("Server Info Fetch Error"))?;
        let signed_message = SignedMessage::new(
            signer.signer(),
            &Bytes(serde_json::to_vec(&user_registration_info.clone())?),
            &PublicKey::from(server_info.x25519_public_key),
        )?;
        // encrypt and sign info
        let url = format!("http://{}/user/receive_key", String::from_utf8(server_info.endpoint)?);
        let client = reqwest::Client::new();

        let _ = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&signed_message)?)
            .send()
            .await?;
    }
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
