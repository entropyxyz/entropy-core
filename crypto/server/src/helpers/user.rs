use std::{net::SocketAddrV4, str::FromStr, time::Duration};

use entropy_shared::{KeyVisibility, X25519PublicKey, SETUP_TIMEOUT_SECONDS};
use kvdb::kv_manager::KeyParams;
use sp_core::crypto::AccountId32;
use subxt::{
    ext::sp_core::{sr25519, Bytes},
    tx::PairSigner,
    utils::AccountId32 as subxtAccountId32,
    OnlineClient,
};
use synedrion::KeyShare;
use tokio::time::timeout;
use x25519_dalek::PublicKey;

use crate::{
    chain_api::{entropy, EntropyConfig},
    signing_client::{
        protocol_execution::{execute_protocol::execute_dkg, Channels},
        protocol_transport::{open_protocol_connections, Listener},
        ListenerState,
    },
    user::{
        api::{UserRegistrationInfo, ValidatorInfo},
        errors::UserErr,
    },
    validation::SignedMessage,
};
/// complete the dkg process for a new user
pub async fn do_dkg(
    validators_info: &Vec<entropy_shared::ValidatorInfo>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    state: &ListenerState,
    sig_request_account: AccountId32,
    my_subgroup: &u8,
    key_visibility: KeyVisibility,
    users_x25519_public_key: X25519PublicKey,
) -> Result<KeyShare<KeyParams>, UserErr> {
    let session_uid = sig_request_account.to_string();
    let account_sp_core = AccountId32::new(*signer.account_id().clone().as_ref());
    let mut converted_validator_info = vec![];
    let mut tss_accounts = vec![];
    for validator_info in validators_info {
        let address_slice: &[u8; 32] = &validator_info
            .tss_account
            .clone()
            .try_into()
            .map_err(|_| UserErr::AddressConversionError("Invalid Length".to_string()))?;
        let tss_account = AccountId32::new(*address_slice);
        let validator_info = ValidatorInfo {
            x25519_public_key: validator_info.x25519_public_key,
            ip_address: SocketAddrV4::from_str(std::str::from_utf8(&validator_info.ip_address)?)?,
            tss_account: tss_account.clone(),
        };
        converted_validator_info.push(validator_info);
        tss_accounts.push(tss_account);
    }

    if key_visibility == KeyVisibility::Private {
        tss_accounts.push(sig_request_account.clone());
    }

    // If key key visibility is private, pass the user's ID to the listener
    let user_details_option = if key_visibility == KeyVisibility::Private {
        Some((sig_request_account, users_x25519_public_key))
    } else {
        None
    };

    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, rx_from_others, listener) =
        Listener::new(converted_validator_info.clone(), &account_sp_core, user_details_option);
    state
	.listeners
	.lock()
	.map_err(|_| UserErr::SessionError("Error getting lock".to_string()))?
	// TODO: using signature ID as session ID. Correct?
	.insert(session_uid.clone(), listener);

    open_protocol_connections(&converted_validator_info, &session_uid, signer, state).await?;
    let channels = {
        let ready = timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await?;
        let broadcast_out = ready??;
        Channels(broadcast_out, rx_from_others)
    };
    let result = execute_dkg(channels, signer.signer(), tss_accounts, my_subgroup).await?;
    Ok(result)
}

/// Send's user key share to other members of signing subgroup
pub async fn send_key(
    api: &OnlineClient<EntropyConfig>,
    stash_address: &subxtAccountId32,
    addresses_in_subgroup: &mut Vec<subxtAccountId32>,
    user_registration_info: UserRegistrationInfo,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
) -> Result<(), UserErr> {
    addresses_in_subgroup.remove(
        addresses_in_subgroup
            .iter()
            .position(|address| *address == *stash_address)
            .ok_or_else(|| UserErr::OptionUnwrapError("Validator not in subgroup"))?,
    );
    for validator in addresses_in_subgroup {
        let server_info_query = entropy::storage().staking_extension().threshold_servers(validator);
        let server_info = api
            .storage()
            .at_latest()
            .await?
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
