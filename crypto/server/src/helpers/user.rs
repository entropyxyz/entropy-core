use std::time::Duration;

use entropy_shared::SETUP_TIMEOUT_SECONDS;
use kvdb::kv_manager::{KvManager, PartyId};
use sp_core::crypto::AccountId32;
use subxt::{
    ext::sp_core::{sr25519, Pair},
    tx::PairSigner,
    utils::AccountId32 as subxtAccountId32,
    OnlineClient,
};
use tokio::time::timeout;

use crate::{
    chain_api::{entropy, EntropyConfig},
    signing_client::{
        new_party::Channels,
        protocol_transport::{open_protocol_connections, Listener},
        SignerState,
    },
    user::{
        api::{UserRegistrationInfo, ValidatorInfo},
        errors::UserErr,
    },
};
/// complete the dkg process for a new user
pub async fn do_dkg(
    validators_info: Vec<ValidatorInfo>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    state: &SignerState,
    session_uid: String,
) -> Result<(), UserErr> {
    let account_sp_core = AccountId32::new(*signer.account_id().clone().as_ref());
    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, rx_from_others, listener) =
        Listener::new(validators_info.clone(), &account_sp_core);
    state
	.listeners
	.lock()
	.map_err(|_| UserErr::SessionError("Error getting lock".to_string()))?
	// TODO: using signature ID as session ID. Correct?
	.insert(session_uid.clone(), listener);

    let my_id = PartyId::new(account_sp_core.clone());

    open_protocol_connections(&validators_info, &session_uid, &my_id, &signer, state).await?;

    let channels = {
        let ready = timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await?;
        let broadcast_out = ready??;
        Channels(broadcast_out, rx_from_others)
    };

    Ok(())
}

pub async fn send_key(
    api: &OnlineClient<EntropyConfig>,
    subgroup: u8,
    addresses_in_subgroup: &Vec<subxtAccountId32>,
    user_registration_info: UserRegistrationInfo,
) -> Result<(), UserErr> {
    for validator in addresses_in_subgroup {
        let server_info_query = entropy::storage().staking_extension().threshold_servers(validator);
        let server_info = api
            .storage()
            .at_latest()
            .await?
            .fetch(&server_info_query)
            .await?
            .ok_or_else(|| UserErr::OptionUnwrapError("Server Info Fetch Error"))?;

        // encrypt and sign info
        let url = format!("http://{}/user/receive_key", String::from_utf8(server_info.endpoint)?);
        let client = reqwest::Client::new();

        let result = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&user_registration_info)?)
            .send()
            .await?;
    }
    Ok(())
}
