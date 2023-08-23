use std::{net::SocketAddrV4, str::FromStr, time::Duration};

use entropy_shared::SETUP_TIMEOUT_SECONDS;
use kvdb::kv_manager::{KvManager, PartyId};
use sp_core::crypto::AccountId32;
use subxt::{
    ext::sp_core::{sr25519, Bytes, Pair},
    tx::PairSigner,
    utils::AccountId32 as subxtAccountId32,
    OnlineClient,
};
use synedrion::{KeyShare, TestSchemeParams};
use tokio::time::timeout;
use x25519_dalek::PublicKey;

use crate::{
    chain_api::{entropy, EntropyConfig},
    signing_client::{
        new_party::{signing_protocol::execute_dkg, Channels},
        protocol_transport::{open_protocol_connections, Listener},
        SignerState,
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
    state: &SignerState,
    session_uid: String,
    my_subgroup: &u8,
) -> Result<KeyShare<TestSchemeParams>, UserErr> {
    let account_sp_core = AccountId32::new(*signer.account_id().clone().as_ref());
    let converted_validator_info: Vec<ValidatorInfo> = validators_info
        .iter()
        .map(|validator_info| {
            let address_slice: &[u8; 32] = &validator_info.tss_account.clone().try_into().unwrap();
            ValidatorInfo {
                x25519_public_key: validator_info.x25519_public_key,
                ip_address: SocketAddrV4::from_str(
                    std::str::from_utf8(&validator_info.ip_address).unwrap(),
                )
                .unwrap(),
                tss_account: AccountId32::new(*address_slice),
            }
        })
        .collect();
    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, rx_from_others, listener) =
        Listener::new(converted_validator_info.clone(), &account_sp_core);
    state
	.listeners
	.lock()
	.map_err(|_| UserErr::SessionError("Error getting lock".to_string())).unwrap()
	// TODO: using signature ID as session ID. Correct?
	.insert(session_uid.clone(), listener);
    let my_id = PartyId::new(account_sp_core.clone());

    open_protocol_connections(&converted_validator_info, &session_uid, &my_id, &signer, state)
        .await?;
    let channels = {
        let ready = timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await?;
        let broadcast_out = ready.unwrap().unwrap();
        Channels(broadcast_out, rx_from_others)
    };
    let tss_accounts: Vec<AccountId32> = validators_info
        .iter()
        .map(|validator_info| {
            let address_slice: &[u8; 32] = &validator_info.tss_account.clone().try_into().unwrap();
            AccountId32::new(*address_slice)
        })
        .collect();
    let result = execute_dkg(channels, signer.signer(), tss_accounts, my_subgroup).await.unwrap();
    dbg!(result.clone());
    Ok(result)
}

pub async fn send_key(
    api: &OnlineClient<EntropyConfig>,
    subgroup: u8,
    stash_address: &subxtAccountId32,
    addresses_in_subgroup: &mut Vec<subxtAccountId32>,
    user_registration_info: UserRegistrationInfo,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
) -> Result<(), UserErr> {
    addresses_in_subgroup.remove(
        addresses_in_subgroup.iter().position(|address| *address == *stash_address).unwrap(),
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
            &Bytes(serde_json::to_vec(&user_registration_info.clone()).unwrap()),
            &PublicKey::from(server_info.x25519_public_key),
        )
        .unwrap();
        // encrypt and sign info
        let url = format!("http://{}/user/receive_key", String::from_utf8(server_info.endpoint)?);
        let client = reqwest::Client::new();

        let result = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&signed_message).unwrap())
            .send()
            .await?;
    }
    Ok(())
}
