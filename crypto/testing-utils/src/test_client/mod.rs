use anyhow::anyhow;
use sp_core::{crypto::AccountId32, sr25519, Pair};
use subxt::{tx::PairSigner, utils::AccountId32 as SubxtAccountId32, Config, OnlineClient};

pub use crate::chain_api::entropy::runtime_types::entropy_shared::{
    constraints::Constraints, types::KeyVisibility,
};
use crate::chain_api::{entropy::runtime_types::pallet_relayer::pallet::RegisteredInfo, *};

pub async fn get_api(ws_url: String) -> anyhow::Result<OnlineClient<EntropyConfig>> {
    Ok(OnlineClient::<EntropyConfig>::from_url(ws_url.clone()).await?)
}

pub async fn register(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keypair: sr25519::Pair,
    constraint_account: SubxtAccountId32,
    key_visibility: KeyVisibility,
    initial_program: Option<Constraints>,
) -> anyhow::Result<RegisteredInfo> {
    // Check if user is already registered
    let account_id32: AccountId32 = sig_req_keypair.public().into();
    let account_id: <EntropyConfig as Config>::AccountId = account_id32.into();
    let registered_query = entropy::storage().relayer().registered(account_id);
    let query_registered_status = api.storage().at_latest().await?.fetch(&registered_query).await;
    if let Some(registered_status) = query_registered_status? {
        return Err(anyhow!("Already registered {:?}", registered_status));
    }

    // Send register transaction
    put_register_request_on_chain(
        api,
        sig_req_keypair.clone(),
        constraint_account,
        key_visibility,
        initial_program,
    )
    .await?;
    // Wait until user is confirmed as registered
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let query_registered_status =
            api.storage().at_latest().await?.fetch(&registered_query).await;
        if let Some(registered_status) = query_registered_status? {
            return Ok(registered_status);
        }
    }
    Err(anyhow!("Timed out waiting for register confirmation"))
}

async fn put_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keypair: sr25519::Pair,
    constraint_account: SubxtAccountId32,
    key_visibility: KeyVisibility,
    initial_program: Option<Constraints>,
) -> anyhow::Result<()> {
    let sig_req_account = PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(sig_req_keypair);

    let registering_tx =
        entropy::tx().relayer().register(constraint_account, key_visibility, initial_program);

    api.tx()
        .sign_and_submit_then_watch_default(&registering_tx, &sig_req_account)
        .await?
        .wait_for_in_block()
        .await?
        .wait_for_success()
        .await?;
    Ok(())
}

// pub fn seed_from_string(input: String) -> [u8; 32] {
//     let mut buffer: [u8; 32] = [0; 32];
//     let mut hasher = Blake2s256::new();
//     hasher.update(input.as_bytes());
//     let hash = hasher.finalize().to_vec();
//     buffer.copy_from_slice(&hash);
//     buffer
// }

// let subgroup_info_query =
// entropy::storage().staking_extension().signing_groups(0 as u8);
// 	let subgroup_info = api
// 	.storage()
// .at_latest()
// 	.await?
// .fetch(&subgroup_info_query)
// 	.await?;
//
// 	println!("SSS {:?}", subgroup_info);
//
// let sudo_tx = entropy::tx().balances().force_set_balance(account_id32.into(), 9);
// api.tx().sudo().sign_and_submit_then_watch_default();
