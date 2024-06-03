use crate::{
    chain_api::{
        entropy::{
            runtime_types::pallet_staking_extension::pallet::ServerInfo, staking_extension::events,
        },
        get_api, get_rpc,
    },
    change_endpoint, change_threshold_accounts,
};
use entropy_testing_utils::substrate_context::test_context_stationary;
use serial_test::serial;
use sp_core::Pair;
use sp_keyring::AccountKeyring;
use subxt::utils::AccountId32;

#[tokio::test]
#[serial]
async fn test_change_endpoint() {
    let one = AccountKeyring::AliceStash;
    let substrate_context = test_context_stationary().await;

    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    let result = change_endpoint(&api, &rpc, one.into(), "new_endpoint".to_string()).await.unwrap();
    assert_eq!(
        format!("{:?}", result),
        format!(
            "{:?}",
            events::EndpointChanged(
                AccountId32(one.pair().public().0),
                "new_endpoint".as_bytes().to_vec()
            )
        )
    );
}

#[tokio::test]
#[serial]
async fn test_change_threhsold_accounts() {
    let one = AccountKeyring::AliceStash;
    let substrate_context = test_context_stationary().await;

    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();
    let x25519_public_key = [0u8; 32];
    let result = change_threshold_accounts(
        &api,
        &rpc,
        one.into(),
        AccountId32(one.pair().public().0.into()).to_string(),
        hex::encode(x25519_public_key),
    )
    .await
    .unwrap();
    assert_eq!(
        format!("{:?}", result),
        format!(
            "{:?}",
            events::ThresholdAccountChanged(
                AccountId32(one.pair().public().0),
                ServerInfo {
                    tss_account: AccountId32(one.pair().public().0),
                    x25519_public_key,
                    endpoint: "127.0.0.1:3001".as_bytes().to_vec()
                }
            )
        )
    );
}
