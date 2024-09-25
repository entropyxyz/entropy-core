use crate::{
    chain_api::{
        entropy::{
            self,
            runtime_types::{
                bounded_collections::bounded_vec::BoundedVec,
                pallet_registry::pallet::ProgramInstance,
                pallet_staking_extension::pallet::ServerInfo,
            },
            staking_extension::events,
        },
        get_api, get_rpc, EntropyConfig,
    },
    change_endpoint, change_threshold_accounts, register, remove_program, store_program,
    substrate::query_chain,
    update_programs,
};
use entropy_testing_utils::{
    constants::{TEST_PROGRAM_WASM_BYTECODE, TSS_ACCOUNTS},
    helpers::{derive_mock_pck_verifying_key, encode_verifying_key},
    jump_start_network,
    substrate_context::test_context_stationary,
    test_node_process_testing_state,
};
use serial_test::serial;
use sp_core::{sr25519, Pair, H256};
use sp_keyring::AccountKeyring;
use subxt::{tx::PairSigner, utils::AccountId32};

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
async fn test_change_threshold_accounts() {
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

    let provisioning_certification_key = {
        let key = derive_mock_pck_verifying_key(&TSS_ACCOUNTS[0]);
        BoundedVec(encode_verifying_key(&key).unwrap().to_vec())
    };

    assert_eq!(
        format!("{:?}", result),
        format!(
            "{:?}",
            events::ThresholdAccountChanged(
                AccountId32(one.pair().public().0),
                ServerInfo {
                    tss_account: AccountId32(one.pair().public().0),
                    x25519_public_key,
                    endpoint: "127.0.0.1:3001".as_bytes().to_vec(),
                    provisioning_certification_key,
                }
            )
        )
    );
}

#[tokio::test]
#[serial]
async fn test_store_and_remove_program() {
    let program_owner = AccountKeyring::Ferdie.pair();
    let substrate_context = test_context_stationary().await;

    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    // Store a program
    let program_hash = store_program(
        &api,
        &rpc,
        &program_owner,
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
        0u8,
    )
    .await
    .unwrap();

    // Check that the program was stored
    let program_query = entropy::storage().programs().programs(program_hash);
    let program_info = query_chain(&api, &rpc, program_query, None).await.unwrap().unwrap();
    assert_eq!(program_info.deployer.0, program_owner.public().0);

    // Remove the program
    remove_program(&api, &rpc, &program_owner, program_hash).await.unwrap();

    // Check that the program is no longer stored
    let program_query = entropy::storage().programs().programs(program_hash);
    assert!(query_chain(&api, &rpc, program_query, None).await.unwrap().is_none());

    // Removing program fails because program has already been removed
    assert!(remove_program(&api, &rpc, &program_owner, program_hash).await.is_err());
}

#[tokio::test]
#[serial]
async fn test_remove_program_reference_counter() {
    let program_owner = AccountKeyring::Ferdie.pair();

    let (_validator_ips, _validator_ids) =
        spawn_testing_validators(ChainSpecType::Integration).await;

    let force_authoring = true;
    let substrate_context = test_node_process_testing_state(force_authoring).await;
    let api = get_api(&substrate_context.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.ws_url).await.unwrap();

    // Jumpstart the network
    let alice = AccountKeyring::Alice;
    let signer = PairSigner::<EntropyConfig, sr25519::Pair>::new(alice.clone().into());
    jump_start_network(&api, &rpc, &signer).await;

    // Store a program
    let program_pointer = store_program(
        &api,
        &rpc,
        &program_owner,
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
        0u8,
    )
    .await
    .unwrap();

    // Register, using that program
    let (verifying_key, _registered_info) = register(
        &api,
        &rpc,
        program_owner.clone(),
        AccountId32(program_owner.public().0),
        BoundedVec(vec![ProgramInstance { program_pointer, program_config: vec![] }]),
    )
    .await
    .unwrap();

    // Removing program fails because program is being used
    assert!(remove_program(&api, &rpc, &program_owner, program_pointer).await.is_err());

    // Now stop using the program
    update_programs(
        &api,
        &rpc,
        verifying_key,
        &program_owner,
        BoundedVec(vec![ProgramInstance {
            program_pointer: H256([0; 32]),
            program_config: vec![],
        }]),
    )
    .await
    .unwrap();

    // We can now remove the program because no-one is using it
    remove_program(&api, &rpc, &program_owner, program_pointer).await.unwrap();
}
