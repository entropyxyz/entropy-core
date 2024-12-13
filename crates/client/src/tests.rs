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
        get_api, get_rpc,
    },
    change_endpoint, change_threshold_accounts, get_oracle_headings, register, remove_program,
    request_attestation, store_program,
    substrate::query_chain,
    update_programs,
};

use entropy_shared::{QuoteContext, QuoteInputData};
use entropy_testing_utils::{
    constants::{TEST_PROGRAM_WASM_BYTECODE, TSS_ACCOUNTS, X25519_PUBLIC_KEYS},
    helpers::{encode_verifying_key, spawn_tss_nodes_and_start_chain},
    substrate_context::test_context_stationary,
    test_node_process_testing_state, ChainSpecType,
};
use rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};
use serial_test::serial;
use sp_core::{sr25519, Pair, H256};
use sp_keyring::AccountKeyring;
use subxt::utils::AccountId32;

#[tokio::test]
#[serial]
async fn test_change_endpoint() {
    let one = AccountKeyring::AliceStash;
    let substrate_context = test_context_stationary().await;

    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    // By using this `Alice` account we can skip the `request_attestation` step since this is
    // already set up at genesis.
    let tss_account_id = &TSS_ACCOUNTS[0];
    let x25519_public_key = X25519_PUBLIC_KEYS[0];

    // This nonce is what was used in the genesis config for `Alice`.
    let nonce = [0; 32];

    let quote = {
        let signing_key = tdx_quote::SigningKey::random(&mut OsRng);
        let public_key = sr25519::Public(tss_account_id.0);

        let input_data =
            QuoteInputData::new(public_key, x25519_public_key, nonce, QuoteContext::ChangeEndpoint);

        let mut pck_seeder = StdRng::from_seed(public_key.0);
        let pck = tdx_quote::SigningKey::random(&mut pck_seeder);
        let pck_encoded = tdx_quote::encode_verifying_key(pck.verifying_key()).unwrap().to_vec();

        tdx_quote::Quote::mock(signing_key.clone(), pck, input_data.0, pck_encoded)
            .as_bytes()
            .to_vec()
    };

    let result =
        change_endpoint(&api, &rpc, one.into(), "new_endpoint".to_string(), quote).await.unwrap();

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

    // We need to use an account that's not a validator (so not our default development/test accounts)
    // otherwise we're not able to update the TSS and X25519 keys for our existing validator.
    let non_validator_seed =
        "gospel prosper cactus remember snap enact refuse review bind rescue guard sock";
    let (tss_signer_pair, x25519_secret) =
        entropy_testing_utils::get_signer_and_x25519_secret_from_mnemonic(non_validator_seed)
            .unwrap();

    let tss_public_key = tss_signer_pair.signer().public();
    let x25519_public_key = x25519_dalek::PublicKey::from(&x25519_secret);

    // We need to give our new TSS account some funds before it can request an attestation.
    let dest = tss_signer_pair.account_id().clone().into();
    let amount = 10 * entropy_shared::MIN_BALANCE;
    let balance_transfer_tx = entropy::tx().balances().transfer_allow_death(dest, amount);
    let _transfer_result = crate::substrate::submit_transaction_with_pair(
        &api,
        &rpc,
        &one.pair(),
        &balance_transfer_tx,
        None,
    )
    .await
    .unwrap();

    // When we request an attestation we get a nonce back that we must use when generating our quote.
    let nonce = request_attestation(&api, &rpc, tss_signer_pair.signer()).await.unwrap();
    let nonce: [u8; 32] = nonce.try_into().unwrap();

    let mut pck_seeder = StdRng::from_seed(tss_public_key.0.clone());
    let pck = tdx_quote::SigningKey::random(&mut pck_seeder);
    let encoded_pck = encode_verifying_key(&pck.verifying_key()).unwrap().to_vec();

    let quote = {
        let input_data = entropy_shared::QuoteInputData::new(
            tss_public_key,
            *x25519_public_key.as_bytes(),
            nonce,
            QuoteContext::ChangeThresholdAccounts,
        );

        let signing_key = tdx_quote::SigningKey::random(&mut OsRng);
        tdx_quote::Quote::mock(signing_key.clone(), pck.clone(), input_data.0, encoded_pck.clone())
            .as_bytes()
            .to_vec()
    };

    let result = change_threshold_accounts(
        &api,
        &rpc,
        one.into(),
        tss_public_key.to_string(),
        hex::encode(*x25519_public_key.as_bytes()),
        quote,
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
                    tss_account: AccountId32(tss_public_key.0),
                    x25519_public_key: *x25519_public_key.as_bytes(),
                    endpoint: "127.0.0.1:3001".as_bytes().to_vec(),
                    provisioning_certification_key: BoundedVec(encoded_pck),
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

    let (_ctx, api, rpc, _validator_ips, _validator_ids) =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

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

#[tokio::test]
#[serial]
async fn test_get_oracle_headings() {
    let force_authoring = true;
    let context =
        test_node_process_testing_state(ChainSpecType::IntegrationJumpStarted, force_authoring)
            .await;
    let api = get_api(&context[0].ws_url).await.unwrap();
    let rpc = get_rpc(&context[0].ws_url).await.unwrap();

    let mut current_block = 0;
    while current_block < 2 {
        let finalized_head = rpc.chain_get_finalized_head().await.unwrap();
        current_block = rpc.chain_get_header(Some(finalized_head)).await.unwrap().unwrap().number;
    }

    let headings = get_oracle_headings(&api, &rpc).await.unwrap();

    assert_eq!(headings, vec!["block_number_entropy".to_string()]);
}
