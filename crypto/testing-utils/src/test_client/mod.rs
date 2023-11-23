//! Client functionality used in itegration tests
use entropy_shared::KeyVisibility;
use subxt::{
    ext::sp_core::{sr25519, Pair},
    tx::PairSigner,
    utils::{AccountId32 as SubxtAccountId32, Static},
    OnlineClient,
};

use server::chain_api::{entropy, EntropyConfig};

/// Submit a register transaction
pub async fn put_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    sig_req_account: sr25519::Pair,
    program_modification_account: SubxtAccountId32,
    key_visibility: KeyVisibility,
) {
    let sig_req_account = PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(sig_req_account);

    let empty_program = vec![];
    let registering_tx = entropy::tx().relayer().register(
        program_modification_account,
        Static(key_visibility),
        empty_program,
    );

    api.tx()
        .sign_and_submit_then_watch_default(&registering_tx, &sig_req_account)
        .await
        .unwrap()
        .wait_for_in_block()
        .await
        .unwrap()
        .wait_for_success()
        .await
        .unwrap();
}

/// Set or update the program associated with a given entropy account
pub async fn update_program(
    entropy_api: &OnlineClient<EntropyConfig>,
    sig_req_account: &sr25519::Pair,
    program_modification_account: &sr25519::Pair,
    initial_program: Vec<u8>,
) {
    // update/set their programs
    let update_program_tx = entropy::tx()
        .programs()
        .update_program(SubxtAccountId32::from(sig_req_account.public()), initial_program);

    let program_modification_account =
        PairSigner::<EntropyConfig, sr25519::Pair>::new(program_modification_account.clone());

    entropy_api
        .tx()
        .sign_and_submit_then_watch_default(&update_program_tx, &program_modification_account)
        .await
        .unwrap()
        .wait_for_in_block()
        .await
        .unwrap()
        .wait_for_success()
        .await
        .unwrap();
}
