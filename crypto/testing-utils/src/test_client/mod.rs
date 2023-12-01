//! Client functionality used in itegration tests
use entropy_shared::KeyVisibility;
use server::chain_api::{entropy, EntropyConfig};
use std::str::FromStr;
use subxt::{
    ext::sp_core::sr25519,
    tx::PairSigner,
    utils::{AccountId32 as SubxtAccountId32, Static, H256},
    OnlineClient,
};
/// Submit a register transaction
pub async fn put_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    sig_req_account: sr25519::Pair,
    program_modification_account: SubxtAccountId32,
    key_visibility: KeyVisibility,
) {
    let sig_req_account = PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(sig_req_account);

    let empty_program_hash: H256 =
        H256::from_str("0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")
            .unwrap();
    let registering_tx = entropy::tx().relayer().register(
        program_modification_account,
        Static(key_visibility),
        empty_program_hash,
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
    program_modification_account: &sr25519::Pair,
    initial_program: Vec<u8>,
) {
    // update/set their programs
    let update_program_tx = entropy::tx().programs().set_program(initial_program);

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
