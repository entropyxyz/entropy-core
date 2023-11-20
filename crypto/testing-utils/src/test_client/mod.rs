use subxt::{
    ext::sp_core::{sr25519, Pair},
    tx::PairSigner,
    utils::AccountId32 as SubxtAccountId32,
    OnlineClient,
};

use server::chain_api::{entropy, EntropyConfig};

pub async fn update_programs(
    entropy_api: &OnlineClient<EntropyConfig>,
    sig_req_keyring: &sr25519::Pair,
    program_modification_account: &sr25519::Pair,
    initial_program: Vec<u8>,
) {
    // update/set their programs
    let update_program_tx = entropy::tx()
        .programs()
        .update_program(SubxtAccountId32::from(sig_req_keyring.public()), initial_program);

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
