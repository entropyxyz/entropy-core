use sp_core::crypto::AccountId32;
use subxt::{
    ext::sp_core::{sr25519, Pair},
    tx::PairSigner,
};

use crate::{
    chain_api::EntropyConfig,
    signing_client::{
        protocol_transport::{open_protocol_connections, Listener},
        SignerState,
    },
    user::{api::ValidatorInfo, errors::UserErr},
};
/// complete the dkg process for a new user
pub async fn do_dkg(
    validators_info: Vec<ValidatorInfo>,
    signer: PairSigner<EntropyConfig, sr25519::Pair>,
    state: &SignerState,
    session_uid: String,
) -> Result<(), UserErr> {
    let account_sp_core = AccountId32::new(*signer.account_id().clone().as_ref());
    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, rx_from_others, listener) = Listener::new(validators_info, &account_sp_core);
    state
	.listeners
	.lock()
	.map_err(|_| UserErr::SessionError("Error getting lock".to_string()))?
	// TODO: using signature ID as session ID. Correct?
	.insert(session_uid.clone(), listener);

    Ok(())
}
