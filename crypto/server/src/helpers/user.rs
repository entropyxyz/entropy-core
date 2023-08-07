use crate::user::errors::UserErr;

/// complete the dkg process for a new user
pub async fn do_dkg() -> Result<(), UserErr> {
    // // subscribe to all other participating parties. Listener waits for other subscribers.
    // let (rx_ready, rx_from_others, listener) = Listener::new(message, &account_sp_core);
    // state
    //     .listeners
    //     .lock()
    // 	.map_err(|_| SigningErr::SessionError("Error getting lock".to_string()))?
    //     // TODO: using signature ID as session ID. Correct?
    //     .insert(sign_context.sign_init.sig_uid.clone(), listener);

    // open_protocol_connections(&sign_context, &my_id, &signer, state).await?;
    // let channels = {
    //     let ready = timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await?;
    //     let broadcast_out = ready??;
    //     Channels(broadcast_out, rx_from_others)
    // };
    Ok(())
}
