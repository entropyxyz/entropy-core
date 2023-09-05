use entropy_protocol::{ValidatorInfo, KeyParams, KeyShare, noise::noise_handshake_initiator};
use futures::future;
use gloo_net::websocket::{Message, futures::WebSocket};
// Need broadcast, mpsc

// implement WsConnection for WebSocket

/// Called when KeyVisibility is private - the user connects to relevant validators
/// and participates in the signing protocol
pub async fn user_connects_to_validators(
    key_share: &KeyShare<KeyParams>,
    sig_uid: &str,
    validators_info: Vec<ValidatorInfo>,
    user_signing_keypair: &sr25519::Pair,
    converted_transaction_request: &str,
) -> Result<RecoverableSignature, ProtocolErr> {
    // Set up channels for communication between signing protocol and other signing parties
    let (tx, _rx) = broadcast::channel(1000);
    let (tx_to_others, rx_to_others) = mpsc::channel(1000);
    let tx_ref = &tx;
    let tx_to_others_ref = &tx_to_others;

    // Create a vec of futures which connect to the other parties over ws
    let connect_to_validators = validators_info
        .iter()
        .map(|validator_info| async move {
            // Open a ws connection
            let ws_endpoint = format!("ws://{}/ws", validator_info.ip_address);
            let (ws_stream, _response) = connect_async(ws_endpoint).await?;
            let ws_stream = WsConnection::WsStream(ws_stream);

            // Send a SubscribeMessage in the payload of the final handshake message
            let server_public_key = PublicKey::from(validator_info.x25519_public_key);
            let signed_message = SignedMessage::new(
                user_signing_keypair,
                &Bytes(serde_json::to_vec(&SubscribeMessage::new(
                    sig_uid,
                    PartyId::new(user_signing_keypair.public().into()),
                ))?),
                &server_public_key,
            )?;
            let subscribe_message_vec = serde_json::to_vec(&signed_message)?;

            let mut encrypted_connection = noise_handshake_initiator(
                ws_stream,
                user_signing_keypair,
                validator_info.x25519_public_key,
                subscribe_message_vec,
            )
            .await
            .map_err(|e| ProtocolErr::EncryptedConnection(e.to_string()))?;

            // Check the response as to whether they accepted our SubscribeMessage
            let response_message = encrypted_connection
                .recv()
                .await
                .map_err(|e| ProtocolErr::EncryptedConnection(e.to_string()))?;

            let subscribe_response: Result<(), String> = serde_json::from_str(&response_message)?;
            if let Err(error_message) = subscribe_response {
                return Err(ProtocolErr::BadSubscribeMessage(error_message));
            }

            // Setup channels
            let ws_channels = WsChannels {
                broadcast: tx_ref.subscribe(),
                tx: tx_to_others_ref.clone(),
                is_final: false,
            };

            let remote_party_id = PartyId::new(validator_info.tss_account.clone());

            // Handle protocol messages in another task
            tokio::spawn(async move {
                if let Err(err) =
                    ws_to_channels(encrypted_connection, ws_channels, remote_party_id).await
                {
                    tracing::warn!("{:?}", err);
                };
            });

            Ok::<_, ProtocolErr>(())
        })
        .collect::<Vec<_>>();

    // Connect to validators
    future::try_join_all(connect_to_validators).await?;

    // Set up the signing protocol
    let channels = Channels(Broadcaster(tx_ref.clone()), rx_to_others);
    let mut tss_accounts: Vec<AccountId32> =
        validators_info.iter().map(|v| v.tss_account.clone()).collect();
    tss_accounts.push(user_signing_keypair.public().into());

    let parsed_tx = <Evm as Architecture>::TransactionRequest::parse(
        converted_transaction_request.to_string(),
    )?;

    let sig_hash = hex::encode(parsed_tx.sighash());

    let digest: PrehashedMessage = hex::decode(sig_hash)?
        .try_into()
        .map_err(|_| ProtocolErr::Conversion("Digest Conversion"))?;

    // Execute the signing protocol
    let rsig = execute_protocol::execute_signing_protocol(
        channels,
        key_share,
        &digest,
        user_signing_keypair,
        tss_accounts,
    )
    .await?;

    // Return a signature if everything went well
    let (signature, recovery_id) = rsig.to_backend();
    Ok(RecoverableSignature { signature, recovery_id })
}
