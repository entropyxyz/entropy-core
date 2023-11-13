#![cfg(feature = "server")]

use entropy_shared::SIGNING_PARTY_SIZE;
use futures::future;
use subxt::utils::AccountId32;
use subxt_signer::sr25519;
use synedrion::KeyShare;
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::connect_async;

use crate::{
    errors::UserRunningProtocolErr,
    execute_protocol::{self, Channels},
    protocol_transport::{
        noise::noise_handshake_initiator, ws_to_channels, Broadcaster, SubscribeMessage, WsChannels,
    },
    KeyParams, PartyId, RecoverableSignature, ValidatorInfo,
};

/// Called when KeyVisibility is private - the user connects to relevant validators
/// and participates in the signing protocol
pub async fn user_participates_in_signing_protocol(
    key_share: &KeyShare<KeyParams>,
    sig_uid: &str,
    validators_info: Vec<ValidatorInfo>,
    user_signing_keypair: &sr25519::Keypair,
    sig_hash: [u8; 32],
    x25519_private_key: &x25519_dalek::StaticSecret,
) -> Result<RecoverableSignature, UserRunningProtocolErr> {
    let (channels, tss_accounts) = user_connects_to_validators(
        sig_uid,
        validators_info,
        user_signing_keypair,
        x25519_private_key,
    )
    .await?;

    // Execute the signing protocol
    let rsig = execute_protocol::execute_signing_protocol(
        channels,
        key_share,
        &sig_hash,
        user_signing_keypair,
        tss_accounts,
    )
    .await?;

    // Return a signature if everything went well
    let (signature, recovery_id) = rsig.to_backend();
    Ok(RecoverableSignature { signature, recovery_id })
}

/// Called during registration when key visibility is private - the user participates
/// in the DKG protocol.
pub async fn user_participates_in_dkg_protocol(
    validators_info: Vec<ValidatorInfo>,
    user_signing_keypair: &sr25519::Keypair,
    x25519_private_key: &x25519_dalek::StaticSecret,
) -> Result<KeyShare<KeyParams>, UserRunningProtocolErr> {
    let sig_req_account: AccountId32 = user_signing_keypair.public_key().0.into();
    let session_id = sig_req_account.to_string();
    let (channels, tss_accounts) = user_connects_to_validators(
        &session_id,
        validators_info,
        user_signing_keypair,
        x25519_private_key,
    )
    .await?;

    // The user's subgroup id is SIGNING_PARTY_SIZE. They will always be alone in their subgroup
    // as all other subgroup id's are < SIGNING_PARTY_SIZE
    let user_subgroup = SIGNING_PARTY_SIZE as u8;

    let keyshare =
        execute_protocol::execute_dkg(channels, user_signing_keypair, tss_accounts, &user_subgroup)
            .await?;

    Ok(keyshare)
}

async fn user_connects_to_validators(
    session_id: &str,
    validators_info: Vec<ValidatorInfo>,
    user_signing_keypair: &sr25519::Keypair,
    x25519_private_key: &x25519_dalek::StaticSecret,
) -> Result<(Channels, Vec<AccountId32>), UserRunningProtocolErr> {
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
            let (ws_stream, _response) = connect_async(ws_endpoint)
                .await
                .map_err(|e| UserRunningProtocolErr::Connection(e.to_string()))?;

            // Send a SubscribeMessage in the payload of the final handshake message
            let subscribe_message_vec =
                bincode::serialize(&SubscribeMessage::new(session_id, user_signing_keypair))?;

            let mut encrypted_connection = noise_handshake_initiator(
                ws_stream,
                x25519_private_key,
                validator_info.x25519_public_key,
                subscribe_message_vec,
            )
            .await?;

            // Check the response as to whether they accepted our SubscribeMessage
            let response_message = encrypted_connection.recv().await?;

            let subscribe_response: Result<(), String> = bincode::deserialize(&response_message)?;
            if let Err(error_message) = subscribe_response {
                return Err(UserRunningProtocolErr::BadSubscribeMessage(error_message));
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

            Ok::<_, UserRunningProtocolErr>(())
        })
        .collect::<Vec<_>>();

    // Connect to validators
    future::try_join_all(connect_to_validators).await?;

    // Things needed for protocol execution
    let channels = Channels(Broadcaster(tx_ref.clone()), rx_to_others);

    let mut tss_accounts: Vec<AccountId32> =
        validators_info.iter().map(|v| v.tss_account.clone()).collect();
    // Add ourself to the list of partys as we will participate
    tss_accounts.push(user_signing_keypair.public_key().0.into());

    Ok((channels, tss_accounts))
}
