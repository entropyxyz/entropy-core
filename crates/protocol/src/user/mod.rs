// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! For private access mode - run the protocol on the client side (the user's device)

#[cfg(feature = "wasm")]
pub mod wasm;
use futures::{future, Future};
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32;
use synedrion::KeyShare;
#[cfg(feature = "server")]
use tokio::spawn;
use tokio::sync::{broadcast, mpsc};
#[cfg(feature = "wasm")]
use wasm_bindgen_futures::spawn_local as spawn;

use crate::{
    errors::UserRunningProtocolErr,
    execute_protocol::{self, Channels},
    protocol_transport::{
        noise::noise_handshake_initiator, open_ws_connection, ws_to_channels, Broadcaster,
        SubscribeMessage, ThreadSafeWsConnection, WsChannels,
    },
    sign_and_encrypt::derive_x25519_static_secret,
    KeyParams, PartyId, RecoverableSignature, SessionId, SigningSessionInfo, ValidatorInfo,
};

/// Called when KeyVisibility is private - the user connects to relevant validators
/// and participates in the signing protocol
pub async fn user_participates_in_signing_protocol(
    key_share: &KeyShare<KeyParams>,
    validators_info: Vec<ValidatorInfo>,
    user_signing_keypair: &sr25519::Pair,
    message_hash: [u8; 32],
) -> Result<RecoverableSignature, UserRunningProtocolErr> {
    let verifying_key = key_share.verifying_key().to_encoded_point(true).as_bytes().to_vec();

    let session_id = SessionId::Sign(SigningSessionInfo {
        signature_verifying_key: verifying_key,
        message_hash,
        request_author: AccountId32(user_signing_keypair.public().0),
    });
    // Make WS connections to the given set of TSS servers
    let (channels, tss_accounts) = user_connects_to_validators(
        open_ws_connection,
        &session_id,
        validators_info,
        user_signing_keypair,
    )
    .await?;

    // Execute the signing protocol
    let rsig = execute_protocol::execute_signing_protocol(
        session_id,
        channels,
        key_share,
        &message_hash,
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
    user_signing_keypair: &sr25519::Pair,
) -> Result<KeyShare<KeyParams>, UserRunningProtocolErr> {
    // Make WS connections to the given set of TSS servers
    let sig_req_account: AccountId32 = user_signing_keypair.public().0.into();
    let session_id = SessionId::Dkg(sig_req_account);
    let (channels, tss_accounts) = user_connects_to_validators(
        open_ws_connection,
        &session_id,
        validators_info,
        user_signing_keypair,
    )
    .await?;

    let keyshare =
        execute_protocol::execute_dkg(session_id, channels, user_signing_keypair, tss_accounts)
            .await?;

    Ok(keyshare)
}

/// Connect to TSS servers using websockets and the noise protocol
async fn user_connects_to_validators<F, Fut, W>(
    open_ws_connection: F,
    session_id: &SessionId,
    validators_info: Vec<ValidatorInfo>,
    user_signing_keypair: &sr25519::Pair,
) -> Result<(Channels, Vec<AccountId32>), UserRunningProtocolErr>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<W, UserRunningProtocolErr>>,
    W: ThreadSafeWsConnection,
{
    let x25519_private_key = derive_x25519_static_secret(user_signing_keypair);
    // Set up channels for communication between the protocol and the other parties
    let (tx, _rx) = broadcast::channel(1000);
    let (tx_to_others, rx_to_others) = mpsc::channel(1000);
    let tx_ref = &tx;
    let tx_to_others_ref = &tx_to_others;

    // Create a vec of futures which connect to the other parties over ws
    let connect_to_validators = validators_info
        .iter()
        .map(|validator_info| async {
            // Open a ws connection
            let ws_endpoint = format!("ws://{}/ws", validator_info.ip_address);
            let ws_stream = open_ws_connection(ws_endpoint).await?;

            // Prepare a SubscribeMessage for the payload of the final handshake message
            let subscribe_message_vec = bincode::serialize(&SubscribeMessage::new(
                session_id.clone(),
                user_signing_keypair,
            )?)?;

            let mut encrypted_connection = noise_handshake_initiator(
                ws_stream,
                &x25519_private_key,
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
            spawn(async move {
                if let Err(err) =
                    ws_to_channels(encrypted_connection, ws_channels, remote_party_id).await
                {
                    tracing::warn!("WS message loop error: {:?}", err);
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
    tss_accounts.push(user_signing_keypair.public().0.into());

    Ok((channels, tss_accounts))
}
