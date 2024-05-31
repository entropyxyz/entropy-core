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

//! A simple protocol server, like a mini version of entropy-tss, for benchmarking
use anyhow::{anyhow, ensure};
use entropy_protocol::{
    execute_protocol::{
        execute_dkg, execute_proactive_refresh, execute_signing_protocol, Channels,
    },
    protocol_transport::{
        errors::WsError,
        noise::{noise_handshake_initiator, noise_handshake_responder},
        ws_to_channels, SubscribeMessage, WsChannels,
    },
    KeyParams, KeyShareWithAuxInfo, Listener, PartyId, RecoverableSignature, SessionId,
    ValidatorInfo,
};
use entropy_shared::X25519PublicKey;
use futures::future;
use sp_core::{sr25519, Pair};
use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};
use subxt::utils::AccountId32;
use synedrion::{AuxInfo, ThresholdKeyShare};
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_tungstenite::connect_async;
use x25519_dalek::StaticSecret;

/// Internal state used by test server
#[derive(Clone)]
struct ServerState {
    x25519_secret_key: StaticSecret,
    listener: Arc<Mutex<Vec<Listener>>>,
}

/// Output of a successful protocol run
pub enum ProtocolOutput {
    Sign(RecoverableSignature),
    ProactiveRefresh(ThresholdKeyShare<KeyParams, PartyId>),
    Dkg(KeyShareWithAuxInfo),
}

impl fmt::Debug for ProtocolOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Success")
    }
}

/// A websocket server handling a single test protocol session
pub async fn server(
    socket: TcpListener,
    validators_info: Vec<ValidatorInfo>,
    pair: sr25519::Pair,
    x25519_secret_key: StaticSecret,
    session_id: SessionId,
    keyshare: Option<ThresholdKeyShare<KeyParams, PartyId>>,
    aux_info: Option<AuxInfo<KeyParams, PartyId>>,
) -> anyhow::Result<ProtocolOutput> {
    let account_id = AccountId32(pair.public().0);

    // Setup a single listener for tracking connnections to the other parties
    let (rx_ready, rx_from_others, listener) = Listener::new(validators_info.clone(), &account_id);

    let state = ServerState {
        listener: Arc::new(Mutex::new(vec![listener])),
        x25519_secret_key: x25519_secret_key.clone(),
    };

    // Handle each incoming connection in a separate task
    let state_clone = state.clone();
    tokio::spawn(async move {
        while let Ok((stream, _address)) = socket.accept().await {
            let state_clone2 = state_clone.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(state_clone2, stream).await {
                    tracing::warn!("Error when handling ws connection {}", e);
                };
            });
        }
    });

    // Make outgoing connections
    open_protocol_connections(&validators_info, &session_id, &pair, &x25519_secret_key, &state)
        .await?;

    // Wait for other parties to connect
    let channels = {
        let ready = timeout(Duration::from_secs(10), rx_ready).await?;
        let broadcast_out = ready??;
        Channels(broadcast_out, rx_from_others)
    };

    let tss_accounts: Vec<AccountId32> =
        validators_info.iter().map(|validator_info| validator_info.tss_account.clone()).collect();

    match session_id.clone() {
        SessionId::Sign(session_info) => {
            let rsig = execute_signing_protocol(
                session_id,
                channels,
                &keyshare.unwrap(),
                &aux_info.unwrap(),
                &session_info.message_hash,
                &pair,
                tss_accounts,
            )
            .await?;

            let (signature, recovery_id) = rsig.to_backend();
            Ok(ProtocolOutput::Sign(RecoverableSignature { signature, recovery_id }))
        },
        SessionId::ProactiveRefresh { .. } => {
            let new_keyshare = execute_proactive_refresh(
                session_id,
                channels,
                &pair,
                tss_accounts,
                keyshare.unwrap(),
            )
            .await?;
            Ok(ProtocolOutput::ProactiveRefresh(new_keyshare))
        },
        SessionId::Dkg { .. } => {
            let keyshare_and_aux_info =
                execute_dkg(session_id, channels, &pair, tss_accounts).await?;
            Ok(ProtocolOutput::Dkg(keyshare_and_aux_info))
        },
    }
}

/// Handle an incoming websocket connection
async fn handle_connection(state: ServerState, raw_stream: TcpStream) -> anyhow::Result<()> {
    let ws_stream = tokio_tungstenite::accept_async(raw_stream).await?;

    let (mut encrypted_connection, serialized_signed_message) =
        noise_handshake_responder(ws_stream, &state.x25519_secret_key).await?;

    let remote_public_key = encrypted_connection.remote_public_key()?;

    let (subscribe_response, ws_channels_option) = match handle_initial_incoming_ws_message(
        serialized_signed_message,
        remote_public_key,
        state,
    )
    .await
    {
        Ok((ws_channels, party_id)) => (Ok(()), Some((ws_channels, party_id))),
        Err(err) => (Err(format!("{err:?}")), None),
    };
    // Send them a response as to whether we are happy with their subscribe message
    let subscribe_response_vec = bincode::serialize(&subscribe_response)?;
    encrypted_connection.send(subscribe_response_vec).await?;

    // If it was successful, proceed with relaying signing protocol messages
    let (ws_channels, remote_party_id) = ws_channels_option.ok_or(WsError::BadSubscribeMessage)?;
    ws_to_channels(encrypted_connection, ws_channels, remote_party_id).await?;
    Ok(())
}

/// Handle a subscribe message (first message sent by the initiator of the connection)
async fn handle_initial_incoming_ws_message(
    serialized_subscribe_message: Vec<u8>,
    _remote_public_key: X25519PublicKey,
    state: ServerState,
) -> anyhow::Result<(WsChannels, PartyId)> {
    let msg: SubscribeMessage = bincode::deserialize(&serialized_subscribe_message)?;
    tracing::info!("Got ws connection, with subscribe message: {msg:?}");
    ensure!(msg.verify()?, "Invalid signature");

    let ws_channels = get_ws_channels(&msg.session_id, &msg.account_id(), &state)?;
    Ok((ws_channels, PartyId::new(msg.account_id())))
}

/// Inform the listener we have made a ws connection to another signing party, and get channels to
/// the signing protocol
fn get_ws_channels(
    _session_id: &SessionId,
    tss_account: &AccountId32,
    state: &ServerState,
) -> anyhow::Result<WsChannels> {
    let mut listeners = state.listener.lock().unwrap();
    let listener = listeners.get_mut(0).ok_or(anyhow::anyhow!("No listener"))?;

    let ws_channels = listener.subscribe(tss_account)?;

    if ws_channels.is_final {
        let listener = listeners.pop().ok_or(anyhow::anyhow!("No listener"))?;
        // all subscribed, wake up the waiting listener to execute the protocol
        let (tx, broadcaster) = listener.into_broadcaster();
        let _ = tx.send(Ok(broadcaster));
    };
    Ok(ws_channels)
}

/// Set up outgoing websocket connections to other parties
async fn open_protocol_connections(
    validators_info: &[ValidatorInfo],
    session_id: &SessionId,
    signer: &sr25519::Pair,
    x25519_secret_key: &x25519_dalek::StaticSecret,
    state: &ServerState,
) -> anyhow::Result<()> {
    let connect_to_validators = validators_info
        .iter()
        .filter(|validator_info| {
            // Decide whether to initiate a connection by comparing account IDs
            // otherwise, we wait for them to connect to us
            signer.public().0 > validator_info.tss_account.0
        })
        .map(|validator_info| async move {
            // Open a ws connection
            let ws_endpoint = format!("ws://{}/ws", validator_info.ip_address);
            let (ws_stream, _response) = connect_async(ws_endpoint).await?;

            // Send a SubscribeMessage in the payload of the final handshake message
            let subscribe_message_vec =
                bincode::serialize(&SubscribeMessage::new(session_id.clone(), signer)?)?;

            let mut encrypted_connection = noise_handshake_initiator(
                ws_stream,
                x25519_secret_key,
                validator_info.x25519_public_key,
                subscribe_message_vec,
            )
            .await?;

            // Check the response as to whether they accepted our SubscribeMessage
            let response_message = encrypted_connection.recv().await?;
            let subscribe_response: Result<(), String> = bincode::deserialize(&response_message)?;
            if let Err(error_message) = subscribe_response {
                return Err(anyhow!(error_message));
            }

            // Setup channels
            let ws_channels = get_ws_channels(session_id, &validator_info.tss_account, state)?;

            let remote_party_id = PartyId::new(validator_info.tss_account.clone());

            // Handle protocol messages
            tokio::spawn(async move {
                if let Err(err) =
                    ws_to_channels(encrypted_connection, ws_channels, remote_party_id).await
                {
                    tracing::warn!("{:?}", err);
                };
            });

            Ok(())
        })
        .collect::<Vec<_>>();

    future::try_join_all(connect_to_validators).await?;
    Ok(())
}
