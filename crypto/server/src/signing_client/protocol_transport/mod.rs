//! Connect to other threshold servers over websocket for exchanging protocol messages
mod broadcaster;
mod listener;
mod message;

use axum::extract::ws::{self, WebSocket};
use entropy_shared::X25519PublicKey;
use futures::{future, SinkExt, StreamExt};
use kvdb::kv_manager::PartyId;
pub(super) use listener::WsChannels;
use snow::{params::NoiseParams, Builder};
use sp_core::{crypto::AccountId32, Bytes};
use subxt::{ext::sp_core::sr25519, tx::PairSigner};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use x25519_dalek::PublicKey;

pub use self::{broadcaster::Broadcaster, listener::Listener, message::SubscribeMessage};
use super::{new_party::SignContext, SigningErr};
use crate::{
    chain_api::EntropyConfig,
    get_signer,
    signing_client::{SigningMessage, SubscribeErr, WsError},
    validation::{derive_static_secret, SignedMessage},
    AppState, SignerState, SUBSCRIBE_TIMEOUT_SECONDS,
};

/// The handshake pattern and other parameters
const NOISE_PARAMS: &str = "Noise_XK_25519_ChaChaPoly_BLAKE2s";

/// This is used in the handshake as context
const NOISE_PROLOGUE: &[u8; 24] = b"Entropy signing protocol";

/// Set up websocket connections to other members of the signing committee
pub async fn open_protocol_connections(
    ctx: &SignContext,
    my_id: &PartyId,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    state: &SignerState,
) -> Result<(), SigningErr> {
    let sig_uid = &ctx.sign_init.sig_uid;

    let connect_to_validators = ctx
        .sign_init
        .validators_info
        .iter()
        .filter(|validators_info| {
            // Decide whether to initiate a connection by comparing accound ids
            // otherwise, we wait for them to connect to us
            signer.account_id() > &validators_info.tss_account
        })
        .map(|validator_info| async move {
            // Open a ws connection
            let ws_endpoint = format!("ws://{}/ws", validator_info.ip_address);
            let (ws_stream, _response) = connect_async(ws_endpoint).await?;
            let mut ws_stream = WsConnection::WsStream(ws_stream);

            let params: NoiseParams = NOISE_PARAMS.parse().unwrap();
            let builder: Builder<'_> = Builder::new(params);
            let mut noise = builder
                .local_private_key(&derive_static_secret(signer.signer()).to_bytes())
                .remote_public_key(&validator_info.x25519_public_key)
                .prologue(NOISE_PROLOGUE)
                .build_initiator()
                .unwrap();

            let mut buf = vec![0u8; 65535];

            let len = noise.write_message(&[], &mut buf).unwrap();
            ws_stream.send(buf[..len].to_vec()).await.map_err(|_| SigningErr::ConnectionClosed)?;

            let _len = noise.read_message(&ws_stream.recv().await.unwrap(), &mut buf).unwrap();
            // TODO here we could receive a signature and validate it

            // Send a SubscribeMessage in the payload of the final handshake message
            let server_public_key = PublicKey::from(validator_info.x25519_public_key);
            let signed_message = SignedMessage::new(
                signer.signer(),
                &Bytes(serde_json::to_vec(&SubscribeMessage::new(sig_uid, my_id.clone()))?),
                &server_public_key,
            )?;
            let subscribe_message_vec = serde_json::to_vec(&signed_message)?;

            let len = noise.write_message(&subscribe_message_vec, &mut buf).unwrap();
            ws_stream.send(buf[..len].to_vec()).await.map_err(|_| SigningErr::ConnectionClosed)?;

            // Transition the state machine into transport mode now that the handshake is complete.
            let mut encrypted_connection =
                EncryptedWsConnection::new(ws_stream, noise.into_transport_mode().unwrap());

            // Check the response as to whether they accepted our SubscribeMessage
            // TODO this error is not handled correctly
            let response_message =
                encrypted_connection.recv().await.map_err(|_| SigningErr::ConnectionClosed)?;
            let subscribe_response: Result<(), String> = serde_json::from_str(&response_message)?;
            if let Err(error_message) = subscribe_response {
                return Err(SigningErr::BadSubscribeMessage(error_message));
            }

            // Setup channels
            let ws_channels = get_ws_channels(state, sig_uid, &validator_info.tss_account)?;

            let remote_party_id = PartyId::new(validator_info.tss_account.clone());

            // Handle protocol messages
            tokio::spawn(async move {
                if let Err(err) =
                    ws_to_channels(encrypted_connection, ws_channels, remote_party_id).await
                {
                    tracing::warn!("{:?}", err);
                };
            });

            Ok::<_, SigningErr>(())
        })
        .collect::<Vec<_>>();

    future::try_join_all(connect_to_validators).await?;

    Ok(())
}

/// Handle an incoming websocket connection
pub async fn handle_socket(socket: WebSocket, app_state: AppState) -> Result<(), WsError> {
    let mut ws_stream = WsConnection::AxumWs(socket);
    let params: NoiseParams = NOISE_PARAMS.parse().unwrap();
    let builder: Builder<'_> = Builder::new(params);

    let signer = get_signer(&app_state.kv_store).await?;

    // Setup a noise HandShakeState
    let mut noise = builder
        .local_private_key(&derive_static_secret(signer.signer()).to_bytes())
        .prologue(NOISE_PROLOGUE)
        .build_responder()
        .unwrap();

    // Used for handshake messages
    let mut buf = vec![0u8; 65535];

    // We are the responded, so the other party speaks first
    noise.read_message(&ws_stream.recv().await.unwrap(), &mut buf).unwrap();

    // TODO we could add a signature here to double-authenticate ourself
    let len = noise.write_message(&[], &mut buf).unwrap();
    ws_stream.send(buf[..len].to_vec()).await?;

    let len = noise.read_message(&ws_stream.recv().await.unwrap(), &mut buf).unwrap();
    let serialized_signed_message = String::from_utf8(buf[..len].to_vec())?;

    let remote_public_key: X25519PublicKey = noise.get_remote_static().unwrap().try_into().unwrap();

    let (subscribe_response, ws_channels_option) = match handle_initial_incoming_ws_message(
        serialized_signed_message,
        remote_public_key,
        app_state,
    )
    .await
    {
        Ok((ws_channels, party_id)) => (Ok(()), Some((ws_channels, party_id))),
        Err(err) => (Err(format!("{err:?}")), None),
    };

    // Transition the state machine into transport mode now that the handshake is complete.
    let mut encrypted_connection =
        EncryptedWsConnection::new(ws_stream, noise.into_transport_mode().unwrap());

    // Send them a response as to whether we are happy with their subscribe message
    let subscribe_response_json =
        serde_json::to_string(&subscribe_response).map_err(|_| WsError::ConnectionClosed)?;
    encrypted_connection.send(subscribe_response_json).await?;

    // If it was successful, proceed with relaying signing protocol messages
    if let Some((ws_channels, remote_party_id)) = ws_channels_option {
        ws_to_channels(encrypted_connection, ws_channels, remote_party_id).await?;
    };

    Ok(())
}

/// Handle a subscribe message
async fn handle_initial_incoming_ws_message(
    serialized_signed_message: String,
    remote_public_key: X25519PublicKey,
    app_state: AppState,
) -> Result<(WsChannels, PartyId), SubscribeErr> {
    let signed_msg: SignedMessage = serde_json::from_str(&serialized_signed_message)?;
    if !signed_msg.verify() {
        return Err(SubscribeErr::InvalidSignature("Invalid signature."));
    }
    let signer = get_signer(&app_state.kv_store)
        .await
        .map_err(|e| SubscribeErr::UserError(e.to_string()))?;

    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| SubscribeErr::Decryption(e.to_string()))?;
    let msg: SubscribeMessage = serde_json::from_slice(&decrypted_message)?;

    tracing::info!("Got ws connection, with message: {msg:?}");

    let party_id = msg.party_id().map_err(SubscribeErr::InvalidPartyId)?;

    let signing_address = signed_msg.account_id();

    if PartyId::new(signing_address) != party_id {
        return Err(SubscribeErr::InvalidSignature("Signature does not match party id."));
    }

    if !app_state.signer_state.contains_listener(&msg.session_id)? {
        // Chain node hasn't yet informed this node of the party. Wait for a timeout and proceed
        // or fail below
        tokio::time::sleep(std::time::Duration::from_secs(SUBSCRIBE_TIMEOUT_SECONDS)).await;
    };

    {
        // Check that the given public key matches the public key we got in the
        // UserTransactionRequest
        let mut listeners = app_state
            .signer_state
            .listeners
            .lock()
            .map_err(|e| SubscribeErr::LockError(e.to_string()))?;
        let listener =
            listeners.get(&msg.session_id).ok_or(SubscribeErr::NoListener("no listener"))?;

        let validators_info = &listener.user_transaction_request.validators_info;
        if !validators_info
            .iter()
            .any(|validator_info| validator_info.x25519_public_key == remote_public_key)
        {
            // Make the signing process fail, since one of the commitee has misbehaved
            listeners.remove(&msg.session_id);
            return Err(SubscribeErr::Decryption(
                "Public key does not match that given in UserTransactionRequest".to_string(),
            ));
        }
    }

    let ws_channels =
        get_ws_channels(&app_state.signer_state, &msg.session_id, &signed_msg.account_id())?;

    Ok((ws_channels, party_id))
}

/// Subscribe to get channels
fn get_ws_channels(
    state: &SignerState,
    sig_uid: &str,
    tss_account: &AccountId32,
) -> Result<WsChannels, SubscribeErr> {
    let mut listeners =
        state.listeners.lock().map_err(|e| SubscribeErr::LockError(e.to_string()))?;
    let listener = listeners.get_mut(sig_uid).ok_or(SubscribeErr::NoListener("no listener"))?;
    let ws_channels = listener.subscribe(tss_account)?;

    if ws_channels.is_final {
        // all subscribed, wake up the waiting listener in new_party
        let listener =
            listeners.remove(sig_uid).ok_or(SubscribeErr::NoListener("listener remove"))?;
        let (tx, broadcaster) = listener.into_broadcaster();
        let _ = tx.send(Ok(broadcaster));
    };
    Ok(ws_channels)
}

/// Send singing protocol messages over websocket, and websocket messages to signing protocol
async fn ws_to_channels(
    mut connection: EncryptedWsConnection,
    mut ws_channels: WsChannels,
    remote_party_id: PartyId,
) -> Result<(), WsError> {
    loop {
        tokio::select! {
            // Incoming message from remote peer
            // TODO handle Err() case
            Ok(serialized_signing_message) = connection.recv() => {
                if let Ok(msg) = SigningMessage::try_from(&serialized_signing_message) {
                    ws_channels.tx.send(msg).await.map_err(|_| WsError::MessageAfterProtocolFinish)?;
                } else {
                    tracing::warn!("Could not deserialize signing protocol message - ignoring");
                    // close connection?
                };
            }
            // Outgoing message (from signing protocol to remote peer)
            Ok(msg) = ws_channels.broadcast.recv() => {
                // Check that the message is for this peer
                if let Some(party_id) = &msg.to {
                    if party_id != &remote_party_id {
                        continue;
                    }
                }
                if let Ok(message_string) = serde_json::to_string(&msg) {
                    // TODO if this fails, the ws connection has been dropped during the protocol
                    // we should inform the chain of this.
                    connection.send(message_string).await?;
                };
            }
        }
    }
}

/// Wrapper around ws connection to encrypt and decrypt messages
pub struct EncryptedWsConnection {
    ws_connection: WsConnection,
    noise_transport: snow::TransportState,
    buf: Vec<u8>,
}

impl EncryptedWsConnection {
    fn new(ws_connection: WsConnection, noise_transport: snow::TransportState) -> Self {
        Self { ws_connection, noise_transport, buf: vec![0u8; 65535] }
    }

    async fn recv(&mut self) -> Result<String, WsError> {
        let ciphertext = self.ws_connection.recv().await.unwrap();
        let len = self.noise_transport.read_message(&ciphertext, &mut self.buf).unwrap();
        Ok(String::from_utf8(self.buf[..len].to_vec())?)
    }

    async fn send(&mut self, msg: String) -> Result<(), WsError> {
        let len = self.noise_transport.write_message(msg.as_bytes(), &mut self.buf).unwrap();
        self.ws_connection.send(self.buf[..len].to_vec()).await
    }
}

// A wrapper around incoming and outgoing Websocket types
enum WsConnection {
    WsStream(WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>),
    AxumWs(WebSocket),
}

impl WsConnection {
    // TODO should return Result, not option
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        match self {
            WsConnection::WsStream(ref mut ws_stream) => {
                if let Some(Ok(Message::Binary(msg))) = ws_stream.next().await {
                    Some(msg)
                } else {
                    None
                }
            },
            WsConnection::AxumWs(ref mut axum_ws) => {
                if let Some(Ok(ws::Message::Binary(msg))) = axum_ws.recv().await {
                    Some(msg)
                } else {
                    None
                }
            },
        }
    }

    pub async fn send(&mut self, msg: Vec<u8>) -> Result<(), WsError> {
        match self {
            WsConnection::WsStream(ref mut ws_stream) =>
                ws_stream.send(Message::Binary(msg)).await.map_err(|_| WsError::ConnectionClosed),
            WsConnection::AxumWs(ref mut axum_ws) =>
                axum_ws.send(ws::Message::Binary(msg)).await.map_err(|_| WsError::ConnectionClosed),
        }
    }
}
