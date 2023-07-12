//! Noise handshake and encrypted channel for protocol messages
use entropy_shared::X25519PublicKey;
use snow::{params::NoiseParams, Builder};
use subxt::ext::sp_core::sr25519;

use super::WsConnection;
use crate::{
    signing_client::{SigningErr, WsError},
    validation::derive_static_secret,
};

/// The handshake pattern and other parameters
const NOISE_PARAMS: &str = "Noise_XK_25519_ChaChaPoly_BLAKE2s";

/// This is used in the handshake as context
const NOISE_PROLOGUE: &[u8; 24] = b"Entropy signing protocol";

/// Handshake as an initiator
pub async fn noise_handshake_initiator(
    ws_stream: WsConnection,
    local_private_key: &sr25519::Pair,
    remote_public_key: X25519PublicKey,
    final_message_payload: Vec<u8>,
) -> Result<EncryptedWsConnection, SigningErr> {
    let (encrypted_connection, _) = noise_handshake(
        ws_stream,
        local_private_key,
        Some(remote_public_key),
        Some(final_message_payload),
    )
    .await?;
    Ok(encrypted_connection)
}

/// Handshake as a responder
pub async fn noise_handshake_responder(
    ws_stream: WsConnection,
    local_private_key: &sr25519::Pair,
) -> Result<(EncryptedWsConnection, String), SigningErr> {
    let (encrypted_connection, output_option) =
        noise_handshake(ws_stream, local_private_key, None, None).await?;
    Ok((encrypted_connection, output_option.unwrap()))
}

async fn noise_handshake(
    mut ws_stream: WsConnection,
    local_private_key: &sr25519::Pair,
    remote_public_key_option: Option<X25519PublicKey>,
    final_message_payload: Option<Vec<u8>>,
) -> Result<(EncryptedWsConnection, Option<String>), SigningErr> {
    let final_message_payload = final_message_payload.unwrap_or_default();
    let private_key = derive_static_secret(local_private_key).to_bytes();

    let is_initiator = remote_public_key_option.is_some();
    let params: NoiseParams = NOISE_PARAMS.parse().unwrap();
    let builder: Builder<'_> =
        Builder::new(params).local_private_key(&private_key).prologue(NOISE_PROLOGUE);

    let mut noise = if let Some(remote_public_key) = remote_public_key_option {
        builder.remote_public_key(&remote_public_key).build_initiator().unwrap()
    } else {
        builder.build_responder().unwrap()
    };

    // Used to hold handshake messages
    let mut buf = vec![0u8; 65535];

    let response = if is_initiator {
        // Initiator sends first message
        let len = noise.write_message(&[], &mut buf).unwrap();
        ws_stream.send(buf[..len].to_vec()).await.map_err(|_| SigningErr::ConnectionClosed)?;

        noise.read_message(&ws_stream.recv().await.unwrap(), &mut buf).unwrap();

        let len = noise.write_message(&final_message_payload, &mut buf).unwrap();
        ws_stream.send(buf[..len].to_vec()).await.map_err(|_| SigningErr::ConnectionClosed)?;
        None
    } else {
        // Responder reads first message
        noise.read_message(&ws_stream.recv().await.unwrap(), &mut buf).unwrap();

        let len = noise.write_message(&[], &mut buf).unwrap();
        ws_stream.send(buf[..len].to_vec()).await.unwrap();

        let len = noise.read_message(&ws_stream.recv().await.unwrap(), &mut buf).unwrap();
        Some(String::from_utf8(buf[..len].to_vec())?)
    };

    // Transition the state machine into transport mode now that the handshake is complete.
    Ok((EncryptedWsConnection::new(ws_stream, noise.into_transport_mode().unwrap()), response))
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

    pub async fn recv(&mut self) -> Result<String, WsError> {
        let ciphertext = self.ws_connection.recv().await.unwrap();
        let len = self.noise_transport.read_message(&ciphertext, &mut self.buf).unwrap();
        Ok(String::from_utf8(self.buf[..len].to_vec())?)
    }

    pub async fn send(&mut self, msg: String) -> Result<(), WsError> {
        let len = self.noise_transport.write_message(msg.as_bytes(), &mut self.buf).unwrap();
        self.ws_connection.send(self.buf[..len].to_vec()).await
    }

    pub fn remote_public_key(&self) -> X25519PublicKey {
        self.noise_transport.get_remote_static().unwrap().try_into().unwrap()
    }
}
