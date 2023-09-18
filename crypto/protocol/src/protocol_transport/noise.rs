//! Noise handshake and encrypted channel for protocol messages
//!
//! We use the XK handshake pattern.
//! This means the initiator has a static keypair, and the responder has a pre-shared static keypair
//! That is, we already know the public key of the remote party we are connecting to before the
//! handshake starts)
//!
//! See: <https://noiseexplorer.com/patterns/XK>
use entropy_shared::X25519PublicKey;
use snow::{params::NoiseParams, Builder, HandshakeState};
use subxt::ext::sp_core::sr25519;
use sp_core::{Pair, crypto::Zeroize};
use blake2::{Blake2s256, Digest};
use x25519_dalek::StaticSecret;

use super::{errors::EncryptedConnectionError, WsConnection};

/// The handshake pattern and other parameters
const NOISE_PARAMS: &str = "Noise_XK_25519_ChaChaPoly_BLAKE2s";

/// This is used in the handshake as context
const NOISE_PROLOGUE: &[u8; 24] = b"Entropy signing protocol";

/// Handshake as an initiator
pub async fn noise_handshake_initiator<T: WsConnection>(
    mut ws_connection: T,
    local_private_key: &sr25519::Pair,
    remote_public_key: X25519PublicKey,
    final_message_payload: Vec<u8>,
) -> Result<EncryptedWsConnection<T>, EncryptedConnectionError> {
    let mut noise = setup_noise(local_private_key, Some(remote_public_key)).await?;

    // Used to hold handshake messages
    let mut buf = vec![0u8; 65535];

    // Initiator sends first message
    let len = noise.write_message(&[], &mut buf)?;
    ws_connection.send(buf[..len].to_vec()).await?;

    noise.read_message(&ws_connection.recv().await?, &mut buf)?;

    let len = noise.write_message(&final_message_payload, &mut buf)?;
    ws_connection.send(buf[..len].to_vec()).await?;

    // Transition the state machine into transport mode now that the handshake is complete.
    Ok(EncryptedWsConnection { ws_connection, noise_transport: noise.into_transport_mode()?, buf })
}

/// Handshake as a responder
pub async fn noise_handshake_responder<T: WsConnection>(
    mut ws_connection: T,
    local_private_key: &sr25519::Pair,
) -> Result<(EncryptedWsConnection<T>, String), EncryptedConnectionError> {
    let mut noise = setup_noise(local_private_key, None).await?;

    // Used to hold handshake messages
    let mut buf = vec![0u8; 65535];

    // Responder reads first message
    noise.read_message(&ws_connection.recv().await?, &mut buf)?;

    let len = noise.write_message(&[], &mut buf)?;
    ws_connection.send(buf[..len].to_vec()).await?;

    let len = noise.read_message(&ws_connection.recv().await?, &mut buf)?;
    let response = String::from_utf8(buf[..len].to_vec())?;

    // Transition the state machine into transport mode now that the handshake is complete.
    Ok((
        EncryptedWsConnection { ws_connection, noise_transport: noise.into_transport_mode()?, buf },
        response,
    ))
}

/// Configure the noise handshake
async fn setup_noise(
    local_private_key: &sr25519::Pair,
    remote_public_key_option: Option<X25519PublicKey>,
) -> Result<HandshakeState, snow::error::Error> {
    let private_key = derive_static_secret(local_private_key).to_bytes();

    let params: NoiseParams = NOISE_PARAMS.parse()?;
    let builder: Builder<'_> =
        Builder::new(params).local_private_key(&private_key).prologue(NOISE_PROLOGUE);

    Ok(if let Some(remote_public_key) = remote_public_key_option {
        builder.remote_public_key(&remote_public_key).build_initiator()?
    } else {
        builder.build_responder()?
    })
}

/// Wrapper around ws connection to encrypt and decrypt messages
pub struct EncryptedWsConnection<T: WsConnection> {
    ws_connection: T,
    noise_transport: snow::TransportState,
    buf: Vec<u8>,
}

impl<T: WsConnection> EncryptedWsConnection<T> {
    /// Receive and decrypt the next message
    pub async fn recv(&mut self) -> Result<String, EncryptedConnectionError> {
        let ciphertext = self.ws_connection.recv().await?;
        let len = self.noise_transport.read_message(&ciphertext, &mut self.buf)?;
        Ok(String::from_utf8(self.buf[..len].to_vec())?)
    }

    /// Encrypt and send a message
    pub async fn send(&mut self, msg: String) -> Result<(), EncryptedConnectionError> {
        let len = self.noise_transport.write_message(msg.as_bytes(), &mut self.buf)?;
        self.ws_connection.send(self.buf[..len].to_vec()).await?;
        Ok(())
    }

    /// Get the remote party's public encryption key
    pub fn remote_public_key(&self) -> Result<X25519PublicKey, EncryptedConnectionError> {
        self.noise_transport
            .get_remote_static()
            .ok_or(EncryptedConnectionError::RemotePublicKey)?
            .try_into()
            .map_err(|_| EncryptedConnectionError::RemotePublicKey)
    }
}

/// Derives a static secret from a sr25519 private key for usage in static Diffie-Hellman.
pub fn derive_static_secret(sk: &sr25519::Pair) -> x25519_dalek::StaticSecret {
    let mut buffer: [u8; 32] = [0; 32];
    let mut hasher = Blake2s256::new();
    hasher.update(sk.to_raw_vec());
    let hash = hasher.finalize().to_vec();
    buffer.copy_from_slice(&hash);
    let result = StaticSecret::from(buffer);
    buffer.zeroize();
    result
}
