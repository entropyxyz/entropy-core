//! Noise handshake and encrypted channel for protocol messages
//!
//! We use the XK handshake pattern.
//! This means the initiator has a static keypair, and the responder has a pre-shared static keypair
//! That is, we already know the public key of the remote party we are connecting to before the
//! handshake starts.
//!
//! See: <https://noiseexplorer.com/patterns/XK>
use entropy_shared::X25519PublicKey;
use snow::{params::NoiseParams, Builder, HandshakeState};
use std::cmp::min;

use super::{errors::EncryptedConnectionErr, WsConnection};

/// The handshake pattern and other parameters
const NOISE_PARAMS: &str = "Noise_XK_25519_ChaChaPoly_BLAKE2s";

/// This is used in the handshake as context
const NOISE_PROLOGUE: &[u8; 24] = b"Entropy signing protocol";

/// The maxiumum message size for the noise protocol
const MAX_NOISE_MESSAGE_SIZE: usize = 65535;

/// The size of the authentication data added to each encrypted noise message
const NOISE_PAYLOAD_AUTHENTICATION_SIZE: usize = 16;

/// Handshake as an initiator
pub async fn noise_handshake_initiator<T: WsConnection>(
    mut ws_connection: T,
    local_private_key: &x25519_dalek::StaticSecret,
    remote_public_key: X25519PublicKey,
    final_message_payload: Vec<u8>,
) -> Result<EncryptedWsConnection<T>, EncryptedConnectionErr> {
    let mut noise = setup_noise(local_private_key, Some(remote_public_key)).await?;

    // Used to hold handshake messages
    let mut buf = vec![0u8; MAX_NOISE_MESSAGE_SIZE];

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
    local_private_key: &x25519_dalek::StaticSecret,
) -> Result<(EncryptedWsConnection<T>, Vec<u8>), EncryptedConnectionErr> {
    let mut noise = setup_noise(local_private_key, None).await?;

    // Used to hold handshake messages
    let mut buf = vec![0u8; MAX_NOISE_MESSAGE_SIZE];

    // Responder reads first message
    noise.read_message(&ws_connection.recv().await?, &mut buf)?;

    let len = noise.write_message(&[], &mut buf)?;
    ws_connection.send(buf[..len].to_vec()).await?;

    let len = noise.read_message(&ws_connection.recv().await?, &mut buf)?;
    let response = buf[..len].to_vec();

    // Transition the state machine into transport mode now that the handshake is complete.
    Ok((
        EncryptedWsConnection { ws_connection, noise_transport: noise.into_transport_mode()?, buf },
        response,
    ))
}

/// Configure the noise handshake
async fn setup_noise(
    local_private_key: &x25519_dalek::StaticSecret,
    remote_public_key_option: Option<X25519PublicKey>,
) -> Result<HandshakeState, snow::error::Error> {
    let private_key = local_private_key.to_bytes();
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
    /// This splits the incoming message into chunks of the maximum message size allowed
    /// by the noise protocol, decrypts them individually and concatenates the results into
    /// a single message
    pub async fn recv(&mut self) -> Result<Vec<u8>, EncryptedConnectionErr> {
        let ciphertext = self.ws_connection.recv().await?;

        let mut full_message = Vec::new();
        let mut i = 0;
        while i < ciphertext.len() {
            let read_to = min(i + MAX_NOISE_MESSAGE_SIZE, ciphertext.len());
            let len = self.noise_transport.read_message(&ciphertext[i..read_to], &mut self.buf)?;
            full_message.extend_from_slice(&self.buf[..len]);
            i += MAX_NOISE_MESSAGE_SIZE;
        }

        Ok(full_message)
    }

    /// Encrypt and send a message
    /// This splits the outgoing message into chunks of the maximum size allowed by the noise
    /// protocol, encrypts them individually and concatenates the results into a single message
    pub async fn send(&mut self, msg: Vec<u8>) -> Result<(), EncryptedConnectionErr> {
        let mut messages = Vec::new();
        let mut i = 0;
        while i < msg.len() {
            let read_to =
                min(i + MAX_NOISE_MESSAGE_SIZE - NOISE_PAYLOAD_AUTHENTICATION_SIZE, msg.len());
            let len = self.noise_transport.write_message(&msg[i..read_to], &mut self.buf)?;
            messages.extend_from_slice(&self.buf[..len]);
            i += MAX_NOISE_MESSAGE_SIZE - NOISE_PAYLOAD_AUTHENTICATION_SIZE;
        }
        self.ws_connection.send(messages).await?;
        Ok(())
    }

    /// Get the remote party's public encryption key
    pub fn remote_public_key(&self) -> Result<X25519PublicKey, EncryptedConnectionErr> {
        self.noise_transport
            .get_remote_static()
            .ok_or(EncryptedConnectionErr::RemotePublicKey)?
            .try_into()
            .map_err(|_| EncryptedConnectionErr::RemotePublicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_transport::WsError;
    use async_trait::async_trait;
    use tokio::sync::mpsc;

    struct MockWsConnection {
        sender: mpsc::Sender<Vec<u8>>,
        receiver: mpsc::Receiver<Vec<u8>>,
    }

    impl MockWsConnection {
        fn new(our_tx: mpsc::Sender<Vec<u8>>, their_rx: mpsc::Receiver<Vec<u8>>) -> Self {
            Self { sender: our_tx, receiver: their_rx }
        }
    }

    #[async_trait]
    impl WsConnection for MockWsConnection {
        async fn recv(&mut self) -> Result<Vec<u8>, WsError> {
            Ok(self.receiver.recv().await.unwrap())
        }

        async fn send(&mut self, msg: Vec<u8>) -> Result<(), WsError> {
            self.sender.send(msg).await.unwrap();
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_encrypted_connection() {
        let alice_sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);

        let bob_sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let bob_pk = x25519_dalek::PublicKey::from(&bob_sk);

        let (alice_tx, alice_rx) = mpsc::channel(100);
        let (bob_tx, bob_rx) = mpsc::channel(100);

        let (alice_connection_result, bob_connection_result) = futures::future::join(
            noise_handshake_initiator(
                MockWsConnection::new(alice_tx, bob_rx),
                &alice_sk,
                bob_pk.as_bytes().clone(),
                Vec::new(),
            ),
            noise_handshake_responder(MockWsConnection::new(bob_tx, alice_rx), &bob_sk),
        )
        .await;

        let mut alice_connection = alice_connection_result.unwrap();
        let (mut bob_connection, _) = bob_connection_result.unwrap();

        alice_connection.send(b"hello bob".to_vec()).await.unwrap();
        bob_connection.send(b"hello alice".to_vec()).await.unwrap();

        assert_eq!(bob_connection.recv().await.unwrap(), b"hello bob".to_vec());
        assert_eq!(alice_connection.recv().await.unwrap(), b"hello alice".to_vec());
    }

    #[tokio::test]
    async fn test_encrypted_connection_with_big_message() {
        let alice_sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);

        let bob_sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let bob_pk = x25519_dalek::PublicKey::from(&bob_sk);

        let (alice_tx, alice_rx) = mpsc::channel(100);
        let (bob_tx, bob_rx) = mpsc::channel(100);

        let (alice_connection_result, bob_connection_result) = futures::future::join(
            noise_handshake_initiator(
                MockWsConnection::new(alice_tx, bob_rx),
                &alice_sk,
                bob_pk.as_bytes().clone(),
                Vec::new(),
            ),
            noise_handshake_responder(MockWsConnection::new(bob_tx, alice_rx), &bob_sk),
        )
        .await;

        let mut alice_connection = alice_connection_result.unwrap();
        let (mut bob_connection, _) = bob_connection_result.unwrap();

        let big_message_for_bob: [u8; MAX_NOISE_MESSAGE_SIZE + 100] =
            [1; MAX_NOISE_MESSAGE_SIZE + 100];
        let big_message_for_alice: [u8; MAX_NOISE_MESSAGE_SIZE * 3] =
            [2; MAX_NOISE_MESSAGE_SIZE * 3];

        alice_connection.send(big_message_for_bob.to_vec()).await.unwrap();
        bob_connection.send(big_message_for_alice.to_vec()).await.unwrap();

        assert_eq!(bob_connection.recv().await.unwrap(), &big_message_for_bob);
        assert_eq!(alice_connection.recv().await.unwrap(), &big_message_for_alice);
    }
}
