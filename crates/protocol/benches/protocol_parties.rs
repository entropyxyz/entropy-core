use anyhow::anyhow;
use entropy_protocol::{
    execute_protocol::{execute_signing_protocol, Channels},
    protocol_transport::{
        errors::WsError,
        noise::{noise_handshake_initiator, noise_handshake_responder},
        ws_to_channels, SubscribeMessage, WsChannels,
    },
    KeyParams, Listener, PartyId, RecoverableSignature, SessionId, SigningSessionInfo,
    ValidatorInfo,
};
use entropy_shared::X25519PublicKey;
use futures::future;
use rand_core::OsRng;
use sp_core::{sr25519, Pair};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subxt::utils::AccountId32;
use synedrion::{ecdsa::VerifyingKey, KeyShare};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_tungstenite::connect_async;
use x25519_dalek::StaticSecret;

/// Details of an individual party
struct ValidatorSecretInfo {
    keyshare: KeyShare<KeyParams>,
    pair: sr25519::Pair,
    x25519_secret_key: StaticSecret,
    socket: TcpListener,
}
use criterion::{criterion_group, criterion_main, Criterion};
pub fn criterion_benchmark(c: &mut Criterion) {
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(8).enable_all().build().unwrap();

    let mut group = c.benchmark_group("happy path");
    group.sample_size(10);
    group.bench_function("fib 20", |b| b.to_async(&runtime).iter(|| test_sign()));
    group.finish();
}

// fn from_elem(c: &mut Criterion) {
//     let size: usize = 1024;
//
//     c.bench_with_input(BenchmarkId::new("input_example", size), &size, |b, &s| {
//         // Insert a call to `to_async` to convert the bencher to async mode.
//         // The timing loops are the same as with the normal bencher.
//         b.to_async(FuturesExecutor).iter(|| test_sign());
//     });
// }

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

// #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_sign() {
    let num_parties = 3;

    let keyshares = KeyShare::<KeyParams>::new_centralized(&mut OsRng, num_parties, None);

    let verifying_key = keyshares[0].verifying_key();
    let message_hash = [0u8; 32];
    let session_id = SessionId::Sign(SigningSessionInfo {
        signature_verifying_key: verifying_key.to_encoded_point(true).as_bytes().to_vec(),
        message_hash,
        request_author: AccountId32([0u8; 32]),
    });

    // Prepare information about each node
    let mut validator_secrets = Vec::new();
    let mut validators_info = Vec::new();
    for i in 0..num_parties {
        // Start a TCP listener and get its socket address
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        // Generate signing and encrytion keys
        let (pair, _) = sr25519::Pair::generate();
        let tss_account = AccountId32(pair.public().0);
        let x25519_secret_key = StaticSecret::random_from_rng(OsRng);
        let x25519_public_key = x25519_dalek::PublicKey::from(&x25519_secret_key).to_bytes();

        validator_secrets.push(ValidatorSecretInfo {
            keyshare: keyshares[i].clone(),
            pair,
            x25519_secret_key,
            socket,
        });
        // Public contact information that all parties know
        validators_info.push(ValidatorInfo {
            tss_account,
            x25519_public_key,
            ip_address: addr.to_string(),
        })
    }

    // Spawn tasks for each party
    let now = Instant::now();
    let mut results_rx = Vec::new();
    for _ in 0..num_parties {
        // Channel used to return the resulting signature
        let (tx, rx) = oneshot::channel();
        results_rx.push(rx);
        let secret = validator_secrets.pop().unwrap();
        let validators_info_clone = validators_info.clone();
        let session_id_clone = session_id.clone();
        tokio::spawn(async move {
            let now_individual = Instant::now();
            let result = server(
                secret.socket,
                validators_info_clone,
                secret.pair,
                secret.x25519_secret_key,
                session_id_clone,
                secret.keyshare,
            )
            .await;
            println!("Individual party finished protocol {:?}", now_individual.elapsed());
            tx.send(result).unwrap();
        });
    }
    let results = future::join_all(results_rx).await;
    println!("{} parties - Time taken to get all results: {:?}", num_parties, now.elapsed());

    // Check signatures
    for res in results {
        let recoverable_signature = res.unwrap().unwrap();
        let recovery_key_from_sig = VerifyingKey::recover_from_prehash(
            &message_hash,
            &recoverable_signature.signature,
            recoverable_signature.recovery_id,
        )
        .unwrap();
        assert_eq!(verifying_key, recovery_key_from_sig);
    }
}

#[derive(Clone)]
struct ServerState {
    x25519_secret_key: StaticSecret,
    listener: Arc<Mutex<Vec<Listener>>>,
}

pub async fn server(
    socket: TcpListener,
    validators_info: Vec<ValidatorInfo>,
    pair: sr25519::Pair,
    x25519_secret_key: StaticSecret,
    session_id: SessionId,
    keyshare: KeyShare<KeyParams>,
) -> anyhow::Result<RecoverableSignature> {
    let account_id = AccountId32(pair.public().0);
    let (rx_ready, rx_from_others, listener) =
        Listener::new(validators_info.clone(), &account_id, None);
    let state = ServerState {
        listener: Arc::new(Mutex::new(vec![listener])),
        x25519_secret_key: x25519_secret_key.clone(),
    };

    // Handle each connection in a separate task
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

    open_protocol_connections(&validators_info, &session_id, &pair, &x25519_secret_key, &state)
        .await?;

    // Wait for other parties to connect
    let channels = {
        let ready = timeout(Duration::from_secs(10), rx_ready).await?;
        let broadcast_out = ready??;
        Channels(broadcast_out, rx_from_others)
    };

    let message_hash = if let SessionId::Sign(session_info) = &session_id {
        session_info.message_hash
    } else {
        return Err(anyhow!("Cannot get message hash from session id"));
    };

    let tss_accounts: Vec<AccountId32> =
        validators_info.iter().map(|validator_info| validator_info.tss_account.clone()).collect();

    let rsig = execute_signing_protocol(
        session_id,
        channels,
        &keyshare,
        &message_hash,
        &pair,
        tss_accounts,
    )
    .await?;

    let (signature, recovery_id) = rsig.to_backend();
    Ok(RecoverableSignature { signature, recovery_id })
}

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

/// Handle a subscribe message
async fn handle_initial_incoming_ws_message(
    serialized_subscribe_message: Vec<u8>,
    _remote_public_key: X25519PublicKey,
    state: ServerState,
) -> anyhow::Result<(WsChannels, PartyId)> {
    let msg: SubscribeMessage = bincode::deserialize(&serialized_subscribe_message)?;
    tracing::info!("Got ws connection, with message: {msg:?}");

    if !msg.verify()? {
        return Err(anyhow::anyhow!("Invalid signature"));
    }

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

/// Set up websocket connections to other members of the signing committee
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
