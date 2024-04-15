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

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use entropy_protocol::{KeyParams, SessionId, SigningSessionInfo, ValidatorInfo};
use futures::future;
use rand_core::OsRng;
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32;
use synedrion::{ecdsa::VerifyingKey, KeyShare};
use tokio::{net::TcpListener, sync::oneshot};
use x25519_dalek::StaticSecret;

mod helpers;
use helpers::server;

/// Benchmark for the signing protocol
pub fn criterion_benchmark(c: &mut Criterion) {
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(8).enable_all().build().unwrap();

    let mut group = c.benchmark_group("Signing protocol");
    for num_parties in 2..num_cpus::get() + 1 {
        let keyshares = KeyShare::<KeyParams>::new_centralized(&mut OsRng, num_parties, None);

        group.sample_size(10);
        group.bench_with_input(
            BenchmarkId::from_parameter(num_parties),
            &num_parties,
            |b, &_num_parties| b.to_async(&runtime).iter(|| test_sign(&keyshares)),
        );
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

/// Details of an individual party
struct ValidatorSecretInfo {
    keyshare: KeyShare<KeyParams>,
    pair: sr25519::Pair,
    x25519_secret_key: StaticSecret,
    socket: TcpListener,
}

async fn test_sign(keyshares: &[KeyShare<KeyParams>]) {
    let num_parties = keyshares.len();

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
    let mut results_rx = Vec::new();
    for _ in 0..num_parties {
        // Channel used to return the resulting signature
        let (tx, rx) = oneshot::channel();
        results_rx.push(rx);
        let secret = validator_secrets.pop().unwrap();
        let validators_info_clone = validators_info.clone();
        let session_id_clone = session_id.clone();
        tokio::spawn(async move {
            let result = server(
                secret.socket,
                validators_info_clone,
                secret.pair,
                secret.x25519_secret_key,
                session_id_clone,
                secret.keyshare,
            )
            .await;
            if !tx.is_closed() {
                tx.send(result).unwrap();
            }
        });
    }
    let (result, _, _) = future::select_all(results_rx).await;

    // Check signature
    let recoverable_signature = result.unwrap().unwrap();
    let recovery_key_from_sig = VerifyingKey::recover_from_prehash(
        &message_hash,
        &recoverable_signature.signature,
        recoverable_signature.recovery_id,
    )
    .unwrap();
    assert_eq!(verifying_key, recovery_key_from_sig);
}
