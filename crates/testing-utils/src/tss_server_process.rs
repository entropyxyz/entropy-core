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

use axum::{routing::IntoMakeService, Router};
use entropy_kvdb::{encrypted_sled::PasswordMethod, kv_manager::KvManager};
use entropy_protocol::{KeyParams, PartyId};
use entropy_shared::DETERMINISTIC_KEY_SHARE;
use entropy_tss::{
    app, get_signer,
    launch::{setup_latest_block_number, setup_mnemonic, Configuration, ValidatorName},
    AppState,
};
use rand_core::OsRng;
use std::time::Duration;
use subxt::utils::AccountId32 as SubxtAccountId32;
use synedrion::{ecdsa::SigningKey, KeyShare};

pub const DEFAULT_ENDPOINT: &str = "ws://localhost:9944";

async fn create_clients(
    key_number: String,
    values: Vec<Vec<u8>>,
    keys: Vec<String>,
    validator_name: &Option<ValidatorName>,
) -> (IntoMakeService<Router>, KvManager) {
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());

    let path = format!(".entropy/testing/test_db_{key_number}");
    let _ = std::fs::remove_dir_all(path.clone());

    let kv_store =
        KvManager::new(path.into(), PasswordMethod::NoPassword.execute().unwrap()).unwrap();
    let _ = setup_mnemonic(&kv_store, validator_name).await;
    let _ = setup_latest_block_number(&kv_store).await;

    for (i, value) in values.into_iter().enumerate() {
        let reservation = kv_store.clone().kv().reserve_key(keys[i].to_string()).await.unwrap();
        let _ = kv_store.clone().kv().put(reservation, value).await;
    }

    let app_state = AppState::new(configuration, kv_store.clone());
    let app = app(app_state).into_make_service();

    (app, kv_store)
}

pub async fn spawn_testing_validators(
    passed_verifying_key: Option<Vec<u8>>,
    // If this is true a keyshare for the user will be generated and returned
    extra_private_keys: bool,
    // If true keyshare and verifying key is deterministic
    deterministic_key_share: bool,
) -> (Vec<String>, Vec<PartyId>, Option<KeyShare<KeyParams>>) {
    // spawn threshold servers
    let ports = [3001i64, 3002];

    let (alice_axum, alice_kv) =
        create_clients("validator1".to_string(), vec![], vec![], &Some(ValidatorName::Alice)).await;
    let alice_id = PartyId::new(SubxtAccountId32(
        *get_signer(&alice_kv).await.unwrap().account_id().clone().as_ref(),
    ));

    let (bob_axum, bob_kv) =
        create_clients("validator2".to_string(), vec![], vec![], &Some(ValidatorName::Bob)).await;
    let bob_id = PartyId::new(SubxtAccountId32(
        *get_signer(&bob_kv).await.unwrap().account_id().clone().as_ref(),
    ));

    let user_keyshare_option = if passed_verifying_key.is_some() {
        let number_of_shares = if extra_private_keys { 3 } else { 2 };
        // creates a deterministic keyshare if requiered
        let signing_key = if deterministic_key_share {
            Some(SigningKey::from_bytes((&*DETERMINISTIC_KEY_SHARE).into()).unwrap())
        } else {
            None
        };

        let shares = KeyShare::<KeyParams>::new_centralized(
            &mut OsRng,
            number_of_shares,
            signing_key.as_ref(),
        );
        let validator_1_threshold_keyshare: Vec<u8> =
            entropy_kvdb::kv_manager::helpers::serialize(&shares[0]).unwrap();
        let validator_2_threshold_keyshare: Vec<u8> =
            entropy_kvdb::kv_manager::helpers::serialize(&shares[1]).unwrap();

        // uses the deterministic verifying key if requested
        let verifying_key = if deterministic_key_share {
            hex::encode(shares[0].verifying_key().to_encoded_point(true).as_bytes())
        } else {
            hex::encode(passed_verifying_key.unwrap())
        };

        // add key share to kvdbs
        let alice_reservation = alice_kv.kv().reserve_key(verifying_key.clone()).await.unwrap();
        alice_kv.kv().put(alice_reservation, validator_1_threshold_keyshare).await.unwrap();

        let bob_reservation = bob_kv.kv().reserve_key(verifying_key.clone()).await.unwrap();
        bob_kv.kv().put(bob_reservation, validator_2_threshold_keyshare).await.unwrap();

        if extra_private_keys {
            Some(shares[2].clone())
        } else {
            Some(shares[1].clone())
        }
    } else {
        None
    };

    let listener_alice = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", ports[0]))
        .await
        .expect("Unable to bind to given server address.");
    tokio::spawn(async move {
        axum::serve(listener_alice, alice_axum).await.unwrap();
    });

    let listener_bob = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", ports[1]))
        .await
        .expect("Unable to bind to given server address.");
    tokio::spawn(async move {
        axum::serve(listener_bob, bob_axum).await.unwrap();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let ips = ports.iter().map(|port| format!("127.0.0.1:{port}")).collect();
    let ids = vec![alice_id, bob_id];
    (ips, ids, user_keyshare_option)
}
