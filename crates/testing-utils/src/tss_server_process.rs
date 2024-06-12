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
use entropy_protocol::PartyId;
use entropy_shared::EVE_VERIFYING_KEY;
use entropy_tss::{
    app, get_signer,
    launch::{setup_latest_block_number, setup_mnemonic, Configuration, ValidatorName},
    AppState,
};
use std::time::Duration;
use subxt::utils::AccountId32 as SubxtAccountId32;

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

#[cfg(test)]
const TEST: bool = true;

#[cfg(not(test))]
const TEST: bool = false;

/// Spawn 3 TSS nodes with pre-stored keyshares
pub async fn spawn_testing_validators() -> (Vec<String>, Vec<PartyId>) {
    // spawn threshold servers
    let ports = [3001i64, 3002, 3003];

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

    let (charlie_axum, charlie_kv) =
        create_clients("validator3".to_string(), vec![], vec![], &Some(ValidatorName::Charlie))
            .await;
    let charlie_id = PartyId::new(SubxtAccountId32(
        *get_signer(&charlie_kv).await.unwrap().account_id().clone().as_ref(),
    ));

    let ids = vec![alice_id, bob_id, charlie_id];

    put_keyshare_in_db("alice", alice_kv).await;
    put_keyshare_in_db("bob", bob_kv).await;
    put_keyshare_in_db("charlie", charlie_kv).await;

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

    let listener_charlie = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", ports[2]))
        .await
        .expect("Unable to bind to given server address.");
    tokio::spawn(async move {
        axum::serve(listener_charlie, charlie_axum).await.unwrap();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let ips = ports.iter().map(|port| format!("127.0.0.1:{port}")).collect();
    (ips, ids)
}

pub async fn put_keyshare_in_db(name: &str, kvdb: KvManager) {
    let test_or_production = if TEST { "test" } else { "production" };
    let keyshare_bytes = {
        let project_root = project_root::get_project_root().expect("Error obtaining project root.");
        let file_path = project_root.join(format!(
            "crates/testing-utils/keyshares/{}/eve-keyshare-held-by-{}.keyshare",
            test_or_production, name
        ));
        std::fs::read(file_path).unwrap()
    };
    let reservation = kvdb.kv().reserve_key(hex::encode(EVE_VERIFYING_KEY)).await.unwrap();
    kvdb.kv().put(reservation, keyshare_bytes).await.unwrap();
}
