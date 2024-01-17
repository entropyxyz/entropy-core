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

use std::{net::SocketAddr, str::FromStr};

use clap::Parser;

use entropy_tss::{
    app,
    launch::{
        load_kv_store, setup_latest_block_number, setup_mnemonic, setup_only, Configuration,
        StartupArgs, ValidatorName,
    },
    sync_validator, AppState,
};

#[tokio::main]
async fn main() {
    let args = StartupArgs::parse();
    args.logger.setup().await;

    if !args.setup_only {
        tracing::info!("Starting Threshold Signature Sever");
        tracing::info!("Starting server on: `{}`", &args.threshold_url);
    }

    if args.logger.loki {
        tracing::info!("Sending logs to Loki server at `{}`", &args.logger.loki_endpoint);
    }

    let configuration = Configuration::new(args.chain_endpoint);
    if !args.setup_only {
        tracing::info!("Connecting to Substrate node at: `{}`", &configuration.endpoint);
    }

    let mut validator_name = None;
    if args.alice {
        validator_name = Some(ValidatorName::Alice);
    }
    if args.bob {
        validator_name = Some(ValidatorName::Bob);
    }
    let kv_store = load_kv_store(&validator_name, args.password_file).await;

    let app_state = AppState::new(configuration.clone(), kv_store.clone());
    setup_mnemonic(&kv_store, &validator_name).await.expect("Issue creating Mnemonic");
    setup_latest_block_number(&kv_store).await.expect("Issue setting up Latest Block Number");

    // Below deals with syncing the kvdb
    sync_validator(args.sync, args.dev, &configuration.endpoint, &kv_store).await;
    let addr = SocketAddr::from_str(&args.threshold_url).expect("failed to parse threshold url.");

    if args.setup_only {
        setup_only(&kv_store).await;
    } else {
        axum::Server::bind(&addr)
            .serve(app(app_state).into_make_service())
            .await
            .expect("failed to launch axum server.");
    }
}
