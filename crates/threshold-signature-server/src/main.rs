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
#![allow(clippy::result_large_err)]
use std::{net::SocketAddr, process, str::FromStr};

use anyhow::anyhow;
use clap::Parser;

use entropy_tss::{
    app,
    launch::{
        get_block_number_and_setup_latest_block_number, setup_kv_store, Configuration, StartupArgs,
        ValidatorName,
    },
    AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = StartupArgs::parse();
    args.logger.setup().await;

    tracing::info!("Starting Threshold Signature Sever");
    tracing::info!("Starting server on: `{}`", &args.threshold_url);

    if args.logger.loki {
        tracing::info!("Sending logs to Loki server at `{}`", &args.logger.loki_endpoint);
    }

    let configuration = Configuration::new(args.chain_endpoint);
    tracing::info!("Connecting to Substrate node at: `{}`", &configuration.endpoint);

    let mut validator_name = None;
    if args.alice {
        validator_name = Some(ValidatorName::Alice);
    }
    if args.bob {
        validator_name = Some(ValidatorName::Bob);
    }
    if args.charlie {
        validator_name = Some(ValidatorName::Charlie);
    }
    if args.dave {
        validator_name = Some(ValidatorName::Dave);
    }
    if args.eve {
        validator_name = Some(ValidatorName::Eve);
    }

    let (kv_store, sr25519_pair, x25519_secret, key_option) =
        setup_kv_store(&validator_name, None).await?;

    let app_state =
        AppState::new(configuration.clone(), kv_store, sr25519_pair, x25519_secret).await;

    {
        let app_state = app_state.clone();
        tokio::spawn(async move {
            // Check for a connection to the chain node parallel to starting the tss_server so that
            // we already can expose the `/info` http route
            if let Err(error) =
                entropy_tss::launch::check_node_prerequisites(app_state.clone(), key_option).await
            {
                tracing::error!("Prerequistite checks failed: {} - terminating.", error);
                process::exit(1);
            }

            if let Err(error) = get_block_number_and_setup_latest_block_number(app_state).await {
                tracing::error!("setup_latest_block_number failed: {} - terminating.", error);
                process::exit(1);
            }
        });
    }

    let addr = SocketAddr::from_str(&args.threshold_url)
        .map_err(|_| anyhow!("Failed to parse threshold url"))?;
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|_| anyhow!("Unable to bind to given server address"))?;
    axum::serve(listener, app(app_state).into_make_service()).await?;
    Ok(())
}
