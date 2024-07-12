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

use entropy_shared::MIN_BALANCE;
use entropy_tss::{
    app,
    chain_api::{get_api, get_rpc},
    launch::{
        development_mnemonic, load_kv_store, setup_latest_block_number, setup_mnemonic, setup_only,
        Configuration, StartupArgs, ValidatorName,
    },
    validator::api::check_balance_for_fees,
    AppState,
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
    if args.charlie {
        validator_name = Some(ValidatorName::Charlie);
    }
    if args.dave {
        validator_name = Some(ValidatorName::Dave);
    }
    if args.eve {
        validator_name = Some(ValidatorName::Eve);
    }

    let kv_store = load_kv_store(&validator_name, args.password_file).await;

    let app_state = AppState::new(configuration.clone(), kv_store.clone());

    // We consider the inputs in order of most to least explicit: CLI flag, supplied file,
    // environment variable.
    let user_mnemonic = args
        .mnemonic
        .or_else(|| {
            args.mnemonic_file.map(|path| {
                let file = std::fs::read(path).expect("Unable to read mnemonic file.");
                let mnemonic = std::str::from_utf8(&file)
                    .expect("Unable to convert provided mnemonic to UTF-8 string.")
                    .trim();

                bip39::Mnemonic::parse_normalized(mnemonic)
                    .expect("Unable to parse given mnemonic.")
            })
        })
        .or_else(|| {
            std::env::var("THRESHOLD_SERVER_MNEMONIC").ok().map(|mnemonic| {
                bip39::Mnemonic::parse_normalized(&mnemonic)
                    .expect("Unable to parse given mnemonic.")
            })
        });

    let account_id = if let Some(mnemonic) = user_mnemonic {
        setup_mnemonic(&kv_store, mnemonic).await
    } else if cfg!(test) || validator_name.is_some() {
        setup_mnemonic(&kv_store, development_mnemonic(&validator_name)).await
    } else {
        let has_mnemonic = entropy_tss::launch::has_mnemonic(&kv_store).await;
        assert!(
            has_mnemonic,
            "No mnemonic provided. Please provide one or use a development account."
        );

        entropy_tss::launch::threshold_account_id(&kv_store).await
    };

    setup_latest_block_number(&kv_store).await.expect("Issue setting up Latest Block Number");

    // Below deals with syncing the kvdb
    let addr = SocketAddr::from_str(&args.threshold_url).expect("failed to parse threshold url.");

    if args.setup_only {
        setup_only(&kv_store).await;
    } else {
        let connect_to_substrate_node = || async {
            tracing::info!(
                "Attempting to establish connection to Substrate node at `{}`",
                &app_state.configuration.endpoint
            );

            let api = get_api(&app_state.configuration.endpoint).await.map_err(|_| {
                Err::<(), String>("Unable to connect to Substrate chain API".to_string())
            })?;

            let rpc = get_rpc(&app_state.configuration.endpoint)
                .await
                .map_err(|_| Err("Unable to connect to Substrate chain RPC".to_string()))?;

            Ok((api, rpc))
        };

        let backoff = backoff::ExponentialBackoffBuilder::default()
            .with_max_elapsed_time(Some(std::time::Duration::from_secs(60)))
            .build();
        match backoff::future::retry(backoff, connect_to_substrate_node).await {
            Ok((api, rpc)) => {
                tracing::info!("Sucessfully connected to Substrate node!");

                tracing::info!("Checking balance of threshold server AccountId `{}`", &account_id);
                let balance_query =
                    check_balance_for_fees(&api, &rpc, account_id.clone(), MIN_BALANCE)
                        .await
                        .map_err(|_| {
                            Err::<bool, String>("Failed to get balance of account.".to_string())
                        });

                match balance_query {
                    Ok(has_minimum_balance) => {
                        if has_minimum_balance {
                            tracing::info!(
                                "The account `{}` has enough funds for submitting extrinsics.",
                                &account_id
                            )
                        } else {
                            tracing::warn!(
                                "The account `{}` does not meet the minimum balance of `{}`",
                                &account_id,
                                MIN_BALANCE
                            )
                        }
                    },
                    Err(_) => {
                        tracing::warn!("Unable to query the account balance of `{}`", &account_id)
                    },
                }
            },
            Err(_err) => {
                tracing::error!(
                    "Unable to establish connection with Substrate node at `{}`",
                    &app_state.configuration.endpoint
                );
                panic!("Unable to establish connection with Substrate node.");
            },
        }

        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .expect("Unable to bind to given server address.");
        axum::serve(listener, app(app_state).into_make_service())
            .await
            .expect("failed to launch axum server.");
    }
}
