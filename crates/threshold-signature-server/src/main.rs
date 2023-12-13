use std::{net::SocketAddr, str::FromStr};

use clap::Parser;

use entropy_tss::{
    app,
    launch::{
        load_kv_store, setup_latest_block_number, setup_mnemonic, Configuration, StartupArgs,
        ValidatorName,
    },
    sync_validator, AppState,
};

#[tokio::main]
async fn main() {
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
    let kv_store = load_kv_store(&validator_name, args.password_file).await;

    let app_state = AppState::new(configuration.clone(), kv_store.clone());
    setup_mnemonic(&kv_store, &validator_name).await.expect("Issue creating Mnemonic");
    setup_latest_block_number(&kv_store).await.expect("Issue setting up Latest Block Number");

    // Below deals with syncing the kvdb
    sync_validator(args.sync, args.dev, &configuration.endpoint, &kv_store).await;
    let addr = SocketAddr::from_str(&args.threshold_url).expect("failed to parse threshold url.");

    axum::Server::bind(&addr)
        .serve(app(app_state).into_make_service())
        .await
        .expect("failed to launch axum server.");
}
