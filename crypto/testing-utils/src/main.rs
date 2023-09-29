//! Simple CLI to test registering
use clap::{Parser, Subcommand};
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32 as SubxtAccountId32;
use testing_utils::test_client::{get_api, register, KeyVisibility};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
#[clap(about = "Test tool for Entropy")]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    #[arg(short, long)]
    chain_endpoint: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    /// Register with Entropy and create shares
    Register { account: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let default_endpoint_addr = "ws://localhost:5001".to_string();
    let endpoint_addr = cli.chain_endpoint.unwrap_or(default_endpoint_addr);

    match cli.command {
        CliCommand::Register { account } => {
            let seed = [1; 32];
            let sig_req_keypair = sr25519::Pair::from_seed(&seed);
            let api = get_api(endpoint_addr).await?;
            let constraint_account = SubxtAccountId32([0; 32]);
            let key_visibility = KeyVisibility::Public;
            match register(&api, sig_req_keypair, constraint_account, key_visibility).await {
                Ok(register_status) => {
                    println!("Registered {:?}", register_status);
                },
                Err(err) => {
                    println!("Error {:?}", err);
                },
            }
        },
    };
    Ok(())
}
