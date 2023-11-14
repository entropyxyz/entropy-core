//! Simple CLI to test registering, updating programs and signing
use std::time::Instant;

use anyhow::anyhow;
use clap::{Parser, Subcommand};
use colored::Colorize;
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32 as SubxtAccountId32;
use testing_utils::{
    constants::TEST_PROGRAM_WASM_BYTECODE,
    test_client::{
        derive_static_secret, fund_account, get_accounts, get_api, get_rpc, register, sign,
        update_program, KeyVisibility,
    },
};

// This is the name of the environment variable used to store the root seed
const ENTROPY_DEVNET_ROOT_SEED: &str = "ENTROPY_DEVNET_ROOT_SEED";

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
#[clap(about = "Test tool for Entropy devnet")]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    /// The chain endpoint to use eg: "ws://blah:9944". Defaults to the ENTROPY_DEVNET environment
    /// variable
    #[arg(short, long)]
    chain_endpoint: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    /// Register with Entropy and create shares
    Register {
        /// A name from which to generate a signature request keypair
        signature_request_account_name: String,
        /// A name from which to generate a program modification keypair
        program_account_name: String,
        /// Public, Private or Permissioned
        #[arg(value_enum)]
        key_visibility: Option<Visibility>,
    },
    /// Ask the network to sign a given message
    Sign {
        /// A name from which to generate a keypair
        signature_request_account_name: String,
        /// A hex encoded message
        message_hex: String,
    },
    /// Update to the 'barebones' program
    UpdateProgram {
        /// A name from which to generate a signature request keypair
        signature_request_account_name: String,
        /// A name from which to generate a program modification keypair
        program_account_name: String,
        /// The path to a .wasm file containing the program (defaults to barebones program)
        program_file: Option<std::path::PathBuf>,
    },
    /// Display some status information
    Status,
    /// Fund an account with sudo
    FundAccount {
        /// The account name to fund
        account_to_fund: String,
        /// How many Bits to give
        amount: Option<u128>,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum Visibility {
    /// Anyone can submit a signature request
    Public,
    /// Only the user who registers can submit a signautre request
    Private,
    /// The program defines who may submit a signature request
    Permissioned,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let now = Instant::now();
    match run_command().await {
        Ok(output) => {
            println!("Success: {}", output.green());
            println!("{}", format!("That took {:?}", now.elapsed()).yellow());
            Ok(())
        },
        Err(err) => {
            println!("{}", "Failed!".red());
            Err(err)
        },
    }
}

async fn run_command() -> anyhow::Result<String> {
    let cli = Cli::parse();

    let endpoint_addr = cli.chain_endpoint.unwrap_or_else(|| {
        std::env::var("ENTROPY_DEVNET").unwrap_or("ws://localhost:9944".to_string())
    });
    let api = get_api(&endpoint_addr).await?;
    let rpc = get_rpc(&endpoint_addr).await?;

    match cli.command {
        CliCommand::Register {
            signature_request_account_name,
            program_account_name,
            key_visibility,
        } => {
            let sig_req_keypair = account_name_to_keypair(signature_request_account_name.clone())?;
            println!("Signature request account: {:?}", sig_req_keypair.public());

            let program_keypair = account_name_to_keypair(program_account_name)?;
            let program_account = SubxtAccountId32(program_keypair.public().0);
            println!("Program account: {:?}", program_keypair.public());

            let key_visibility_converted = match key_visibility {
                Some(Visibility::Permissioned) => KeyVisibility::Permissioned,
                Some(Visibility::Private) => {
                    let x25519_secret = derive_static_secret(&sig_req_keypair);
                    let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);
                    KeyVisibility::Private(x25519_public.to_bytes())
                },
                _ => KeyVisibility::Public,
            };

            // TODO we should take initial program as an argument
            let initial_program = Vec::new();

            let register_status = register(
                &api,
                &rpc,
                signature_request_account_name,
                program_account,
                key_visibility_converted,
                initial_program,
            )
            .await?;
            Ok(format!("{:?}", register_status))
        },
        CliCommand::Sign { signature_request_account_name, message_hex } => {
            let message = hex::decode(message_hex)?;
            let recoverable_signature =
                sign(&api, signature_request_account_name, message, None).await?;
            Ok(format!("Message signed: {:?}", recoverable_signature))
        },
        CliCommand::UpdateProgram {
            signature_request_account_name,
            program_account_name,
            program_file,
        } => {
            let sig_req_keypair = account_name_to_keypair(signature_request_account_name)?;
            println!("Signature request account: {:?}", sig_req_keypair.public());
            let sig_req_account = SubxtAccountId32(sig_req_keypair.public().0);

            let program = match program_file {
                Some(file_name) => std::fs::read(file_name)?,
                None => TEST_PROGRAM_WASM_BYTECODE.to_owned(),
            };

            update_program(&api, sig_req_account, program_account_name, program).await?;
            Ok("Program updated".to_string())
        },
        CliCommand::Status => {
            let accounts = get_accounts(&api, &rpc).await?;
            println!(
                "There are {} registered Entropy accounts.\n",
                accounts.len().to_string().green()
            );
            if !accounts.is_empty() {
                println!(
                    "{:<64} {:<12} {}",
                    "Signature request account ID:".green(),
                    "Visibility:".purple(),
                    "Verifying key: ".cyan()
                );
                for (key, info) in accounts {
                    println!(
                        "{} {:<12} {}",
                        hex::encode(key).green(),
                        format!("{:?}", info.key_visibility).purple(),
                        hex::encode(info.verifying_key.0).cyan()
                    );
                }
            }
            Ok("Got status".to_string())
        },
        CliCommand::FundAccount { account_to_fund, amount } => {
            let root_keypair = {
                let root_seed_hex = std::env::var(ENTROPY_DEVNET_ROOT_SEED).map_err(|_| {
                    anyhow!(
                        "Root seed must be stored in environment variable {}",
                        ENTROPY_DEVNET_ROOT_SEED
                    )
                })?;
                let root_seed_vec = hex::decode(root_seed_hex)?;
                let root_seed: [u8; 32] = root_seed_vec.try_into().unwrap();
                sr25519::Pair::from_seed(&root_seed)
            };
            let to_fund_keypair = account_name_to_keypair(account_to_fund)?;
            let amount = amount.unwrap_or(100_000);

            fund_account(&api, root_keypair, to_fund_keypair.public().into(), amount).await?;
            Ok("Account funded".to_string())
        },
    }
}

/// Generate an sr2119 keypair from a given seed string
fn account_name_to_keypair(account_name: String) -> anyhow::Result<sr25519::Pair> {
    let account_name =
        if account_name.starts_with("//") { account_name } else { format!("//{}", account_name) };
    let (sig_req_keypair, _) = sr25519::Pair::from_string_with_seed(&account_name, None)?;
    Ok(sig_req_keypair)
}
