//! Simple CLI to test registering, updating programs and signing
use std::{fs, path::PathBuf, time::Instant};

use clap::{Parser, Subcommand};
use colored::Colorize;
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32 as SubxtAccountId32;
use testing_utils::{
    constants::{AUXILARY_DATA_SHOULD_SUCCEED, TEST_PROGRAM_WASM_BYTECODE},
    test_client::{
        derive_static_secret, get_accounts, get_api, get_rpc, register, sign, update_program,
        KeyVisibility,
    },
};

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
        /// A file containing an initial program for the account (defaults to test program)
        program_file: Option<PathBuf>,
    },
    /// Ask the network to sign a given message
    Sign {
        /// A name from which to generate a keypair
        signature_request_account_name: String,
        /// A hex encoded message
        message_hex: String,
        /// Optional auxiliary data passed to the program, given as hex
        auxilary_data: Option<String>,
    },
    /// Update the program for a particular account
    UpdateProgram {
        /// A name from which to generate a signature request keypair
        signature_request_account_name: String,
        /// A name from which to generate a program modification keypair
        program_account_name: String,
        /// The path to a .wasm file containing the program (defaults to test program)
        program_file: Option<PathBuf>,
    },
    /// Display a list of registered entropy accounts
    Status,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum Visibility {
    /// Anyone can submit a signature request (default)
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
            program_file,
        } => {
            let signature_request_keypair: sr25519::Pair =
                SeedString::new(signature_request_account_name).try_into()?;
            println!("Signature request account: {:?}", signature_request_keypair.public());

            let program_keypair: sr25519::Pair =
                SeedString::new(program_account_name).try_into()?;
            let program_account = SubxtAccountId32(program_keypair.public().0);
            println!("Program account: {:?}", program_keypair.public());

            let key_visibility_converted = match key_visibility {
                Some(Visibility::Permissioned) => KeyVisibility::Permissioned,
                Some(Visibility::Private) => {
                    let x25519_secret = derive_static_secret(&signature_request_keypair);
                    let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);
                    KeyVisibility::Private(x25519_public.to_bytes())
                },
                _ => KeyVisibility::Public,
            };

            let program = match program_file {
                Some(file_name) => fs::read(file_name)?,
                // This is temporary - if empty programs are allowed it can be None
                None => TEST_PROGRAM_WASM_BYTECODE.to_owned(),
            };

            let register_status = register(
                &api,
                &rpc,
                signature_request_keypair,
                program_account,
                key_visibility_converted,
                program,
            )
            .await?;
            Ok(format!("{:?}", register_status))
        },
        CliCommand::Sign { signature_request_account_name, message_hex, auxilary_data } => {
            let signature_request_keypair: sr25519::Pair =
                SeedString::new(signature_request_account_name).try_into()?;
            println!("Signature request account: {:?}", signature_request_keypair.public());

            let message = hex::decode(message_hex)?;
            let auxilary_data = if let Some(data) = auxilary_data {
                Some(hex::decode(data)?)
            } else {
                // This is temporary for testing with the test program
                Some(AUXILARY_DATA_SHOULD_SUCCEED.to_vec())
            };
            let recoverable_signature =
                sign(&api, &rpc, signature_request_keypair, message, None, auxilary_data).await?;
            Ok(format!("Message signed: {:?}", recoverable_signature))
        },
        CliCommand::UpdateProgram {
            signature_request_account_name,
            program_account_name,
            program_file,
        } => {
            let signature_request_keypair: sr25519::Pair =
                SeedString::new(signature_request_account_name).try_into()?;
            println!("Signature request account: {:?}", signature_request_keypair.public());
            let sig_req_account = SubxtAccountId32(signature_request_keypair.public().0);

            let program = match program_file {
                Some(file_name) => fs::read(file_name)?,
                None => TEST_PROGRAM_WASM_BYTECODE.to_owned(),
            };

            let program_keypair: sr25519::Pair =
                SeedString::new(program_account_name).try_into()?;
            update_program(&api, sig_req_account, &program_keypair, program).await?;
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
    }
}

/// A string from which to generate a sr25519 keypair for test accounts
#[derive(Clone)]
struct SeedString(String);

impl SeedString {
    fn new(seed_string: String) -> Self {
        Self(if seed_string.starts_with("//") { seed_string } else { format!("//{}", seed_string) })
    }
}

impl TryFrom<SeedString> for sr25519::Pair {
    type Error = anyhow::Error;

    fn try_from(seed_string: SeedString) -> Result<Self, Self::Error> {
        let (keypair, _) = sr25519::Pair::from_string_with_seed(&seed_string.0, None)?;
        Ok(keypair)
    }
}
