//! Simple CLI to test registering
use clap::{Parser, Subcommand};
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32 as SubxtAccountId32;
use testing_utils::{
    constants::BAREBONES_PROGRAM_WASM_BYTECODE,
    test_client::{get_api, register, sign, update_program, KeyVisibility},
};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
#[clap(about = "Test tool for Entropy")]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    /// The chain endpoint to use eg: ws://blah:9944
    #[arg(short, long)]
    chain_endpoint: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    /// Register with Entropy and create shares
    Register {
        /// A name from which to generate a keypair
        account_name: String,
        // #[arg(value_enum)]
        // key_visibility: KeyVisibility,
    },
    Sign {
        /// A name from which to generate a keypair
        account_name: String,
        /// A hex encoded message
        message_hex: String,
    },
    UpdateProgram {
        /// A name from which to generate a keypair
        account_name: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let default_endpoint_addr = "ws://localhost:9944".to_string();
    let endpoint_addr = cli.chain_endpoint.unwrap_or(default_endpoint_addr);

    match cli.command {
        CliCommand::Register { account_name } => {
            let (sig_req_keypair, _) =
                sr25519::Pair::from_string_with_seed(&format!("//{}", account_name), None)?;
            let api = get_api(endpoint_addr).await?;
            println!("Signature request account: {:?}", sig_req_keypair.public());

            let (program_keypair, _) =
                sr25519::Pair::from_string_with_seed(&format!("//{}-program", account_name), None)?;
            let program_account = SubxtAccountId32(program_keypair.public().0);
            println!("Program account: {:?}", program_keypair.public());

            let key_visibility = KeyVisibility::Public;

            match register(&api, sig_req_keypair, program_account, key_visibility, None).await {
                Ok(register_status) => {
                    println!("Registered successfully: {:?}", register_status);
                },
                Err(err) => {
                    println!("Error: {:?}", err);
                },
            }
        },
        CliCommand::Sign { account_name, message_hex } => {
            let (sig_req_keypair, _) =
                sr25519::Pair::from_string_with_seed(&format!("//{}", account_name), None)?;
            let api = get_api(endpoint_addr).await?;
            println!("Signature request account: {:?}", sig_req_keypair.public());
            let message = hex::decode(message_hex)?;
            match sign(&api, sig_req_keypair, message).await {
                Ok(()) => {
                    println!("signed successfully");
                },
                Err(err) => {
                    println!("Error: {:?}", err);
                },
            }
        },
        CliCommand::UpdateProgram { account_name } => {
            let (sig_req_keypair, _) =
                sr25519::Pair::from_string_with_seed(&format!("//{}", account_name), None)?;
            let api = get_api(endpoint_addr).await?;
            println!("Signature request account: {:?}", sig_req_keypair.public());

            let (program_keypair, _) =
                sr25519::Pair::from_string_with_seed(&format!("//{}-program", account_name), None)?;
            println!("Program account: {:?}", program_keypair.public());

            let program = BAREBONES_PROGRAM_WASM_BYTECODE.to_owned();
            match update_program(&api, sig_req_keypair, program_keypair, program).await {
                Ok(()) => {
                    println!("Updated successfully");
                },
                Err(err) => {
                    println!("Error: {:?}", err);
                },
            }
        },
    };
    Ok(())
}
