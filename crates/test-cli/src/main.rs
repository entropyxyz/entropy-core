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

//! Simple CLI to test registering, updating programs and signing
use std::{
    fmt::{self, Display},
    fs,
    path::PathBuf,
    time::Instant,
};

use clap::{Parser, Subcommand};
use colored::Colorize;
use entropy_testing_utils::{
    chain_api::{
        entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec, EntropyConfig,
    },
    constants::{AUXILARY_DATA_SHOULD_SUCCEED, TEST_PROGRAM_WASM_BYTECODE},
    test_client::{
        derive_static_secret, get_accounts, get_api, get_rpc, register, sign, store_program,
        update_programs, KeyParams, KeyShare, KeyVisibility,
    },
};
use sp_core::{sr25519, Pair};
use subxt::{
    utils::{AccountId32 as SubxtAccountId32, H256},
    OnlineClient,
};

#[derive(Parser, Debug, Clone)]
#[clap(
    version,
    about = "CLI tool for testing Entropy",
    long_about = "This is a CLI test client.\nIt requires a running deployment of Entropy with at least two chain nodes and two TSS servers."
)]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    /// The chain endpoint to use.
    ///
    /// The format should be in the form of `scheme://hostname:port`.
    ///
    /// Default to `ws://localhost:9944`. If a value exists for `ENTROPY_DEVNET`, that takes
    /// priority.
    #[arg(short, long)]
    chain_endpoint: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    /// Register with Entropy and create keyshares
    Register {
        /// A name from which to generate a signature request keypair, eg: "Alice"
        ///
        /// Optionally may be preceeded with "//", eg: "//Alice"
        signature_request_account_name: String,
        /// A name from which to generate a program modification keypair, eg: "Bob"
        ///
        /// Optionally may be preceeded with "//" eg: "//Bob"
        program_account_name: String,
        /// The access mode of the Entropy account
        #[arg(value_enum, default_value_t = Default::default())]
        key_visibility: Visibility,
        /// Either hex-encoded hashes, or paths to wasm files to store
        programs: Vec<String>,
    },
    /// Ask the network to sign a given message
    Sign {
        /// A name from which to generate a keypair, eg: "Alice"
        ///
        /// Optionally may be preceeded with "//", eg: "//Alice"
        signature_request_account_name: String,
        /// The message to be signed
        message: String,
        /// Optional auxiliary data passed to the program, given as hex
        auxilary_data: Option<String>,
    },
    /// Update the program for a particular account
    UpdatePrograms {
        /// A name from which to generate a signature request keypair, eg: "Alice"
        ///
        /// Optionally may be preceeded with "//", eg: "//Alice"
        signature_request_account_name: String,
        /// A name from which to generate a program modification keypair, eg: "Bob"
        ///
        /// Optionally may be preceeded with "//", eg: "//Bob"
        program_account_name: String,
        /// Either hex-encoded program hashes, or paths to wasm files to store
        programs: Vec<String>,
    },
    /// Store a given program on chain
    StoreProgram {
        /// A name from which to generate a keypair, eg: "Alice"
        ///
        /// Optionally may be preceeded with "//", eg: "//Alice"
        account_name: String,
        /// The path to a .wasm file containing the program (defaults to a test program)
        program_file: Option<PathBuf>,
    },
    /// Display a list of registered Entropy accounts
    Status,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Default)]
enum Visibility {
    /// Anyone can submit a signature request (default)
    #[default]
    Public,
    /// Only the user who registers can submit a signature request
    Private,
    /// The program defines who may submit a signature request
    Permissioned,
}

impl From<KeyVisibility> for Visibility {
    fn from(key_visibility: KeyVisibility) -> Self {
        match key_visibility {
            KeyVisibility::Public => Visibility::Public,
            KeyVisibility::Private(_) => Visibility::Private,
            KeyVisibility::Permissioned => Visibility::Permissioned,
        }
    }
}

impl Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
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
            programs,
        } => {
            let signature_request_keypair: sr25519::Pair =
                SeedString::new(signature_request_account_name).try_into()?;
            println!("Signature request account: {:?}", signature_request_keypair.public());

            let program_keypair: sr25519::Pair =
                SeedString::new(program_account_name).try_into()?;
            let program_account = SubxtAccountId32(program_keypair.public().0);
            println!("Program account: {:?}", program_keypair.public());

            let key_visibility_converted = match key_visibility {
                Visibility::Permissioned => KeyVisibility::Permissioned,
                Visibility::Private => {
                    let x25519_secret = derive_static_secret(&signature_request_keypair);
                    let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);
                    KeyVisibility::Private(x25519_public.to_bytes())
                },
                Visibility::Public => KeyVisibility::Public,
            };

            let mut program_hashes = Vec::new();
            for program in programs {
                program_hashes.push(Program::new(&api, &program_keypair, program).await?.0)
            }

            let (registered_info, keyshare_option) = register(
                &api,
                &rpc,
                signature_request_keypair.clone(),
                program_account,
                key_visibility_converted,
                BoundedVec(program_hashes),
            )
            .await?;

            // If we got a keyshare, write it to a file
            if let Some(keyshare) = keyshare_option {
                KeyShareFile::new(signature_request_keypair.public()).write(keyshare)?;
            }

            Ok(format!("{:?}", registered_info))
        },
        CliCommand::Sign { signature_request_account_name, message, auxilary_data } => {
            let signature_request_keypair: sr25519::Pair =
                SeedString::new(signature_request_account_name).try_into()?;
            println!("Signature request account: {:?}", signature_request_keypair.public());

            let auxilary_data = if let Some(data) = auxilary_data {
                Some(hex::decode(data)?)
            } else {
                // This is temporary for testing with the test program
                Some(AUXILARY_DATA_SHOULD_SUCCEED.to_vec())
            };

            // If we have a keyshare file for this account, get it
            let private_keyshare =
                KeyShareFile::new(signature_request_keypair.public()).read().ok();

            let recoverable_signature = sign(
                &api,
                &rpc,
                signature_request_keypair,
                message.as_bytes().to_vec(),
                private_keyshare,
                auxilary_data,
            )
            .await?;
            Ok(format!("Message signed: {:?}", recoverable_signature))
        },
        CliCommand::StoreProgram { account_name, program_file } => {
            let keypair: sr25519::Pair = SeedString::new(account_name).try_into()?;
            println!("Storing program using account: {:?}", keypair.public());

            let program = match program_file {
                Some(file_name) => fs::read(file_name)?,
                None => TEST_PROGRAM_WASM_BYTECODE.to_owned(),
            };

            let hash = store_program(&api, &keypair, program).await?;
            Ok(format!("Program updated {hash}"))
        },
        CliCommand::UpdatePrograms {
            signature_request_account_name,
            program_account_name,
            programs,
        } => {
            let signature_request_keypair: sr25519::Pair =
                SeedString::new(signature_request_account_name).try_into()?;
            println!("Signature request account: {:?}", signature_request_keypair.public());

            let program_keypair: sr25519::Pair =
                SeedString::new(program_account_name).try_into()?;
            println!("Program account: {:?}", program_keypair.public());

            let mut program_hashes = Vec::new();
            for program in programs {
                program_hashes.push(Program::new(&api, &program_keypair, program).await?.0)
            }

            update_programs(
                &api,
                &rpc,
                &signature_request_keypair,
                &program_keypair,
                BoundedVec(program_hashes),
            )
            .await?;

            Ok("Programs updated".to_string())
        },
        CliCommand::Status => {
            let accounts = get_accounts(&api, &rpc).await?;
            println!(
                "There are {} registered Entropy accounts.\n",
                accounts.len().to_string().green()
            );
            if !accounts.is_empty() {
                println!(
                    "{:<48} {:<12} {}",
                    "Signature request account ID:".green(),
                    "Visibility:".purple(),
                    "Verifying key: ".cyan()
                );
                for (account_id, info) in accounts {
                    let visibility: Visibility = info.key_visibility.0.into();
                    println!(
                        "{} {:<12} {}",
                        format!("{}", account_id).green(),
                        format!("{}", visibility).purple(),
                        format!("{:?}", info.verifying_key.0).cyan()
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

/// Represents a keyshare stored in a file, serialized using [bincode]
struct KeyShareFile(String);

impl KeyShareFile {
    fn new(public_key: sr25519::Public) -> Self {
        Self(format!("keyshare-{}", hex::encode(public_key.0)))
    }

    fn read(&self) -> anyhow::Result<KeyShare<KeyParams>> {
        let keyshare_vec = fs::read(&self.0)?;
        println!("Reading keyshare from file: {}", self.0);
        Ok(bincode::deserialize(&keyshare_vec)?)
    }

    fn write(&self, keyshare: KeyShare<KeyParams>) -> anyhow::Result<()> {
        println!("Writing keyshare to file: {}", self.0);
        let keyshare_vec = bincode::serialize(&keyshare)?;
        Ok(fs::write(&self.0, keyshare_vec)?)
    }
}

struct Program(H256);

impl Program {
    async fn new(
        api: &OnlineClient<EntropyConfig>,
        keypair: &sr25519::Pair,
        hash_or_filename: String,
    ) -> anyhow::Result<Self> {
        match hex::decode(hash_or_filename.clone()) {
            Ok(hash) => {
                let hash_32_res: Result<[u8; 32], _> = hash.try_into();
                match hash_32_res {
                    Ok(hash_32) => Ok(Self(H256(hash_32))),
                    Err(_) => Self::from_filename(api, keypair, hash_or_filename).await,
                }
            },
            Err(_) => Self::from_filename(api, keypair, hash_or_filename).await,
        }
    }

    async fn from_filename(
        api: &OnlineClient<EntropyConfig>,
        keypair: &sr25519::Pair,
        filename: String,
    ) -> anyhow::Result<Self> {
        let program_bytecode = fs::read(filename)?;
        let hash = store_program(api, keypair, program_bytecode).await?;
        Ok(Self(hash))
    }
}
