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

use anyhow::ensure;
use clap::{Parser, Subcommand};
use colored::Colorize;
use entropy_testing_utils::{
    chain_api::{
        entropy::runtime_types::{
            bounded_collections::bounded_vec::BoundedVec, pallet_registry::pallet::ProgramInstance,
        },
        EntropyConfig,
    },
    constants::TEST_PROGRAM_WASM_BYTECODE,
    test_client::{
        derive_static_secret, get_accounts, get_api, get_programs, get_rpc, register, sign,
        store_program, update_programs, KeyParams, KeyShare, KeyVisibility,
    },
};
use sp_core::{sr25519, Hasher, Pair};
use sp_runtime::traits::BlakeTwo256;
use subxt::{
    backend::legacy::LegacyRpcMethods,
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
        /// Either hex-encoded hashes of existing programs, or paths to wasm files to store.
        ///
        /// Specifying program configurations
        ///
        /// If there exists a file in the current directory of the same name or hex hash and
        /// a '.json' extension, it will be read and used as the configuration for that program.
        ///
        /// If the path to a wasm file is given, and there is a file with the same name with a
        /// '.interface-description' extension, it will be stored as that program's configuration
        /// interface. If no such file exists, it is assumed the program has no configuration
        /// interface.
        programs: Vec<String>,
    },
    /// Ask the network to sign a given message
    Sign {
        /// A name from which to generate a keypair, eg: "Alice"
        ///
        /// Optionally may be preceeded with "//", eg: "//Alice"
        user_account_name: String,
        /// The verifying key of the account to sign with
        #[arg(short, long)]
        signature_verifying_key: Vec<u8>,
        /// The message to be signed
        message: String,
        /// Optional auxiliary data passed to the program, given as hex
        auxilary_data: Option<String>,
    },
    /// Update the program for a particular account
    UpdatePrograms {
        /// The verifying key of the account to update their programs
        signature_verifying_key: Vec<u8>,
        /// A name from which to generate a program modification keypair, eg: "Bob"
        ///
        /// Optionally may be preceeded with "//", eg: "//Bob"
        program_account_name: String,
        /// Either hex-encoded program hashes, or paths to wasm files to store.
        ///
        /// Specifying program configurations
        ///
        /// If there exists a file in the current directory of the same name or hex hash and
        /// a '.json' extension, it will be read and used as the configuration for that program.
        ///
        /// If the path to a wasm file is given, and there is a file with the same name with a
        /// '.interface-description' extension, it will be stored as that program's configuration
        /// interface. If no such file exists, it is assumed the program has no configuration
        /// interface.
        programs: Vec<String>,
    },
    /// Store a given program on chain
    StoreProgram {
        /// A name from which to generate a keypair, eg: "Alice"
        ///
        /// Optionally may be preceeded with "//", eg: "//Alice"
        deployer_name: String,
        /// The path to a .wasm file containing the program (defaults to a test program)
        program_file: Option<PathBuf>,
        /// The path to a file containing the program config interface (defaults to empty)
        config_interface_file: Option<PathBuf>,
        /// The path to a file containing the program aux interface (defaults to empty)
        aux_data_interface_file: Option<PathBuf>,
    },
    /// Display a list of registered Entropy accounts
    Status,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Default)]
enum Visibility {
    /// User holds keyshare
    Private,
    /// User does not hold a keyshare
    #[default]
    Public,
}

impl From<KeyVisibility> for Visibility {
    fn from(key_visibility: KeyVisibility) -> Self {
        match key_visibility {
            KeyVisibility::Private(_) => Visibility::Private,
            KeyVisibility::Public => Visibility::Public,
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
            println!("Signature request account: {}", signature_request_keypair.public());

            let program_keypair: sr25519::Pair =
                SeedString::new(program_account_name).try_into()?;
            let program_account = SubxtAccountId32(program_keypair.public().0);
            println!("Program account: {}", program_keypair.public());

            let key_visibility_converted = match key_visibility {
                Visibility::Private => {
                    let x25519_secret = derive_static_secret(&signature_request_keypair);
                    let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);
                    KeyVisibility::Private(x25519_public.to_bytes())
                },
                Visibility::Public => KeyVisibility::Public,
            };
            let mut programs_info = vec![];

            for program in programs {
                programs_info.push(
                    Program::from_hash_or_filename(&api, &rpc, &program_keypair, program).await?.0,
                );
            }

            let (registered_info, keyshare_option) = register(
                &api,
                &rpc,
                signature_request_keypair.clone(),
                program_account,
                key_visibility_converted,
                BoundedVec(programs_info),
            )
            .await?;

            // If we got a keyshare, write it to a file
            if let Some(keyshare) = keyshare_option {
                KeyShareFile::new(signature_request_keypair.public()).write(keyshare)?;
            }

            Ok(format!("{:?}", registered_info))
        },
        CliCommand::Sign { user_account_name, signature_verifying_key, message, auxilary_data } => {
            let user_keypair: sr25519::Pair = SeedString::new(user_account_name).try_into()?;
            println!("User account: {}", user_keypair.public());

            let auxilary_data =
                if let Some(data) = auxilary_data { Some(hex::decode(data)?) } else { None };

            // If we have a keyshare file for this account, get it
            let private_keyshare = KeyShareFile::new(user_keypair.public()).read().ok();

            let recoverable_signature = sign(
                &api,
                &rpc,
                user_keypair,
                signature_verifying_key,
                message.as_bytes().to_vec(),
                private_keyshare,
                auxilary_data,
            )
            .await?;
            Ok(format!("Message signed: {:?}", recoverable_signature))
        },
        CliCommand::StoreProgram {
            deployer_name,
            program_file,
            config_interface_file,
            aux_data_interface_file,
        } => {
            let keypair: sr25519::Pair = SeedString::new(deployer_name).try_into()?;
            println!("Storing program using account: {}", keypair.public());

            let program = match program_file {
                Some(file_name) => fs::read(file_name)?,
                None => TEST_PROGRAM_WASM_BYTECODE.to_owned(),
            };

            let config_interface = match config_interface_file {
                Some(file_name) => fs::read(file_name)?,
                None => vec![],
            };

            let aux_data_interface = match aux_data_interface_file {
                Some(file_name) => fs::read(file_name)?,
                None => vec![],
            };

            let hash =
                store_program(&api, &rpc, &keypair, program, config_interface, aux_data_interface)
                    .await?;
            Ok(format!("Program stored {hash}"))
        },
        CliCommand::UpdatePrograms { signature_verifying_key, program_account_name, programs } => {
            let program_keypair: sr25519::Pair =
                SeedString::new(program_account_name).try_into()?;
            println!("Program account: {}", program_keypair.public());

            let mut programs_info = Vec::new();
            for program in programs {
                programs_info.push(
                    Program::from_hash_or_filename(&api, &rpc, &program_keypair, program).await?.0,
                );
            }

            update_programs(
                &api,
                &rpc,
                signature_verifying_key,
                &program_keypair,
                BoundedVec(programs_info),
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
                    "{:<48} {:<12} {:<66} Programs:",
                    "Signature request account ID:".green(),
                    "Visibility:".purple(),
                    "Verifying key: ".cyan(),
                );
                for (account_id, info) in accounts {
                    let visibility: Visibility = info.key_visibility.0.into();
                    println!(
                        "{} {:<12} {}",
                        format!("{:?}", account_id.to_vec()).green(),
                        format!("{}", visibility).purple(),
                        format!(
                            "{:?}",
                            info.programs_data
                                .0
                                .iter()
                                .map(|program_instance| format!(
                                    "{}",
                                    program_instance.program_pointer
                                ))
                                .collect::<Vec<_>>()
                        )
                        .white(),
                    );
                }
            }

            let programs = get_programs(&api, &rpc).await?;

            println!("\nThere are {} stored programs\n", programs.len().to_string().green());

            if !programs.is_empty() {
                println!(
                    "{:<11} {:<48} {:<11} {:<14} {} {}",
                    "Hash".blue(),
                    "Stored by:".green(),
                    "Times used:".purple(),
                    "Size in bytes:".cyan(),
                    "Configurable?".yellow(),
                    "Has auxiliary?".yellow(),
                );
                for (hash, program_info) in programs {
                    println!(
                        "{} {} {:>11} {:>14} {} {}",
                        hash,
                        program_info.deployer,
                        program_info.ref_counter,
                        program_info.bytecode.len(),
                        !program_info.configuration_schema.is_empty(),
                        !program_info.auxiliary_data_schema.is_empty(),
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

struct Program(ProgramInstance);

impl Program {
    fn new(program_pointer: H256, program_config: Vec<u8>) -> Self {
        Self(ProgramInstance { program_pointer, program_config })
    }

    async fn from_hash_or_filename(
        api: &OnlineClient<EntropyConfig>,
        rpc: &LegacyRpcMethods<EntropyConfig>,
        keypair: &sr25519::Pair,
        hash_or_filename: String,
    ) -> anyhow::Result<Self> {
        match hex::decode(hash_or_filename.clone()) {
            Ok(hash) => {
                let hash_32_res: Result<[u8; 32], _> = hash.try_into();
                match hash_32_res {
                    Ok(hash_32) => {
                        // If there is a file called <hash as hex>.json use that as the
                        // configuration:
                        let configuration = {
                            let mut configuration_file = PathBuf::from(&hash_or_filename);
                            configuration_file.set_extension("json");
                            fs::read(&configuration_file).unwrap_or_default()
                        };
                        Ok(Self::new(H256(hash_32), configuration))
                    },
                    Err(_) => Self::from_file(api, rpc, keypair, hash_or_filename).await,
                }
            },
            Err(_) => Self::from_file(api, rpc, keypair, hash_or_filename).await,
        }
    }

    /// Given a path to a .wasm file, read it, store the program if it doesn't already exist, and
    /// return the hash.
    async fn from_file(
        api: &OnlineClient<EntropyConfig>,
        rpc: &LegacyRpcMethods<EntropyConfig>,
        keypair: &sr25519::Pair,
        filename: String,
    ) -> anyhow::Result<Self> {
        let program_bytecode = fs::read(&filename)?;

        // If there is a file with the same name with the '.config-description' extension, read it
        let config_description = {
            let mut config_description_file = PathBuf::from(&filename);
            config_description_file.set_extension("config-description");
            fs::read(&config_description_file).unwrap_or_default()
        };

        // If there is a file with the same name with the '.aux-description' extension, read it
        let auxiliary_data_schema = {
            let mut auxiliary_data_schema_file = PathBuf::from(&filename);
            auxiliary_data_schema_file.set_extension("aux-description");
            fs::read(&auxiliary_data_schema_file).unwrap_or_default()
        };

        // If there is a file with the same name with the '.json' extension, read it
        let configuration = {
            let mut configuration_file = PathBuf::from(&filename);
            configuration_file.set_extension("json");
            fs::read(&configuration_file).unwrap_or_default()
        };

        ensure!(
            (config_description.is_empty() && configuration.is_empty())
                || (!config_description.is_empty() && !configuration.is_empty()),
            "If giving an interface description you must also give a configuration"
        );

        match store_program(
            api,
            rpc,
            keypair,
            program_bytecode.clone(),
            config_description,
            auxiliary_data_schema,
        )
        .await
        {
            Ok(hash) => Ok(Self::new(hash, configuration)),
            Err(error) => {
                if error.to_string().ends_with("ProgramAlreadySet") {
                    println!("Program is already stored - using existing one");
                    let hash = BlakeTwo256::hash(&program_bytecode);
                    Ok(Self::new(H256(hash.into()), configuration))
                } else {
                    Err(error)
                }
            },
        }
    }
}
