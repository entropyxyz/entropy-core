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
use anyhow::{anyhow, ensure};
use clap::{Parser, Subcommand};
use colored::Colorize;
use entropy_client::{
    chain_api::{
        entropy::runtime_types::{
            bounded_collections::bounded_vec::BoundedVec, pallet_registry::pallet::ProgramInstance,
        },
        EntropyConfig,
    },
    client::{
        change_endpoint, change_threshold_accounts, get_accounts, get_api, get_programs, get_rpc,
        register, sign, store_program, update_programs, VERIFYING_KEY_LENGTH,
    },
};
use sp_core::{sr25519, Hasher, Pair};
use sp_runtime::traits::BlakeTwo256;
use std::{fs, path::PathBuf};
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
        /// A name or mnemonic from which to derive a program modification keypair.
        /// This is used to send the register extrinsic so it must be funded
        /// If giving a name it must be preceded with "//", eg: "--mnemonic-option //Alice"
        /// If giving a mnemonic it must be enclosed in quotes, eg: "--mnemonic-option "alarm mutual concert...""  
        #[arg(short, long)]
        mnemonic_option: Option<String>,
    },
    /// Ask the network to sign a given message
    Sign {
        /// The verifying key of the account to sign with, given as hex
        signature_verifying_key: String,
        /// The message to be signed
        message: String,
        /// Optional auxiliary data passed to the program, given as hex
        auxilary_data: Option<String>,
        /// The mnemonic to use for the call
        mnemonic_option: Option<String>,
    },
    /// Update the program for a particular account
    UpdatePrograms {
        /// The verifying key of the account to update their programs, given as hex
        signature_verifying_key: String,
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
        /// The mnemonic to use for the call
        #[arg(short, long)]
        mnemonic_option: Option<String>,
    },
    /// Store a given program on chain
    StoreProgram {
        /// The path to a .wasm file containing the program (defaults to a test program)
        program_file: Option<PathBuf>,
        /// The path to a file containing the program config interface (defaults to empty)
        config_interface_file: Option<PathBuf>,
        /// The path to a file containing the program aux interface (defaults to empty)
        aux_data_interface_file: Option<PathBuf>,
        /// The mnemonic to use for the call
        #[arg(short, long)]
        mnemonic_option: Option<String>,
    },
    /// Allows a validator to change their endpoint
    ChangeEndpoint {
        /// New endpoint to change to (ex. "127.0.0.1:3001")
        new_endpoint: String,
        /// The mnemonic for the validator stash account to use for the call, should be stash address
        #[arg(short, long)]
        mnemonic_option: Option<String>,
    },
    /// Allows a validator to change their threshold accounts
    ChangeThresholdAccounts {
        /// New threshold account
        new_tss_account: String,
        /// New x25519 public key
        new_x25519_public_key: String,
        /// The mnemonic for the validator stash account to use for the call, should be stash address
        #[arg(short, long)]
        mnemonic_option: Option<String>,
    },
    /// Display a list of registered Entropy accounts
    Status,
}

pub async fn run_command(
    program_file_option: Option<PathBuf>,
    config_interface_file_option: Option<PathBuf>,
    aux_data_interface_file_option: Option<PathBuf>,
) -> anyhow::Result<String> {
    let cli = Cli::parse();

    let endpoint_addr = cli.chain_endpoint.unwrap_or_else(|| {
        std::env::var("ENTROPY_DEVNET").unwrap_or("ws://localhost:9944".to_string())
    });

    let passed_mnemonic = std::env::var("DEPLOYER_MNEMONIC");

    let api = get_api(&endpoint_addr).await?;
    let rpc = get_rpc(&endpoint_addr).await?;

    match cli.command {
        CliCommand::Register { mnemonic_option, programs } => {
            let mnemonic = if let Some(mnemonic_option) = mnemonic_option {
                mnemonic_option
            } else {
                passed_mnemonic.expect("No mnemonic set")
            };

            let program_keypair = <sr25519::Pair as Pair>::from_string(&mnemonic, None)?;
            let program_account = SubxtAccountId32(program_keypair.public().0);
            println!("Program account: {}", program_keypair.public());

            let mut programs_info = vec![];

            for program in programs {
                programs_info.push(
                    Program::from_hash_or_filename(&api, &rpc, &program_keypair, program).await?.0,
                );
            }

            let (verifying_key, registered_info) = register(
                &api,
                &rpc,
                program_keypair.clone(),
                program_account,
                BoundedVec(programs_info),
            )
            .await?;

            Ok(format!("Verfiying key: {},\n{:?}", hex::encode(verifying_key), registered_info))
        },
        CliCommand::Sign { signature_verifying_key, message, auxilary_data, mnemonic_option } => {
            let mnemonic = if let Some(mnemonic_option) = mnemonic_option {
                mnemonic_option
            } else {
                passed_mnemonic.unwrap_or("//Alice".to_string())
            };
            // If an account name is not provided, use the Alice key
            let user_keypair = <sr25519::Pair as Pair>::from_string(&mnemonic, None)?;

            println!("User account for current call: {}", user_keypair.public());

            let auxilary_data =
                if let Some(data) = auxilary_data { Some(hex::decode(data)?) } else { None };

            let signature_verifying_key: [u8; VERIFYING_KEY_LENGTH] =
                hex::decode(signature_verifying_key)?
                    .try_into()
                    .map_err(|_| anyhow!("Verifying key must be 33 bytes"))?;

            let recoverable_signature = sign(
                &api,
                &rpc,
                user_keypair,
                signature_verifying_key,
                message.as_bytes().to_vec(),
                auxilary_data,
            )
            .await?;
            Ok(format!("Message signed: {:?}", recoverable_signature))
        },
        CliCommand::StoreProgram {
            mnemonic_option,
            program_file,
            config_interface_file,
            aux_data_interface_file,
        } => {
            let mnemonic = if let Some(mnemonic_option) = mnemonic_option {
                mnemonic_option
            } else {
                passed_mnemonic.expect("No Mnemonic set")
            };
            let keypair = <sr25519::Pair as Pair>::from_string(&mnemonic, None)?;
            println!("Storing program using account: {}", keypair.public());

            let program = match program_file {
                Some(file_name) => fs::read(file_name)?,
                None => fs::read(program_file_option.expect("No program file passed in"))?,
            };

            let config_interface = match config_interface_file {
                Some(file_name) => fs::read(file_name)?,
                None => fs::read(
                    config_interface_file_option.expect("No config interface file passed"),
                )?,
            };

            let aux_data_interface = match aux_data_interface_file {
                Some(file_name) => fs::read(file_name)?,
                None => fs::read(
                    aux_data_interface_file_option.expect("No aux data interface file passed"),
                )?,
            };

            let hash = store_program(
                &api,
                &rpc,
                &keypair,
                program,
                config_interface,
                aux_data_interface,
                vec![],
            )
            .await?;
            Ok(format!("Program stored {hash}"))
        },
        CliCommand::UpdatePrograms { signature_verifying_key, mnemonic_option, programs } => {
            let mnemonic = if let Some(mnemonic_option) = mnemonic_option {
                mnemonic_option
            } else {
                passed_mnemonic.expect("No Mnemonic set")
            };
            let program_keypair = <sr25519::Pair as Pair>::from_string(&mnemonic, None)?;
            println!("Program account: {}", program_keypair.public());

            let mut programs_info = Vec::new();
            for program in programs {
                programs_info.push(
                    Program::from_hash_or_filename(&api, &rpc, &program_keypair, program).await?.0,
                );
            }

            let verifying_key: [u8; VERIFYING_KEY_LENGTH] = hex::decode(signature_verifying_key)?
                .try_into()
                .map_err(|_| anyhow!("Verifying key must be 33 bytes"))?;

            update_programs(&api, &rpc, verifying_key, &program_keypair, BoundedVec(programs_info))
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
                    "{:<64} {:<12} Programs:",
                    "Verifying key:".green(),
                    "Visibility:".purple(),
                );
                for (account_id, info) in accounts {
                    println!(
                        "{} {}",
                        hex::encode(account_id).green(),
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
                        "{} {} {:>11} {:>14} {:<13} {}",
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
        CliCommand::ChangeEndpoint { new_endpoint, mnemonic_option } => {
            let mnemonic = if let Some(mnemonic_option) = mnemonic_option {
                mnemonic_option
            } else {
                passed_mnemonic.expect("No Mnemonic set")
            };

            let user_keypair = <sr25519::Pair as Pair>::from_string(&mnemonic, None)?;
            println!("User account for current call: {}", user_keypair.public());

            let result_event = change_endpoint(&api, &rpc, user_keypair, new_endpoint).await?;
            println!("Event result: {:?}", result_event);
            Ok("Endpoint changed".to_string())
        },
        CliCommand::ChangeThresholdAccounts {
            new_tss_account,
            new_x25519_public_key,
            mnemonic_option,
        } => {
            let mnemonic = if let Some(mnemonic_option) = mnemonic_option {
                mnemonic_option
            } else {
                passed_mnemonic.expect("No Mnemonic set")
            };
            let user_keypair = <sr25519::Pair as Pair>::from_string(&mnemonic, None)?;
            println!("User account for current call: {}", user_keypair.public());

            let result_event = change_threshold_accounts(
                &api,
                &rpc,
                user_keypair,
                new_tss_account,
                new_x25519_public_key,
            )
            .await?;
            println!("Event result: {:?}", result_event);

            Ok("Threshold accounts changed".to_string())
        },
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
            vec![],
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
                    Err(error.into())
                }
            },
        }
    }
}
