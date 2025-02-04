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
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use entropy_client::{
    chain_api::{
        entropy::runtime_types::{
            bounded_collections::bounded_vec::BoundedVec,
            pallet_programs::pallet::ProgramInfo,
            pallet_registry::pallet::{ProgramInstance, RegisteredInfo},
        },
        EntropyConfig,
    },
    client::{
        bond_account, get_accounts, get_api, get_oracle_headings, get_programs,
        get_quote_and_change_endpoint, get_quote_and_change_threshold_accounts,
        get_quote_and_declare_validate, get_rpc, get_tdx_quote, jumpstart_network, register,
        remove_program, set_session_keys, sign, store_program, update_programs,
        VERIFYING_KEY_LENGTH,
    },
};
pub use entropy_shared::{attestation::QuoteContext, PROGRAM_VERSION_NUMBER};
use parity_scale_codec::Decode;
use sp_core::{sr25519, Hasher, Pair};
use sp_runtime::{traits::BlakeTwo256, Serialize};
use std::{fs, path::PathBuf, str::FromStr};
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
pub struct Cli {
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
    /// Whether to give command output as JSON. Defaults to false.
    #[arg(short, long)]
    pub json: bool,
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
        /// Option of version numbers to go with the programs, will default to 0 if None
        #[arg(short, long)]
        program_version_numbers: Option<Vec<u8>>,
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
        #[arg(short, long)]
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
        /// Option of version numbers to go with the programs, will default to 0 if None
        program_version_numbers: Option<Vec<u8>>,
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
        /// The path to a file containing the program oracle data headings (defaults to empty)
        oracle_data_file: Option<PathBuf>,
        /// The version number of the program's runtime you compiled with
        program_version_number: Option<u8>,
        /// The mnemonic to use for the call
        #[arg(short, long)]
        mnemonic_option: Option<String>,
    },
    /// Remove a given program from chain
    RemoveProgram {
        /// The 32 bytes hash of the program to remove, encoded as hex
        hash: String,
        /// The mnemonic to use for the call, which must be the program deployer
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
    /// Triggers the network wide distributed key generation process.
    ///
    /// A fully jumpstarted network is required for the on-chain registration flow to work
    /// correctly.
    ///
    /// Note: Any account may trigger the jumpstart process.
    JumpstartNetwork {
        /// The mnemonic for the signer which will trigger the jumpstart process.
        #[arg(short, long)]
        mnemonic_option: Option<String>,
    },
    /// Get headings of oracle data
    ///
    /// This is useful for program developers to know what oracle data is available.
    GetOracleHeadings,
    /// Request a TDX quote from a TSS server and write it to a file.
    GetTdxQuote {
        /// The socket address of the TS server, eg: `127.0.0.1:3002`
        tss_endpoint: String,
        /// The context in which this quote will be used. Must be one of
        #[arg(value_enum)]
        quote_context: QuoteContextArg,
        /// The filename to write the quote to. Defaults to `quote.dat`
        #[arg(long)]
        output_filename: Option<String>,
    },
    /// Bonds an account.
    BondAccount {
        /// Amount to bond
        amount: u128,
        /// Destination to get rewards encoded as ss58
        reward_destination: String,
        /// The mnemonic for the signer which will trigger the call.
        #[arg(short, long)]
        mnemonic_option: Option<String>,
    },
    /// Sets session keys for an account.
    SetSessionKeys {
        /// Session key received from a node
        session_keys: String,
        /// The mnemonic for the signer which will trigger the call.
        #[arg(short, long)]
        mnemonic_option: Option<String>,
    },
    /// Declares intention to validate
    DeclareValidate {
        /// Threshold account encoded as ss58
        tss_account: String,
        ///  X25519 public key encoded as hex
        x25519_public_key: String,
        /// Endpoint of TSS node (ex. "127.0.0.1:3001")
        endpoint: String,
        /// Commission amount
        comission: u32,
        /// Whether to block from nominating
        blocked: bool,
        /// The mnemonic for the signer which will trigger the call.
        #[arg(short, long)]
        mnemonic_option: Option<String>,
    },
}

impl Cli {
    fn log(&self, text: String) {
        if !self.json {
            println!("{text}");
        }
    }
}

pub async fn run_command(
    cli: Cli,
    program_file_option: Option<PathBuf>,
    config_interface_file_option: Option<PathBuf>,
    aux_data_interface_file_option: Option<PathBuf>,
    oracle_data_file_option: Option<PathBuf>,
    program_version_number_option: Option<u8>,
) -> anyhow::Result<String> {
    let endpoint_addr = cli.chain_endpoint.clone().unwrap_or_else(|| {
        std::env::var("ENTROPY_DEVNET").unwrap_or("ws://localhost:9944".to_string())
    });

    let api = get_api(&endpoint_addr).await?;
    let rpc = get_rpc(&endpoint_addr).await?;

    match cli.command.clone() {
        CliCommand::Register { mnemonic_option, programs, program_version_numbers } => {
            let program_keypair = handle_mnemonic(mnemonic_option)?;
            let program_account = SubxtAccountId32(program_keypair.public().0);
            cli.log(format!("Program account: {}", program_keypair.public()));

            let mut programs_info = vec![];

            for (i, program) in programs.into_iter().enumerate() {
                let program_version_number =
                    program_version_numbers.as_ref().map_or(0u8, |versions| versions[i]);
                programs_info.push(
                    Program::from_hash_or_filename(
                        &api,
                        &rpc,
                        &program_keypair,
                        program,
                        program_version_number,
                    )
                    .await?
                    .0,
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

            let verifying_key = hex::encode(verifying_key);
            if cli.json {
                Ok(serde_json::to_string_pretty(&verifying_key)?)
            } else {
                Ok(format!("Verifying key: {},\n{:?}", verifying_key, registered_info))
            }
        },
        CliCommand::Sign { signature_verifying_key, message, auxilary_data, mnemonic_option } => {
            // If an account name is not provided, use the Alice key
            let user_keypair = handle_mnemonic(mnemonic_option)
                .unwrap_or(<sr25519::Pair as Pair>::from_string("//Alice", None)?);

            cli.log(format!("User account for current call: {}", user_keypair.public()));

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

            if cli.json {
                Ok(serde_json::to_string_pretty(&recoverable_signature)?)
            } else {
                Ok(format!("Message signed: {:?}", recoverable_signature))
            }
        },
        CliCommand::StoreProgram {
            mnemonic_option,
            program_file,
            config_interface_file,
            aux_data_interface_file,
            oracle_data_file,
            program_version_number,
        } => {
            let keypair = handle_mnemonic(mnemonic_option)?;
            cli.log(format!("Storing program using account: {}", keypair.public()));

            let program = match program_file {
                Some(file_name) => fs::read(file_name)?,
                None => fs::read(program_file_option.expect("No program file passed in"))?,
            };

            let config_interface = match config_interface_file {
                Some(file_name) => fs::read(file_name)?,
                None => match config_interface_file_option {
                    Some(config_interface_file) => fs::read(config_interface_file)?,
                    None => Vec::new(),
                },
            };

            let aux_data_interface = match aux_data_interface_file {
                Some(file_name) => fs::read(file_name)?,
                None => match aux_data_interface_file_option {
                    Some(aux_data_interface_file) => fs::read(aux_data_interface_file)?,
                    None => Vec::new(),
                },
            };

            let oracle_data: Vec<Vec<u8>> = match oracle_data_file {
                Some(file_name) => Vec::<Vec<u8>>::decode(&mut (fs::read(file_name)?).as_ref())?,
                None => match oracle_data_file_option {
                    Some(oracle_data_file) => {
                        Vec::<Vec<u8>>::decode(&mut (fs::read(oracle_data_file)?).as_ref())?
                    },
                    None => vec![],
                },
            };

            let program_version_number = match program_version_number_option {
                Some(program_version_number) => program_version_number,
                None => program_version_number.unwrap_or(0u8),
            };

            let hash = store_program(
                &api,
                &rpc,
                &keypair,
                program,
                config_interface,
                aux_data_interface,
                oracle_data,
                program_version_number,
            )
            .await?;

            let hash = hex::encode(hash);

            if cli.json {
                Ok(serde_json::to_string_pretty(&hash)?)
            } else {
                Ok(format!("Program stored: {}", hex::encode(hash)))
            }
        },
        CliCommand::RemoveProgram { mnemonic_option, hash } => {
            let keypair = handle_mnemonic(mnemonic_option)?;
            cli.log(format!("Removing program using account: {}", keypair.public()));

            let hash: [u8; 32] = hex::decode(hash)?
                .try_into()
                .map_err(|_| anyhow!("Program hash must be 32 bytes"))?;

            remove_program(&api, &rpc, &keypair, H256(hash)).await?;

            if cli.json {
                Ok("{}".to_string())
            } else {
                Ok("Program removed".to_string())
            }
        },
        CliCommand::UpdatePrograms {
            signature_verifying_key,
            mnemonic_option,
            programs,
            program_version_numbers,
        } => {
            let program_keypair = handle_mnemonic(mnemonic_option)?;
            cli.log(format!("Program account: {}", program_keypair.public()));

            let mut programs_info = Vec::new();

            for (i, program) in programs.into_iter().enumerate() {
                let program_version_number =
                    program_version_numbers.as_ref().map_or(0u8, |versions| versions[i]);
                programs_info.push(
                    Program::from_hash_or_filename(
                        &api,
                        &rpc,
                        &program_keypair,
                        program,
                        program_version_number,
                    )
                    .await?
                    .0,
                );
            }

            let verifying_key: [u8; VERIFYING_KEY_LENGTH] = hex::decode(signature_verifying_key)?
                .try_into()
                .map_err(|_| anyhow!("Verifying key must be 33 bytes"))?;

            update_programs(&api, &rpc, verifying_key, &program_keypair, BoundedVec(programs_info))
                .await?;

            if cli.json {
                Ok("{}".to_string())
            } else {
                Ok("Programs updated".to_string())
            }
        },
        CliCommand::Status => {
            let accounts = get_accounts(&api, &rpc).await?;
            let programs = get_programs(&api, &rpc).await?;

            if !cli.json {
                println!(
                    "There are {} registered Entropy accounts.\n",
                    accounts.len().to_string().green()
                );
                if !accounts.is_empty() {
                    println!("{:<66} Programs:", "Verifying key:".green());
                    for (account_id, info) in accounts.iter() {
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

                println!("\nThere are {} stored programs\n", programs.len().to_string().green());

                if !programs.is_empty() {
                    println!(
                        "{:<64} {:<48} {:<11} {:<14} {} {}",
                        "Hash".blue(),
                        "Stored by:".green(),
                        "Times used:".purple(),
                        "Size in bytes:".cyan(),
                        "Configurable?".yellow(),
                        "Has auxiliary?".yellow(),
                    );
                    for (hash, program_info) in programs.iter() {
                        println!(
                            "{} {} {:>11} {:>14} {:<13} {}",
                            hex::encode(hash),
                            program_info.deployer,
                            program_info.ref_counter,
                            program_info.bytecode.len(),
                            !program_info.configuration_schema.is_empty(),
                            !program_info.auxiliary_data_schema.is_empty(),
                        );
                    }
                }
            }

            if cli.json {
                let output = StatusOutput::new(accounts, programs);
                Ok(serde_json::to_string_pretty(&output)?)
            } else {
                Ok("Got status".to_string())
            }
        },
        CliCommand::ChangeEndpoint { new_endpoint, mnemonic_option } => {
            let user_keypair = handle_mnemonic(mnemonic_option)?;
            cli.log(format!("User account for current call: {}", user_keypair.public()));

            let result_event =
                get_quote_and_change_endpoint(&api, &rpc, user_keypair, new_endpoint).await?;
            cli.log(format!("Event result: {:?}", result_event));

            if cli.json {
                Ok("{}".to_string())
            } else {
                Ok("Endpoint changed".to_string())
            }
        },
        CliCommand::ChangeThresholdAccounts {
            new_tss_account,
            new_x25519_public_key,
            mnemonic_option,
        } => {
            let user_keypair = handle_mnemonic(mnemonic_option)?;
            cli.log(format!("User account for current call: {}", user_keypair.public()));

            let new_tss_account = SubxtAccountId32::from_str(&new_tss_account)?;
            let new_x25519_public_key = hex::decode(new_x25519_public_key)?
                .try_into()
                .map_err(|_| anyhow!("X25519 pub key needs to be 32 bytes"))?;
            let result_event = get_quote_and_change_threshold_accounts(
                &api,
                &rpc,
                user_keypair,
                new_tss_account,
                new_x25519_public_key,
            )
            .await?;
            cli.log(format!("Event result: {:?}", result_event));

            if cli.json {
                Ok("{}".to_string())
            } else {
                Ok("Threshold accounts changed".to_string())
            }
        },
        CliCommand::JumpstartNetwork { mnemonic_option } => {
            let signer = handle_mnemonic(mnemonic_option)?;
            cli.log(format!("Account being used for jumpstart: {}", signer.public()));

            jumpstart_network(&api, &rpc, signer).await?;

            if cli.json {
                Ok("{}".to_string())
            } else {
                Ok("Succesfully jumpstarted network.".to_string())
            }
        },
        CliCommand::GetOracleHeadings => {
            let headings = get_oracle_headings(&api, &rpc).await?;
            Ok(serde_json::to_string_pretty(&headings)?)
        },
        CliCommand::GetTdxQuote { tss_endpoint, output_filename, quote_context } => {
            let quote_bytes = get_tdx_quote(&tss_endpoint, quote_context.into()).await?;
            let output_filename = output_filename.unwrap_or("quote.dat".into());

            std::fs::write(&output_filename, quote_bytes)?;
            if cli.json {
                Ok("{}".to_string())
            } else {
                Ok(format!("Succesfully written quote to {}", output_filename))
            }
        },
        CliCommand::BondAccount { amount, reward_destination, mnemonic_option } => {
            let signer = handle_mnemonic(mnemonic_option)?;
            cli.log(format!("Account being used for bonding: {}", signer.public()));
            let reward_destination_account = SubxtAccountId32::from_str(&reward_destination)?;

            let result_event =
                bond_account(&api, &rpc, signer, amount, reward_destination_account).await?;
            cli.log(format!("Event result: {:?}", result_event));

            if cli.json {
                Ok("{}".to_string())
            } else {
                Ok("Acount bonded".to_string())
            }
        },
        CliCommand::SetSessionKeys { session_keys, mnemonic_option } => {
            let signer = handle_mnemonic(mnemonic_option)?;
            cli.log(format!("Account being used for session keys: {}", signer.public()));

            set_session_keys(&api, &rpc, signer, session_keys).await?;

            if cli.json {
                Ok("{}".to_string())
            } else {
                Ok("Session Keys updates".to_string())
            }
        },
        CliCommand::DeclareValidate {
            tss_account,
            x25519_public_key,
            endpoint,
            comission,
            blocked,
            mnemonic_option,
        } => {
            let signer = handle_mnemonic(mnemonic_option)?;
            cli.log(format!("Account being used for session keys: {}", signer.public()));

            let result_event = get_quote_and_declare_validate(
                &api,
                &rpc,
                signer,
                comission,
                blocked,
                tss_account,
                x25519_public_key,
                endpoint,
            )
            .await?;

            cli.log(format!("Event result: {:?}", result_event));

            if cli.json {
                Ok("{}".to_string())
            } else {
                Ok("Validation declared succefully".to_string())
            }
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
        program_version_number: u8,
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
                    Err(_) => {
                        Self::from_file(api, rpc, keypair, hash_or_filename, program_version_number)
                            .await
                    },
                }
            },
            Err(_) => {
                Self::from_file(api, rpc, keypair, hash_or_filename, program_version_number).await
            },
        }
    }

    /// Given a path to a .wasm file, read it, store the program if it doesn't already exist, and
    /// return the hash.
    async fn from_file(
        api: &OnlineClient<EntropyConfig>,
        rpc: &LegacyRpcMethods<EntropyConfig>,
        keypair: &sr25519::Pair,
        filename: String,
        program_version_number: u8,
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
            program_version_number,
        )
        .await
        {
            Ok(hash) => Ok(Self::new(hash, configuration)),
            Err(error) => {
                if error.to_string().ends_with("ProgramAlreadySet") {
                    // Use existing program as it is already stored
                    let hash = BlakeTwo256::hash(&program_bytecode);
                    Ok(Self::new(H256(hash.into()), configuration))
                } else {
                    Err(error.into())
                }
            },
        }
    }
}

#[derive(Serialize)]
/// Output from the status command
struct StatusOutput {
    accounts: Vec<String>,
    programs: Vec<String>,
}

impl StatusOutput {
    fn new(accounts: Vec<([u8; 33], RegisteredInfo)>, programs: Vec<(H256, ProgramInfo)>) -> Self {
        let accounts = accounts
            .into_iter()
            .map(|(verifying_key, _registered_info)| hex::encode(verifying_key))
            .collect();
        let programs =
            programs.into_iter().map(|(hash, _program_info)| hex::encode(hash.0)).collect();
        Self { accounts, programs }
    }
}

/// Get an sr25519 from a mnemonic given as either option or environment variable
fn handle_mnemonic(mnemonic_option: Option<String>) -> anyhow::Result<sr25519::Pair> {
    let mnemonic = if let Some(mnemonic) = mnemonic_option {
        mnemonic
    } else {
        std::env::var("DEPLOYER_MNEMONIC")
            .map_err(|_| anyhow!("A mnemonic must be given either by the command line option or DEPLOYER_MNEMONIC environment variable"))?
    };
    Ok(<sr25519::Pair as Pair>::from_string(&mnemonic, None)?)
}

/// This is the same as [QuoteContext] but implements [ValueEnum]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum QuoteContextArg {
    /// To be used in the `validate` extrinsic
    Validate,
    /// To be used in the `change_endpoint` extrinsic
    ChangeEndpoint,
    /// To be used in the `change_threshold_accounts` extrinsic
    ChangeThresholdAccounts,
}

impl From<QuoteContextArg> for QuoteContext {
    fn from(quote_context: QuoteContextArg) -> Self {
        match quote_context {
            QuoteContextArg::Validate => QuoteContext::Validate,
            QuoteContextArg::ChangeEndpoint => QuoteContext::ChangeEndpoint,
            QuoteContextArg::ChangeThresholdAccounts => QuoteContext::ChangeThresholdAccounts,
        }
    }
}
