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

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use entropy_runtime::{Block, EXISTENTIAL_DEPOSIT};
use frame_benchmarking_cli::{BenchmarkCmd, ExtrinsicFactory, SUBSTRATE_REFERENCE_HARDWARE};
use sc_cli::SubstrateCli;
use sc_service::PartialComponents;
use sp_keyring::Sr25519Keyring;
use sp_runtime::traits::HashingFor;

use crate::{
    benchmarking::{inherent_benchmark_data, RemarkBuilder, TransferKeepAliveBuilder},
    chain_spec::{self, testnet::TestnetChainSpecInputs},
    cli::{Cli, Subcommand},
    service,
};

impl SubstrateCli for Cli {
    fn impl_name() -> String {
        "Entropy Node".into()
    }

    fn impl_version() -> String {
        env!("SUBSTRATE_CLI_IMPL_VERSION").into()
    }

    fn description() -> String {
        env!("CARGO_PKG_DESCRIPTION").into()
    }

    fn author() -> String {
        env!("CARGO_PKG_AUTHORS").into()
    }

    fn support_url() -> String {
        "https://github.com/entropyxyz/entropy-core/".into()
    }

    fn copyright_start_year() -> i32 {
        2022
    }

    // | --chain                            | Description |
    // |----------------------------------  |----------- |
    // | dev                                | Four nodes, Four threshold servers, Alice Bob and Charlie and Dave, Development Configuration |
    // | devnet-local                       | Four nodes, four threshold servers, Alice Bob Charlie and Dave, Development Configuration, Docker Compatible |
    // | integration-tests                  | Two nodes, Four threshold servers, Alice and Bob, Development Configuration |
    // | testnet-local                      | Two Nodes, Two threshold servers, Alice and Bob, Testnet Configuration, Docker Compatible |
    // | testnet-blank                      | Testnet chainspec configuration with 'blank' inputs which need to be filled in later |
    // | <my-testnet>-chainspec-inputs.json | Custom Testnet Configuration with given inputs from a specified JSON file |
    fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
        Ok(match id {
            "" | "dev" => Box::new(chain_spec::dev::development_config()),
            "devnet-local" => Box::new(chain_spec::dev::devnet_local_four_node_config()),
            "integration-tests" => {
                let jumpstarted = false;
                Box::new(chain_spec::integration_tests::integration_tests_config(jumpstarted))
            },
            "integration-tests-jumpstarted" => {
                let jumpstarted = true;
                Box::new(chain_spec::integration_tests::integration_tests_config(jumpstarted))
            },
            "testnet-local" => Box::new(chain_spec::testnet::testnet_local_config()),
            "testnet-blank" => Box::new(chain_spec::testnet::testnet_blank_config()?),
            path if id.ends_with("-chainspec-inputs.json") => {
                let inputs = TestnetChainSpecInputs::from_json_file(path)?;
                Box::new(chain_spec::testnet::testnet_config(inputs)?)
            },
            path => {
                Box::new(chain_spec::ChainSpec::from_json_file(std::path::PathBuf::from(path))?)
            },
        })
    }
}

/// Parse and run command line arguments
pub fn run() -> sc_cli::Result<()> {
    let cli = Cli::from_args();

    match &cli.subcommand {
        Some(Subcommand::Key(cmd)) => cmd.run(&cli),
        Some(Subcommand::BuildSpec(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run(config.chain_spec, config.network))
        },
        Some(Subcommand::CheckBlock(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents { client, task_manager, import_queue, .. } =
                    service::new_partial(&config)?;
                Ok((cmd.run(client, import_queue), task_manager))
            })
        },
        Some(Subcommand::ExportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents { client, task_manager, .. } = service::new_partial(&config)?;
                Ok((cmd.run(client, config.database), task_manager))
            })
        },
        Some(Subcommand::ExportState(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents { client, task_manager, .. } = service::new_partial(&config)?;
                Ok((cmd.run(client, config.chain_spec), task_manager))
            })
        },
        Some(Subcommand::ImportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents { client, task_manager, import_queue, .. } =
                    service::new_partial(&config)?;
                Ok((cmd.run(client, import_queue), task_manager))
            })
        },
        Some(Subcommand::PurgeChain(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run(config.database))
        },
        Some(Subcommand::Revert(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents { client, task_manager, backend, .. } =
                    service::new_partial(&config)?;
                let aux_revert = Box::new(|client, _, blocks| {
                    grandpa::revert(client, blocks)?;
                    Ok(())
                });
                Ok((cmd.run(client, backend, Some(aux_revert)), task_manager))
            })
        },
        Some(Subcommand::Benchmark(cmd)) => {
            let runner = cli.create_runner(cmd)?;

            runner.sync_run(|config| {
                // This switch needs to be in the client, since the client decides
                // which sub-commands it wants to support.
                match cmd {
                    BenchmarkCmd::Pallet(cmd) => {
                        if !cfg!(feature = "runtime-benchmarks") {
                            return Err("Runtime benchmarking wasn't enabled when building the \
                                        node. You can enable it with `--features \
                                        runtime-benchmarks`."
                                .into());
                        }

						cmd.run_with_spec::<HashingFor<Block>, sp_statement_store::runtime_api::HostFunctions>(Some(config.chain_spec))
                    },
                    BenchmarkCmd::Block(cmd) => {
                        let PartialComponents { client, .. } = service::new_partial(&config)?;
                        cmd.run(client)
                    },
                    #[cfg(not(feature = "runtime-benchmarks"))]
                    BenchmarkCmd::Storage(_) => Err("Storage benchmarking can be enabled with \
                                                     `--features runtime-benchmarks`."
                        .into()),
                    #[cfg(feature = "runtime-benchmarks")]
                    BenchmarkCmd::Storage(cmd) => {
                        let PartialComponents { client, backend, .. } =
                            service::new_partial(&config)?;
                        let db = backend.expose_db();
                        let storage = backend.expose_storage();

                        cmd.run(config, client, db, storage)
                    },
                    BenchmarkCmd::Overhead(cmd) => {
                        let PartialComponents { client, .. } = service::new_partial(&config)?;
                        let ext_builder = RemarkBuilder::new(client.clone());

                        cmd.run(
							config.chain_spec.name().into(),
                            client,
                            inherent_benchmark_data()?,
                            Vec::new(),
                            &ext_builder,
                            false,
                        )
                    },
                    BenchmarkCmd::Extrinsic(cmd) => {
                        let PartialComponents { client, .. } = service::new_partial(&config)?;
                        // Register the *Remark* and *TKA* builders.
                        let ext_factory = ExtrinsicFactory(vec![
                            Box::new(RemarkBuilder::new(client.clone())),
                            Box::new(TransferKeepAliveBuilder::new(
                                client.clone(),
                                Sr25519Keyring::Alice.to_account_id(),
                                EXISTENTIAL_DEPOSIT,
                            )),
                        ]);

                        cmd.run(client, inherent_benchmark_data()?, Vec::new(), &ext_factory)
                    },
                    BenchmarkCmd::Machine(cmd) => {
                        cmd.run(&config, SUBSTRATE_REFERENCE_HARDWARE.clone())
                    },
                }
            })
        },
        #[cfg(feature = "try-runtime")]
        Some(Subcommand::TryRuntime(cmd)) => {
            use sc_executor::{sp_wasm_interface::ExtendedHostFunctions, NativeExecutionDispatch};

            use crate::service::ExecutorDispatch;
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                // we don't need any of the components of new_partial, just a runtime, or a task
                // manager to do `async_run`.
                let registry = config.prometheus_config.as_ref().map(|cfg| &cfg.registry);
                let task_manager =
                    sc_service::TaskManager::new(config.tokio_handle.clone(), registry)
                        .map_err(|e| sc_cli::Error::Service(sc_service::Error::Prometheus(e)))?;
                let info_provider = timestamp_with_aura_info(6000);

                Ok((
                    cmd.run::<Block, ExtendedHostFunctions<
                        sp_io::SubstrateHostFunctions,
                        <ExecutorDispatch as NativeExecutionDispatch>::ExtendHostFunctions,
                    >, _>(Some(info_provider)),
                    task_manager,
                ))
            })
        },

        #[cfg(not(feature = "try-runtime"))]
        Some(Subcommand::TryRuntime) => Err("TryRuntime wasn't enabled when building the node. \
                                             You can enable it with `--features try-runtime`."
            .into()),
        Some(Subcommand::ChainInfo(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run::<Block>(&config))
        },
        None => {
            let runner = cli.create_runner(&cli.run)?;
            runner.run_node_until_exit(|config| async move {
                service::new_full(config, cli).map_err(sc_cli::Error::Service)
            })
        },
    }
}
