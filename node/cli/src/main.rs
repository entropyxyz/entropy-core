//! Substrate Node Template CLI library.
#![warn(missing_docs)]

mod chain_spec;
#[macro_use]
mod service;
mod admin;
mod benchmarking;
mod cli;
mod command;
mod endowed_accounts;
mod rpc;

fn main() -> sc_cli::Result<()> { command::run() }
