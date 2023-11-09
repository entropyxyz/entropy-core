//! Entropy Node CLI library.
#![doc(html_logo_url = "https://entropy.xyz/assets/logo_02.png")]
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

fn main() -> sc_cli::Result<()> {
    command::run()
}
