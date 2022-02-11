#![allow(unused_imports)]
pub mod gg20_sm_client;
pub mod keygen;
pub mod node;
pub mod gg20_sm_manager;
pub mod sign;
pub mod user;
//use std::path::PathBuf;
use crate::gg20_sm_client::SmClientCli;
use crate::{ keygen::KeygenCli};
use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use structopt::StructOpt;

/// Generate `SHARES` of `threshold` key shares
pub const N_PARTIES: u16 = 6;
pub const THRESHOLD: u16 = 6;

#[derive(Debug, StructOpt)]
struct Cli {
	#[structopt(subcommand)]
	cmd: Command,
}

#[derive(StructOpt, Debug)]
enum Command {
	SmManager,
	SmClient(SmClientCli),
	/// Generate `threshold` of `output` keyshares at `output`
	Keygen(KeygenCli),
	Sign,
	DeleteAccount, // todo: sign tx, delete acct
}

#[tokio::main]
async fn main() -> Result<()> {
	let args: Cli = Cli::from_args();
	match args.cmd {
		Command::SmClient(cli) => gg20_sm_client::sm_client_cli(cli).await,
		Command::SmManager => gg20_sm_manager::sm_manager_cli().await,
		Command::Keygen(cli) => keygen::keygen_cli(cli).await,
		Command::Sign => todo!(),
		Command::DeleteAccount => todo!(),
	}
}
