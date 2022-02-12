#![allow(unused_imports)]
pub mod gg20_sm_client;
pub mod gg20_sm_manager;
pub mod keygen;
pub mod node;
pub mod sign;
pub mod user;
//use std::path::PathBuf;
use crate::{gg20_sm_client::SmClientCli, keygen::KeygenCli};
use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::task;

/// Generate `SHARES` of `threshold` key shares
pub const N_PARTIES: u16 = 6;
pub const THRESHOLD: u16 = 6;

#[derive(Debug, StructOpt, Clone)]
struct Cli {
	#[structopt(subcommand)]
	cmd: Command,
}

#[derive(StructOpt, Debug, Clone)]
enum Command {
	SmManager,
	SmClient(SmClientCli),
	/// Generate `threshold` of `output` keyshares at `output`
	Keygen(KeygenCli),
	Sign(SignCli),
	DeleteAccount, // todo: sign tx, delete acct
}

#[tokio::main]
async fn main() -> Result<()> {
	let args: Cli = Cli::from_args();
	match args.cmd {
		Command::SmClient(cli) => gg20_sm_client::sm_client_cli(cli).await,
		Command::SmManager => gg20_sm_manager::sm_manager_cli().await,
		Command::Keygen(cli) => {
			todo!(); // async await issues, revisit when jesse gets out of the tub
			// let tasks: Vec<_> = (0..cli.threshold)
			// 	.map( |i| async move {
			// 		keygen::keygen_cli(&cli, &i);
			// 	})
			// 	.collect();
			// let _ = futures::future::join_all(tasks).await;
			// Ok(())
		},
		Command::Sign(cli) => sign::sign(cli,index).await,
		Command::DeleteAccount => todo!(),
	}
}
