//use std::path::PathBuf;
#![allow(unused_imports)]
use anyhow::{anyhow, Context, Result};
use protocol::{
	gg20_sm_client, gg20_sm_client::SmClientCli, gg20_sm_manager, keygen, keygen::KeygenCli, sign,
	sign::SignCli,
};
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::task;

// ToDo: JA remove hard coding
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
	DeleteAccount, // todo: tk sign tx, delete acct
}

#[tokio::main]
async fn main() -> Result<()> {
	let args: Cli = Cli::from_args();
	match args.cmd {
		Command::SmClient(cli) => gg20_sm_client::sm_client_cli(cli).await,
		Command::SmManager => gg20_sm_manager::sm_manager_cli().await,
		Command::Keygen(cli) => {
			// library requires indices start at 1
			// TODO: tk alice can't send messages to herself in round_based dep
			let ids = 1..=(cli.threshold + 1);
			futures::future::try_join_all(ids.map(|id| keygen::keygen_cli(&cli, id)))
				.await
				.unwrap();
			Ok(())
		},
		Command::Sign(cli) => sign::sign(cli.into()).await,
		Command::DeleteAccount => todo!(),
	}
}
