#![allow(unused_imports)]
pub mod keygen;
pub mod node;
pub mod signing;
pub mod user;
//use std::path::PathBuf;
use structopt::StructOpt;
use keygen::KeygenCli;
use anyhow::{anyhow, Context, Result};


/// Generate `SHARES` of `threshold` key shares
pub const N_PARTIES: u16 = 6;
pub const THRESHOLD: u16= 6;

#[derive(Debug,StructOpt)]
struct Cli{
	#[structopt(subcommand)]
	cmd: Command 
}

#[derive(StructOpt, Debug)]
enum Command {
	/// Generate `threshold` of `output` keyshares at `output`
	Keygen ( KeygenCli),
	Sign,
	DeleteAccount
	// todo: sign tx, delete acct
}

#[tokio::main]
async fn main() -> Result<()> {
	let args: Cli = Cli::from_args();
	match &args.cmd {
 
		Command::Keygen(keygen_cli) => {
			keygen::keygen(keygen_cli);
		},
		Command::Sign => todo!(), 
		Command::DeleteAccount => todo!(),
	}
	Ok(())
}