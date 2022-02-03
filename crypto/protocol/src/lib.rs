pub mod keygen;
pub mod node;
pub mod signing;
pub mod user;
/// Generate `num_parties` of `threshold` key shares
use clap::{AppSettings, Parser, Subcommand};
use std::path::PathBuf;

pub const SHARES: u8 = 6;
pub const THRESHOLD: u8 = 6;

/// Arguments to CLI, default to 6 of 6.
#[derive(Parser, Debug)]
#[clap(name = "entro", version, about = "Entropy cryptography CLI")]
struct Cli {
	#[clap(subcommand)]
	commands: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
	/// Generate `threshold` of `output` keyshares at `output`
	#[clap(setting(AppSettings::ArgRequiredElseHelp))]
	Keygen {
		#[clap(short, long, default_value_t = SHARES)]
		shares: u8,
		#[clap(short, long, default_value_t = THRESHOLD)]
		threshold: u8,
		/// Where keys are written to
		#[clap(short, long)]
		output: PathBuf,
	},
	// todo: sign tx, delete acct
}

#[tokio::main]
async fn main() {
	let args = Cli::parse();
	match &args.commands {
		Commands::Keygen { shares, threshold, output } => {
			keygen::keygen(shares, threshold, output);
		},
	}
}
