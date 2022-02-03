pub mod keygen;
pub mod node;
pub mod signing;
pub mod user;
/// Generate `num_parties` of `threshold` key shares
use clap::{AppSettings, Parser, Subcommand};

pub const SHARES: u16 = 6;
pub const THRESHOLD: u16 = 6;

/// Arguments to CLI, default to 6 of 6.
#[derive(Parser, Debug)]
#[clap(name = "entro", version, about = "Entropy cryptography CLI")]
struct Cli {
	commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
	#[clap(setting(AppSettings::ArgRequiredElseHelp))]
	Keygen {
		#[clap(short, long, default_value_t = SHARES)]
		shares: u8,
		#[clap(short, long, default_value_t = THRESHOLD)]
		threshold: u8,
	},
	// todo: sign tx, delete acct
}

fn main() {
	let args = Args::parse();
	match &args.command {
		Commands::Keygen { shares, threshold } => {
			// Do keygen
		},
	}
}
