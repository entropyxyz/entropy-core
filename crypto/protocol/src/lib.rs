pub mod keygen;
pub mod node;
pub mod signing;
pub mod user;
use clap::{AppSettings, Parser, Subcommand};
use std::path::PathBuf;

/// Generate `SHARES` of `threshold` key shares
pub const SHARES: u16 = 6;
pub const THRESHOLD: u16= 6;

/// Arguments to CLI, default to 6 of 6. Usage:
/// `$ entro <subcommand>`
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
		shares: u16,
		#[clap(short, long, default_value_t = THRESHOLD)]
		threshold: u16,
		/// Where keys are written to
		#[clap(short, long)]
		output: PathBuf,
	},
	Sign,
	DeleteAccount
	// todo: sign tx, delete acct
}

#[tokio::main]
async fn main() {
	let args = Cli::parse();
	match &args.commands {
 
		Commands::Keygen { shares, threshold, output } => {
			keygen::keygen(shares, threshold, output);
		},
		Commands::Sign => todo!(), 
		Commands::DeleteAccount => todo!(),
	}
}
