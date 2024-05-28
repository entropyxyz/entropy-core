use std::time::Instant;

use colored::Colorize;
use entropy_test_cli::run_command;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let now = Instant::now();
    match run_command(None, None, None).await {
        Ok(output) => {
            println!("Success: {}", output.green());
            println!("{}", format!("That took {:?}", now.elapsed()).yellow());
            Ok(())
        },
        Err(err) => {
            println!("{}", "Failed!".red());
            Err(err)
        },
    }
}
