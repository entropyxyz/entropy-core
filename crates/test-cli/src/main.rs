// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Simple CLI to test registering, updating programs and signing
use clap::Parser;
use colored::Colorize;
use entropy_test_cli::{run_command, Cli};
use std::time::Instant;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let now = Instant::now();
    let cli = Cli::parse();
    let json_ouput = cli.json;
    match run_command(cli, None, None, None, None).await {
        Ok(output) => {
            if json_ouput {
                println!("{}", output);
            } else {
                println!("Success: {}", output.green());
                println!("{}", format!("That took {:?}", now.elapsed()).yellow());
            }
            Ok(())
        },
        Err(err) => {
            eprintln!("{}", "Failed!".red());
            Err(err)
        },
    }
}
