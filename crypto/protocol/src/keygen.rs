//! Alice generates the keys.
//! Reference heavily:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg20_keygen.rs
#![allow(unused_imports, dead_code)]
use std::marker::Copy;
use crate::gg20_sm_client::join_computation;
use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;
use round_based::async_runtime::AsyncProtocol;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt, Clone)]
pub struct KeygenCli {
	/// Address to post to*
	#[structopt(short, long, default_value = "http://localhost:8000/")]
	address: surf::Url,
	#[structopt(short, long, default_value = "default-keygen")]
	room: String,
	#[structopt(short, long)]
	pub threshold: u16,
	#[structopt(short, long)]
	number_of_parties: u16,
}


/// In the example https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg20_keygen.rs,
/// the key generator:
/// 1. asyncronously opens an output file
/// 2. `join_computation` takes a url and a "room_id", creates an http client, and subscribes to the
/// incoming stream of messages,broadcasts the outgoing sink of messages, and returns the channels
/// 3. creates a fuse
pub async fn keygen_cli(args: &KeygenCli, index: &u16) -> Result<()> {
	let output = format!(
		"local-share{}.json",index);

	let mut output_file = tokio::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(output)
		.await
		.context("cannot create output file")?;

	let (_i, incoming, outgoing) = join_computation(args.address.clone(), &args.room)
		.await
		.context("join computation")?;

	let incoming = incoming.fuse();
	tokio::pin!(incoming);
	tokio::pin!(outgoing);

	let keygen = Keygen::new(index.clone(), args.threshold, args.number_of_parties)?;
	let output = AsyncProtocol::new(keygen, incoming, outgoing)
		.run()
		.await
		.map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;
	let output = serde_json::to_vec_pretty(&output).context("serialize output")?;
	tokio::io::copy(&mut output.as_slice(), &mut output_file)
		.await
		.context("save output to file")?;
	Ok(())
}
