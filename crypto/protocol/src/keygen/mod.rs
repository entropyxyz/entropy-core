//! Alice generates the keys.
//! Reference heavily:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg20_keygen.rs
#![allow(unused_imports)]
use anyhow::{anyhow, Context, Result};
// use futures::StreamExt;
use std::path::PathBuf;
// use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;
// use round_based::async_runtime::AsyncProtocol;

// mod gg20_sm_client;
// use gg20_sm_client::join_computation;

pub async fn keygen(shares: &u8, threshold: &u8, output: &PathBuf) -> Result<()> {
	let mut output_file = tokio::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(output)
		.await
		.context("cannot create output file")?;

	// let (_i, incoming, outgoing) =
	// 	join_computation(args.address, &args.room).await.context("join computation")?;

	// let incoming = incoming.fuse();
	// tokio::pin!(incoming);
	// tokio::pin!(outgoing);

	// let keygen = Keygen::new(args.index, args.threshold, args.number_of_parties)?;
	// let output = AsyncProtocol::new(keygen, incoming, outgoing)
	// 	.run()
	// 	.await
	// 	.map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;
	// let output = serde_json::to_vec_pretty(&output).context("serialize output")?;
	// tokio::io::copy(&mut output.as_slice(), &mut output_file)
	// 	.await
	// 	.context("save output to file")?;

	Ok(())
}
