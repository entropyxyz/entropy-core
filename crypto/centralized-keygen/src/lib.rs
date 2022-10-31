//! Methods for Alice to use to generate secret shares from her private key.
use std::path::PathBuf;

use tofn::gg20::ceygen;

/// Split a `secret_key` into `threshold`-of-`parties` shards, write to directory `path`.
/// A wrapper around entropyxyz/tofn.
/// See https://github.com/entropyxyz/tofn for details.
pub fn ceygen(
    path: PathBuf,
    parties: usize,
    threshold: usize,
    secret_key: Vec<u8>,
) -> anyhow::Result<()> {
    let ceygen = ceygen::ceygen(parties, threshold, &secret_key)?;
    // write the results to a local dir.
    tofn::gg20::ceygen::write_ceygen_results(ceygen, Some(path))?;
    Ok(())
}
