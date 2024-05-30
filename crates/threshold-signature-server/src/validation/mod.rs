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

use std::time::{Duration, SystemTime};

use bip39::Mnemonic;
pub use entropy_protocol::sign_and_encrypt::{
    EncryptedSignedMessage, EncryptedSignedMessageErr, SignedMessage,
};
use entropy_shared::BlockNumber;
use rand_core::{OsRng, RngCore};
use subxt::{
    backend::legacy::LegacyRpcMethods,
    ext::sp_core::{sr25519, Pair},
};
pub mod errors;
use crate::chain_api::EntropyConfig;
use errors::ValidationErr;

pub const BLOCK_BUFFER: BlockNumber = 5u32;

/// Derives a sr25519::Pair from a Mnemonic
pub fn mnemonic_to_pair(m: &Mnemonic) -> Result<sr25519::Pair, ValidationErr> {
    Ok(<sr25519::Pair as Pair>::from_phrase(&m.to_string(), None)
        .map_err(|_| ValidationErr::SecretString("Secret String Error"))?
        .0)
}

/// Checks if the message sent was within X amount of time
pub async fn check_stale(
    user_block_number: BlockNumber,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<(), ValidationErr> {
    let block_number =
        rpc.chain_get_header(None).await?.ok_or_else(|| ValidationErr::BlockNumber)?.number;
    let block_difference =
        block_number.checked_sub(user_block_number).ok_or(ValidationErr::StaleMessage)?;
    if block_difference > BLOCK_BUFFER {
        return Err(ValidationErr::StaleMessage);
    }
    Ok(())
}

/// Creates a new random Mnemonic.
pub fn new_mnemonic() -> Result<Mnemonic, bip39::Error> {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    Mnemonic::from_entropy(&entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stale_check() {
        let result = check_stale(SystemTime::now());
        assert!(result.is_ok());

        let fail_time =
            SystemTime::now().checked_sub(TIME_BUFFER).unwrap().checked_sub(TIME_BUFFER).unwrap();
        let fail_stale = check_stale(fail_time).unwrap_err();
        assert_eq!(fail_stale.to_string(), "Message is too old".to_string());

        let future_time = SystemTime::now().checked_add(TIME_BUFFER).unwrap();
        let fail_future = check_stale(future_time).unwrap_err();
        assert_eq!(
            fail_future.to_string(),
            "Time subtraction error: second time provided was later than self".to_string()
        );
    }
}
