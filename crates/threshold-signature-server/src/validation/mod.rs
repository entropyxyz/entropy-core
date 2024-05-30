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

use bip39::Mnemonic;
pub use entropy_protocol::sign_and_encrypt::{
    EncryptedSignedMessage, EncryptedSignedMessageErr, SignedMessage,
};
use entropy_shared::BlockNumber;
use rand_core::{OsRng, RngCore};
use subxt::ext::sp_core::{sr25519, Pair};
pub mod errors;
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
    chain_block_number: BlockNumber,
) -> Result<(), ValidationErr> {
    let block_difference = if chain_block_number > user_block_number {
        chain_block_number.checked_sub(user_block_number).ok_or(ValidationErr::StaleMessage)?
    } else {
        user_block_number.checked_sub(chain_block_number).ok_or(ValidationErr::StaleMessage)?
    };

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

    #[tokio::test]
    async fn test_stale_check() {
        let result = check_stale(1, 1).await;
        assert!(result.is_ok());

        let result_server_larger = check_stale(1, 2).await;
        assert!(result_server_larger.is_ok());

        let result_user_larger = check_stale(2, 1).await;
        assert!(result_user_larger.is_ok());

        let fail_stale = check_stale(1, 2 + BLOCK_BUFFER).await.unwrap_err();
        assert_eq!(fail_stale.to_string(), "Message is too old".to_string());
    }
}
