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
use rand_core::{OsRng, RngCore};
use subxt::ext::sp_core::{sr25519, Pair};

pub mod errors;

use errors::ValidationErr;

pub const TIME_BUFFER: Duration = Duration::from_secs(25);

/// Derives a sr25519::Pair from a Mnemonic
pub fn mnemonic_to_pair(m: &Mnemonic) -> Result<sr25519::Pair, ValidationErr> {
    Ok(<sr25519::Pair as Pair>::from_phrase(&m.to_string(), None)
        .map_err(|_| ValidationErr::SecretString("Secret String Error"))?
        .0)
}

/// Checks if the message sent was within X amount of time
pub fn check_stale(message_time: SystemTime) -> Result<(), ValidationErr> {
    let time_difference = SystemTime::now().duration_since(message_time)?;
    if time_difference > TIME_BUFFER {
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
