use std::time::{Duration, SystemTime};

use bip39::Mnemonic;
use subxt::ext::sp_core::{sr25519, Pair};
pub use x25519_chacha20poly1305::{derive_static_secret, SignedMessage, SignedMessageErr};

pub mod errors;

use errors::ValidationErr;

pub const TIME_BUFFER: Duration = Duration::from_secs(25);

/// Derives a sr25519::Pair from a Mnemonic
pub fn mnemonic_to_pair(m: &Mnemonic) -> Result<sr25519::Pair, ValidationErr> {
    Ok(<sr25519::Pair as Pair>::from_phrase(m.phrase(), None)
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
#[cfg(test)]
/// Creates a new random Mnemonic.
pub fn new_mnemonic() -> Mnemonic {
    Mnemonic::new(bip39::MnemonicType::Words24, bip39::Language::English)
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
