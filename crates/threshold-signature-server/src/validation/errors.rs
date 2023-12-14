use entropy_protocol::sign_and_encrypt::SignedMessageErr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationErr {
    #[error("Encryption or signing error: {0}")]
    Json(#[from] SignedMessageErr),
    #[error("Secret String failure: {0:?}")]
    SecretString(&'static str),
    #[error("Message is too old")]
    StaleMessage,
    #[error("Time subtraction error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
}
