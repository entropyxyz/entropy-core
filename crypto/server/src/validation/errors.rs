use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationErr {
    #[error("ChaCha20 decryption error: {0}")]
    Decryption(String),
    #[error("ChaCha20 Encryption error: {0}")]
    Encryption(String),
    #[error("ChaCha20 Conversion error: {0}")]
    Conversion(String),
    #[error("Secret String failure: {0:?}")]
    SecretString(&'static str),
    #[error("Message is too old")]
    StaleMessage,
    #[error("Time subtraction error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
}
