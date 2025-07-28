use crate::errors::ClientError;
use entropy_shared::{
    attestation::{QuoteContext, QuoteInputData},
    BoundedVecEncodedVerifyingKey,
};
use subxt::utils::AccountId32;

/// Create a mock TDX quote for testing on non-TDX hardware
#[cfg(not(feature = "production"))]
pub async fn create_quote(
    nonce: [u8; 32],
    account_id: AccountId32,
    x25519_public_key: &[u8; 32],
    context: QuoteContext,
) -> Result<Vec<u8>, ClientError> {
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::OsRng;

    // In the real thing this is the key used in the quoting enclave
    let signing_key = tdx_quote::SigningKey::random(&mut OsRng);

    let input_data = QuoteInputData::new(account_id.clone(), *x25519_public_key, nonce, context);

    // This is generated deterministically from account id
    let mut pck_seeder = StdRng::from_seed(account_id.0);
    let pck = tdx_quote::SigningKey::random(&mut pck_seeder);

    let pck_encoded = tdx_quote::encode_verifying_key(pck.verifying_key())?.to_vec();
    let quote = tdx_quote::Quote::mock(signing_key.clone(), pck, input_data.0, pck_encoded)
        .as_bytes()
        .to_vec();
    Ok(quote)
}

/// Create a TDX quote in production
#[cfg(feature = "production")]
pub async fn create_quote(
    nonce: [u8; 32],
    account_id: AccountId32,
    x25519_public_key: &[u8; 32],
    context: QuoteContext,
) -> Result<Vec<u8>, ClientError> {
    let input_data = QuoteInputData::new(account_id, *x25519_public_key, nonce, context);

    Ok(configfs_tsm::create_quote(input_data.0)
        .map_err(|e| ClientError::QuoteGeneration(format!("{:?}", e)))?)
}

/// Get the measurement value from this build by generating a quote.
/// This is used by the `/version` HTTP route to display measurement details of the current build.
#[cfg(feature = "production")]
pub fn get_measurement_value() -> Result<[u8; 32], ClientError> {
    let quote_raw = configfs_tsm::create_quote([0; 64])
        .map_err(|e| ClientError::QuoteGeneration(format!("{:?}", e)))?;
    let quote = tdx_quote::Quote::from_bytes(&quote_raw)?;
    Ok(entropy_shared::attestation::compute_quote_measurement(&quote))
}

/// Get our Provisioning Certification Key (PCK)
/// This generates a quote and gets the public key from it
#[cfg(feature = "production")]
pub fn get_pck(_account_id: AccountId32) -> Result<BoundedVecEncodedVerifyingKey, ClientError> {
    let quote_raw = configfs_tsm::create_quote([0; 64])
        .map_err(|e| ClientError::QuoteGeneration(format!("{:?}", e)))?;
    let quote = tdx_quote::Quote::from_bytes(&quote_raw)?;
    let pck = quote.verify().map_err(|e| {
        ClientError::QuoteGeneration(format!("Could not get PCK from quote {:?}", e))
    })?;

    let pck =
        BoundedVecEncodedVerifyingKey::try_from(tdx_quote::encode_verifying_key(&pck)?.to_vec())
            .map_err(|_| ClientError::BadVerifyingKeyLength)?;
    Ok(pck)
}

/// Get our Provisioning Certification Key (PCK)
/// In mock mode, this is derived from the TSS account ID
#[cfg(not(feature = "production"))]
#[allow(clippy::result_large_err)]
pub fn get_pck(account_id: AccountId32) -> Result<BoundedVecEncodedVerifyingKey, ClientError> {
    use rand::{rngs::StdRng, SeedableRng};

    // This is generated deterministically from account id
    let mut pck_seeder = StdRng::from_seed(account_id.0);
    let pck = tdx_quote::SigningKey::random(&mut pck_seeder);

    let pck = BoundedVecEncodedVerifyingKey::try_from(
        tdx_quote::encode_verifying_key(pck.verifying_key())?.to_vec(),
    )
    .map_err(|_| ClientError::BadVerifyingKeyLength)?;
    Ok(pck)
}
