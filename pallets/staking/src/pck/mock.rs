use super::{CompressedVerifyingKey, PckCertChainVerifier, PckParseVerifyError};

pub struct MockPckCertChainVerifyer {}

impl PckCertChainVerifier for MockPckCertChainVerifyer {
    fn verify_pck_cert_chain(
        pck_cert: Vec<u8>,
        _provider_cert: Vec<u8>,
    ) -> Result<CompressedVerifyingKey, PckParseVerifyError> {
        Ok(pck_cert.try_into().unwrap())
    }
}
