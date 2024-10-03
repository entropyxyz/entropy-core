use super::{CompressedVerifyingKey, PckCertChainVerifier, PckParseVerifyError};
use sp_runtime::BoundedVec;

pub struct MockPckCertChainVerifyer {}

impl PckCertChainVerifier for MockPckCertChainVerifyer {
    fn verify_pck_certificate_chain(
        _pck_certificate_chain: Vec<Vec<u8>>,
    ) -> Result<CompressedVerifyingKey, PckParseVerifyError> {
        // TODO we want them to give a tss account id, from which we derive a keypair
        // let mut pck_seeder = StdRng::from_seed(tss_accound_id);
        // let pck_secret = p256::SigningKey::random(&mut pck_seeder);
        // let pck_public = VerifyingKey::from(&pck_secret);
        // let pck_public = pck_public.to_encoded_point(true).as_bytes().to_vec();
        // Ok(pck_public.try_into().unwrap())
        Ok(BoundedVec::with_max_capacity())
    }
}
