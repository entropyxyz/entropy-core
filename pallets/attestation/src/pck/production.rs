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
use sp_std::vec::Vec;
use x509_verify::{
    der::{Decode, Encode},
    x509_cert::Certificate,
    Signature, VerifyInfo, VerifyingKey,
};

use super::{CompressedVerifyingKey, PckCertChainVerifier, PckParseVerifyError};

/// Intels root CA certificate in DER format available from here:
/// https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer
/// Valid until December 31 2049
const INTEL_ROOT_CA_DER: &[u8; 659] =
    include_bytes!("Intel_SGX_Provisioning_Certification_RootCA.cer");

/// A PCK certificate chain verifier for use in production where entropy-tss is running on TDX
/// hardware and we have a PCK certificate chain
pub struct ProductionPckCertChainVerifier {}

impl PckCertChainVerifier for ProductionPckCertChainVerifier {
    fn verify_pck_certificate_chain(
        pck_certificate_chain: Vec<Vec<u8>>,
    ) -> Result<CompressedVerifyingKey, PckParseVerifyError> {
        let pck_uncompressed = verify_pck_cert_chain(pck_certificate_chain)?;

        // Compress / convert public key
        let point = p256::EncodedPoint::from_bytes(pck_uncompressed)
            .map_err(|_| PckParseVerifyError::BadPublicKey)?;
        let pck_verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
            .map_err(|_| PckParseVerifyError::BadPublicKey)?;
        let pck_compressed = pck_verifying_key.to_encoded_point(true).as_bytes().to_vec();
        pck_compressed.try_into().map_err(|_| PckParseVerifyError::BadPublicKey)
    }
}

/// Validate PCK and provider certificates and if valid return the PCK
/// These certificates will be provided by a joining validator
fn verify_pck_cert_chain(certificates_der: Vec<Vec<u8>>) -> Result<[u8; 65], PckParseVerifyError> {
    if certificates_der.is_empty() {
        return Err(PckParseVerifyError::NoCertificate);
    }

    // Parse the certificates
    let mut certificates = Vec::new();
    for certificate in certificates_der {
        certificates.push(Certificate::from_der(&certificate)?);
    }
    // Add the root certificate to the end of the chain. Since the root cert is self-signed, this
    // will work regardless of whether the user has included this certicate in the chain or not
    certificates.push(Certificate::from_der(INTEL_ROOT_CA_DER)?);

    // Verify the certificate chain
    for i in 0..certificates.len() {
        let verifying_key: &VerifyingKey = if i + 1 == certificates.len() {
            &certificates[i].tbs_certificate.subject_public_key_info.clone().try_into()?
        } else {
            &certificates[i + 1].tbs_certificate.subject_public_key_info.clone().try_into()?
        };
        verify_cert(&certificates[i], verifying_key)?;
    }

    // Get the first certificate
    let pck_key = &certificates
        .first()
        .ok_or(PckParseVerifyError::NoCertificate)?
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key;

    Ok(pck_key.as_bytes().ok_or(PckParseVerifyError::BadPublicKey)?.try_into()?)
}

/// Given a cerificate and a public key, verify the certificate
fn verify_cert(subject: &Certificate, issuer_pk: &VerifyingKey) -> Result<(), PckParseVerifyError> {
    let verify_info = VerifyInfo::new(
        subject.tbs_certificate.to_der()?.into(),
        Signature::new(
            &subject.signature_algorithm,
            subject.signature.as_bytes().ok_or(PckParseVerifyError::Parse)?,
        ),
    );
    Ok(issuer_pk.verify(&verify_info)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_pck_cert_chain() {
        let pck = include_bytes!("../../test_pck_certs/pck_cert.der").to_vec();
        let platform = include_bytes!("../../test_pck_certs/platform_pcs_cert.der").to_vec();
        assert!(ProductionPckCertChainVerifier::verify_pck_certificate_chain(vec![pck, platform])
            .is_ok());
    }
}
