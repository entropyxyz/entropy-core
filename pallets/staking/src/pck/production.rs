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
use spki::{
    der::{asn1::BitString, Any},
    SubjectPublicKeyInfo,
};
use x509_verify::{
    der::{Decode, Encode},
    x509_cert::Certificate,
    Signature, VerifyInfo, VerifyingKey,
};

use super::{CompressedVerifyingKey, PckCertChainVerifier, PckParseVerifyError};

/// Intel's root public key together with metadata, encoded as der
const INTEL_ROOT_CA_PK_DER: [u8; 91] = [
    48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66,
    0, 4, 11, 169, 196, 192, 192, 200, 97, 147, 163, 254, 35, 214, 176, 44, 218, 16, 168, 187, 212,
    232, 142, 72, 180, 69, 133, 97, 163, 110, 112, 85, 37, 245, 103, 145, 142, 46, 220, 136, 228,
    13, 134, 11, 208, 204, 78, 226, 106, 172, 201, 136, 229, 5, 169, 83, 85, 140, 69, 63, 107, 9,
    4, 174, 115, 148,
];

/// A PCK certificate chain verifyer for use in production where entropy-tss is running on TDX
/// hardware and we have a PCK certificate chain
pub struct ProductionPckCertChainVerifyer {}

impl PckCertChainVerifier for ProductionPckCertChainVerifyer {
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

    // Get the rook public key
    let root_pk: SubjectPublicKeyInfo<Any, BitString> =
        SubjectPublicKeyInfo::from_der(&INTEL_ROOT_CA_PK_DER)?;
    let root_pk: VerifyingKey = root_pk.try_into()?;

    // Verify the certificate chain
    for i in 0..certificates.len() {
        let verifying_key: &VerifyingKey = if i + 1 == certificates.len() {
            &root_pk
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
        subject.tbs_certificate.to_der().unwrap().into(),
        Signature::new(&subject.signature_algorithm, subject.signature.as_bytes().unwrap()),
    );
    Ok(issuer_pk.verify(&verify_info)?)
}
