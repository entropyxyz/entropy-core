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
use super::{CompressedVerifyingKey, PckCertChainVerifier, PckParseVerifyError};

/// Intel's root public key together with metadata, encoded as der
const INTEL_ROOT_CA_PK_DER: [u8; 91] = [
    48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66,
    0, 4, 11, 169, 196, 192, 192, 200, 97, 147, 163, 254, 35, 214, 176, 44, 218, 16, 168, 187, 212,
    232, 142, 72, 180, 69, 133, 97, 163, 110, 112, 85, 37, 245, 103, 145, 142, 46, 220, 136, 228,
    13, 134, 11, 208, 204, 78, 226, 106, 172, 201, 136, 229, 5, 169, 83, 85, 140, 69, 63, 107, 9,
    4, 174, 115, 148,
];

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

pub struct ProductionPckCertChainVerifyer {}

impl PckCertChainVerifier for ProductionPckCertChainVerifyer {
    fn verify_pck_certificate_chain(
        pck_certificate_chain: Vec<Vec<u8>>,
    ) -> Result<CompressedVerifyingKey, PckParseVerifyError> {
        // TODO validate chain of arbitrary length
        let pck_uncompressed = parse_pck_cert_chain(
            pck_certificate_chain.get(0).unwrap().to_vec(),
            pck_certificate_chain.get(1).unwrap().to_vec(),
        )?;
        // Compress public key
        let point = p256::EncodedPoint::from_bytes(pck_uncompressed).unwrap();
        let pck_verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&point).unwrap();
        let pck_compressed = pck_verifying_key.to_encoded_point(true).as_bytes().to_vec();
        Ok(pck_compressed.try_into().unwrap())
    }
}

/// Given a cerificate and a public key, verify the certificate
fn verify_cert(subject: &Certificate, issuer_pk: VerifyingKey) -> Result<(), PckParseVerifyError> {
    let verify_info = VerifyInfo::new(
        subject.tbs_certificate.to_der().unwrap().into(),
        Signature::new(&subject.signature_algorithm, subject.signature.as_bytes().unwrap()),
    );
    Ok(issuer_pk.verify(&verify_info)?)
}

/// Validate PCK and provider certificates and if valid return the PCK
/// These certificates will be provided by a joining validator
pub fn parse_pck_cert_chain(
    pck: Vec<u8>,
    pck_provider: Vec<u8>,
) -> Result<[u8; 65], PckParseVerifyError> {
    let pck = Certificate::from_der(&pck)?;
    let provider = Certificate::from_der(&pck_provider)?;
    let root_pk: SubjectPublicKeyInfo<Any, BitString> =
        SubjectPublicKeyInfo::from_der(&INTEL_ROOT_CA_PK_DER)?;
    verify_cert(&provider, root_pk.try_into()?)?;

    let provider_verifying_key: VerifyingKey =
        provider.tbs_certificate.subject_public_key_info.try_into()?;
    verify_cert(&pck, provider_verifying_key)?;

    let pck_key = pck.tbs_certificate.subject_public_key_info.subject_public_key;

    Ok(pck_key.as_bytes().ok_or(PckParseVerifyError::BadPublicKey)?.try_into()?)
}
