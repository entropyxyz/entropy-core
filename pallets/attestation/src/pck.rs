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

use x509_parser::{
    certificate::X509Certificate, error::X509Error, prelude::FromDer, public_key::PublicKey,
    x509::SubjectPublicKeyInfo,
};

/// Intel's root public key together with metadata, encoded as der
const INTEL_ROOT_CA_PK_DER: [u8; 91] = [
    48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66,
    0, 4, 11, 169, 196, 192, 192, 200, 97, 147, 163, 254, 35, 214, 176, 44, 218, 16, 168, 187, 212,
    232, 142, 72, 180, 69, 133, 97, 163, 110, 112, 85, 37, 245, 103, 145, 142, 46, 220, 136, 228,
    13, 134, 11, 208, 204, 78, 226, 106, 172, 201, 136, 229, 5, 169, 83, 85, 140, 69, 63, 107, 9,
    4, 174, 115, 148,
];

/// Parse a der encoded certificate to an X509Certificate struct
fn parse_der(input: &[u8]) -> Result<X509Certificate, X509Error> {
    let (_remaining, cert) = X509Certificate::from_der(input)?;
    Ok(cert)
}

/// Given an X509Certificate, get the subject public key, assuming it is ECDSA, and encoded it to
/// bytes
fn x509_to_subject_public_key(input: X509Certificate) -> Result<Vec<u8>, X509Error> {
    let public_key = input.tbs_certificate.subject_pki.parsed()?;
    match public_key {
        PublicKey::EC(ec_point) => Ok(ec_point.data().to_vec()),
        _ => Err(X509Error::Generic),
    }
}

/// Validate PCK and provider certificates and if valid return the PCK
/// These certificates will be provided by a joining validator
pub fn parse_pck_cert_chain(pck: Vec<u8>, pck_provider: Vec<u8>) -> Result<[u8; 65], X509Error> {
    // Parse input certificates from der encoding
    let pck = parse_der(&pck)?;
    let pck_provider = parse_der(&pck_provider)?;

    // Check PCK signature matches provider public key
    pck.verify_signature(Some(pck_provider.public_key()))?;

    // Check provider signature matches root public key
    let (_, root_public_key) = SubjectPublicKeyInfo::from_der(&INTEL_ROOT_CA_PK_DER)?;
    pck_provider.verify_signature(Some(&root_public_key))?;

    // Return the PCK public key
    Ok(x509_to_subject_public_key(pck)?.try_into().unwrap())
}
