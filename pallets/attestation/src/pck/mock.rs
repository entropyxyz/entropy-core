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
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::{rngs::StdRng, SeedableRng};
use sp_std::vec::Vec;

/// This is used in the benchmarking tests to check that ServerInfo is as expected
pub const MOCK_PCK_DERIVED_FROM_NULL_ARRAY: [u8; 33] = [
    3, 237, 193, 27, 177, 204, 234, 67, 54, 141, 157, 13, 62, 87, 113, 224, 4, 121, 206, 251, 190,
    151, 134, 87, 68, 46, 37, 163, 127, 97, 252, 174, 108,
];

/// A PCK certificate chain verifier for testing.
/// Rather than actually use test certificates, we give here the TSS account ID instead of the first
/// certificate, and derive a keypair from it. The same keypair will be derived when creating a mock
/// quote in entropy-tss
pub struct MockPckCertChainVerifier {}

impl PckCertChainVerifier for MockPckCertChainVerifier {
    fn verify_pck_certificate_chain(
        pck_certificate_chain: Vec<Vec<u8>>,
    ) -> Result<CompressedVerifyingKey, PckParseVerifyError> {
        let first_certificate =
            pck_certificate_chain.first().ok_or(PckParseVerifyError::NoCertificate)?;

        // Read the certificate bytes as a TSS account id
        let tss_account_id: [u8; 32] =
            first_certificate.clone().try_into().map_err(|_| PckParseVerifyError::Parse)?;

        // Derive a keypair
        let pck_secret = signing_key_from_seed(tss_account_id);

        // Convert/compress the public key
        let pck_public = VerifyingKey::from(&pck_secret);
        let pck_public = pck_public.to_encoded_point(true).as_bytes().to_vec();
        pck_public.try_into().map_err(|_| PckParseVerifyError::Parse)
    }
}

pub fn signing_key_from_seed(input: [u8; 32]) -> SigningKey {
    let mut pck_seeder = StdRng::from_seed(input);
    SigningKey::random(&mut pck_seeder)
}
