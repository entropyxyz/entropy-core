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
mod mock;
pub use mock::{MockPckCertChainVerifyer, MOCK_PCK_DERIVED_FROM_NULL_ARRAY};
mod production;
use super::VerifyingKey as CompressedVerifyingKey;
use core::array::TryFromSliceError;
use sp_std::vec::Vec;

pub trait PckCertChainVerifier {
    fn verify_pck_certificate_chain(
        pck_certificate_chain: Vec<Vec<u8>>,
    ) -> Result<CompressedVerifyingKey, PckParseVerifyError>;
}

/// An error when parsing or verifying a PCK or provider certificate
#[derive(Debug)]
pub enum PckParseVerifyError {
    Parse,
    Verify,
    BadPublicKey,
    NoCertificate,
}

impl From<spki::der::Error> for PckParseVerifyError {
    fn from(_: spki::der::Error) -> PckParseVerifyError {
        PckParseVerifyError::Parse
    }
}

impl From<x509_verify::Error> for PckParseVerifyError {
    fn from(_: x509_verify::Error) -> PckParseVerifyError {
        PckParseVerifyError::Verify
    }
}

impl From<TryFromSliceError> for PckParseVerifyError {
    fn from(_: TryFromSliceError) -> PckParseVerifyError {
        PckParseVerifyError::BadPublicKey
    }
}
