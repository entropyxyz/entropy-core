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
//! TDX attestion related shared types and functions

use crate::X25519PublicKey;
use blake2::{Blake2b, Blake2b512, Digest};
use codec::{Decode, Encode};

/// Input data to be included in a TDX attestation
pub struct QuoteInputData(pub [u8; 64]);

impl QuoteInputData {
    pub fn new<T: Encode>(
        tss_account_id: T,
        x25519_public_key: X25519PublicKey,
        nonce: [u8; 32],
        context: QuoteContext,
    ) -> Self {
        let mut hasher = Blake2b512::new();
        hasher.update(tss_account_id.encode());
        hasher.update(x25519_public_key);
        hasher.update(nonce);
        hasher.update(context.encode());
        Self(hasher.finalize().into())
    }
}

/// An indicator as to the context in which a quote is intended to be used
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuoteContext {
    /// To be used in the `validate` extrinsic
    Validate,
    /// To be used in the `change_endpoint` extrinsic
    ChangeEndpoint,
    /// To be used in the `change_threshold_accounts` extrinsic
    ChangeThresholdAccounts,
    /// To be used when requesting to recover an encryption key
    EncryptionKeyRecoveryRequest,
}

#[cfg(feature = "std")]
impl std::fmt::Display for QuoteContext {
    /// Custom display implementation so that it can be used to build a query string
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuoteContext::Validate => write!(f, "validate"),
            QuoteContext::ChangeEndpoint => write!(f, "change_endpoint"),
            QuoteContext::ChangeThresholdAccounts => write!(f, "change_threshold_accounts"),
            QuoteContext::EncryptionKeyRecoveryRequest => {
                write!(f, "encryption_key_recovery_request")
            },
        }
    }
}

#[cfg(feature = "wasm-no-std")]
use sp_std::vec::Vec;

/// A trait for types which can handle attestation requests.
#[cfg(not(feature = "wasm"))]
pub trait AttestationHandler<AccountId> {
    /// Verify that the given quote is valid and matches the given information about the attestee.
    /// The Provisioning Certification Key (PCK) certifcate chain is extracted from the quote and
    /// verified. If successful, the PCK public key used to sign the quote is returned.
    fn verify_quote(
        attestee: &AccountId,
        x25519_public_key: X25519PublicKey,
        quote: Vec<u8>,
        context: QuoteContext,
    ) -> Result<crate::BoundedVecEncodedVerifyingKey, VerifyQuoteError>;

    /// Indicate to the attestation handler that a quote is desired.
    ///
    /// The `nonce` should be a piece of data (e.g a random number) which indicates that the quote
    /// is reasonably fresh and has not been reused.
    fn request_quote(attestee: &AccountId, nonce: [u8; 32]);
}

/// A convenience implementation for testing and benchmarking.
#[cfg(not(feature = "wasm"))]
impl<AccountId> AttestationHandler<AccountId> for () {
    fn verify_quote(
        _attestee: &AccountId,
        _x25519_public_key: X25519PublicKey,
        _quote: Vec<u8>,
        _context: QuoteContext,
    ) -> Result<crate::BoundedVecEncodedVerifyingKey, VerifyQuoteError> {
        Ok(crate::BoundedVecEncodedVerifyingKey::try_from([0; 33].to_vec()).unwrap())
    }

    fn request_quote(_attestee: &AccountId, _nonce: [u8; 32]) {}
}

/// An error when verifying a quote
#[cfg(not(feature = "wasm"))]
#[derive(Debug, Eq, PartialEq)]
pub enum VerifyQuoteError {
    /// Quote could not be parsed or verified
    BadQuote,
    /// Attestation extrinsic submitted when not requested
    UnexpectedAttestation,
    /// Hashed input data does not match what was expected
    IncorrectInputData,
    /// Unacceptable VM image running
    BadMeasurementValue,
    /// Cannot encode verifying key (PCK)
    CannotEncodeVerifyingKey,
    /// Cannot decode verifying key (PCK)
    CannotDecodeVerifyingKey,
    /// PCK certificate chain cannot be parsed
    PckCertificateParse,
    /// PCK certificate chain cannot be verified
    PckCertificateVerify,
    /// PCK certificate chain public key is not well formed
    PckCertificateBadPublicKey,
    /// Pck certificate could not be extracted from quote
    PckCertificateNoCertificate,
}

#[cfg(feature = "std")]
impl std::fmt::Display for VerifyQuoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyQuoteError::BadQuote => write!(f, "Quote could not be parsed of verified"),
            VerifyQuoteError::UnexpectedAttestation => {
                write!(f, "Attestation extrinsic submitted when not requested")
            },
            VerifyQuoteError::IncorrectInputData => {
                write!(f, "Hashed input data does not match what was expected")
            },
            VerifyQuoteError::BadMeasurementValue => write!(f, "Unacceptable VM image running"),
            VerifyQuoteError::CannotEncodeVerifyingKey => {
                write!(f, "Cannot encode verifying key (PCK)")
            },
            VerifyQuoteError::CannotDecodeVerifyingKey => {
                write!(f, "Cannot decode verifying key (PCK)")
            },
            VerifyQuoteError::PckCertificateParse => {
                write!(f, "PCK certificate chain cannot be parsed")
            },
            VerifyQuoteError::PckCertificateVerify => {
                write!(f, "PCK certificate chain cannot be verified")
            },
            VerifyQuoteError::PckCertificateBadPublicKey => {
                write!(f, "PCK certificate chain public key is not well formed")
            },
            VerifyQuoteError::PckCertificateNoCertificate => {
                write!(f, "PCK certificate could not be extracted from quote")
            },
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyQuoteError {}

/// Verify a PCK certificate chain from a quote in production
#[cfg(feature = "production")]
pub fn verify_pck_certificate_chain(
    quote: &tdx_quote::Quote,
) -> Result<tdx_quote::VerifyingKey, VerifyQuoteError> {
    quote.verify().map_err(|_| VerifyQuoteError::PckCertificateVerify)
}

/// A mock version of verifying the PCK certificate chain.
/// When generating mock quotes, we just put the encoded PCK in place of the certificate chain
/// so this function just decodes it, checks it was used to sign the quote, and returns it
#[cfg(not(any(feature = "production", feature = "wasm")))]
pub fn verify_pck_certificate_chain(
    quote: &tdx_quote::Quote,
) -> Result<tdx_quote::VerifyingKey, VerifyQuoteError> {
    let provisioning_certification_key =
        quote.pck_cert_chain().map_err(|_| VerifyQuoteError::PckCertificateNoCertificate)?;
    let provisioning_certification_key = tdx_quote::decode_verifying_key(
        &provisioning_certification_key
            .try_into()
            .map_err(|_| VerifyQuoteError::CannotDecodeVerifyingKey)?,
    )
    .map_err(|_| VerifyQuoteError::CannotDecodeVerifyingKey)?;

    quote
        .verify_with_pck(&provisioning_certification_key)
        .map_err(|_| VerifyQuoteError::PckCertificateVerify)?;
    Ok(provisioning_certification_key)
}

/// Create a measurement value by hashing together all measurement registers from quote data
pub fn compute_quote_measurement(quote: &tdx_quote::Quote) -> [u8; 32] {
    let mut hasher = Blake2b::new();
    hasher.update(quote.mrtd());
    hasher.update(quote.rtmr0());
    hasher.update(quote.rtmr1());
    hasher.update(quote.rtmr2());
    hasher.update(quote.rtmr3());
    hasher.finalize().into()
}
