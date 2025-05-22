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

//! # Outtie Pallet
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unused_unit)]

use entropy_shared::{
    attestation::{AttestationHandler, QuoteContext, VerifyQuoteError},
    X25519PublicKey, VERIFICATION_KEY_LENGTH,
};
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_runtime::DispatchResult;
use sp_std::vec::Vec;
#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod weights;

pub use module::*;
pub use weights::WeightInfo;

#[frame_support::pallet]
pub mod module {
    use super::*;

    // TODO put this somewhere common to here and the staking pallet
    pub type VerifyingKey = BoundedVec<u8, ConstU32<VERIFICATION_KEY_LENGTH>>;

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_session::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// The maximum length of an API box server's endpoint address, in bytes.
        type MaxEndpointLength: Get<u32>;

        /// Weight information for the extrinsics in this module.
        type WeightInfo: WeightInfo;

        /// The handler to use when issuing and verifying attestations.
        type AttestationHandler: AttestationHandler<Self::AccountId>;
    }

    /// Information about a joining Outtie server
    #[derive(Encode, Decode, Clone, Eq, PartialEq, RuntimeDebug, TypeInfo)]
    #[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
    pub struct JoiningOuttieServerInfo {
        pub x25519_public_key: X25519PublicKey,
        pub endpoint: Vec<u8>,
    }

    /// Information about an Outtie server
    #[derive(Encode, Decode, Clone, Eq, PartialEq, RuntimeDebug, TypeInfo)]
    #[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
    pub struct OuttieServerInfo {
        pub x25519_public_key: X25519PublicKey,
        pub endpoint: Vec<u8>,
        pub provisioning_certification_key: VerifyingKey,
    }

    /// API box signing account => Server Info
    #[pallet::storage]
    #[pallet::getter(fn get_api_boxes)]
    pub type ApiBoxes<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, OuttieServerInfo, OptionQuery>;

    #[pallet::error]
    pub enum Error<T> {
        /// Endpoint is too long
        EndpointTooLong,
        /// Box account already exists
        BoxAccountAlreadyExists,
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

    impl<T> From<VerifyQuoteError> for Error<T> {
        /// As there are many reasons why quote verification can fail we want these error types to
        /// be reflected in the dispatch errors from extrinsics in this pallet which do quote
        /// verification
        fn from(error: VerifyQuoteError) -> Self {
            match error {
                VerifyQuoteError::BadQuote => Error::<T>::BadQuote,
                VerifyQuoteError::UnexpectedAttestation => Error::<T>::UnexpectedAttestation,
                VerifyQuoteError::IncorrectInputData => Error::<T>::IncorrectInputData,
                VerifyQuoteError::BadMeasurementValue => Error::<T>::BadMeasurementValue,
                VerifyQuoteError::CannotEncodeVerifyingKey => Error::<T>::CannotEncodeVerifyingKey,
                VerifyQuoteError::PckCertificateParse => Error::<T>::PckCertificateParse,
                VerifyQuoteError::PckCertificateVerify => Error::<T>::PckCertificateVerify,
                VerifyQuoteError::PckCertificateBadPublicKey => {
                    Error::<T>::PckCertificateBadPublicKey
                },
                VerifyQuoteError::PckCertificateNoCertificate => {
                    Error::<T>::PckCertificateNoCertificate
                },
                VerifyQuoteError::CannotDecodeVerifyingKey => Error::<T>::CannotDecodeVerifyingKey,
            }
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(fn deposit_event)]
    pub enum Event<T: Config> {
        BoxAdded { box_account: T::AccountId, server_info: OuttieServerInfo },
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(1)]
        #[pallet::weight(<T as Config>::WeightInfo::add_box())]
        pub fn add_box(
            origin: OriginFor<T>,
            joining_server_info: JoiningOuttieServerInfo,
            quote: Vec<u8>,
        ) -> DispatchResult {
            let box_account = ensure_signed(origin.clone())?;

            ensure!(
                joining_server_info.endpoint.len() as u32 <= T::MaxEndpointLength::get(),
                Error::<T>::EndpointTooLong
            );

            ensure!(
                !ApiBoxes::<T>::contains_key(&box_account),
                Error::<T>::BoxAccountAlreadyExists
            );

            let provisioning_certification_key =
                <T::AttestationHandler as entropy_shared::attestation::AttestationHandler<_>>::verify_quote(
                    &box_account,
                    joining_server_info.x25519_public_key,
                    quote,
                    QuoteContext::OuttieAddBox,
                )
                .map_err(<VerifyQuoteError as Into<Error<T>>>::into)?;

            let server_info = OuttieServerInfo {
                x25519_public_key: joining_server_info.x25519_public_key,
                endpoint: joining_server_info.endpoint,
                provisioning_certification_key,
            };

            ApiBoxes::<T>::insert(&box_account, server_info.clone());

            Self::deposit_event(Event::BoxAdded { box_account, server_info });

            Ok(())
        }
    }
}
