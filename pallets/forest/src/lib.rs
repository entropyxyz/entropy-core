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

//! # Forest Pallet
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unused_unit)]

use entropy_shared::{
    attestation::{AttestationHandler, QuoteContext, VerifyQuoteError},
    X25519PublicKey, VERIFICATION_KEY_LENGTH,
};
use frame_support::{pallet_prelude::*, traits::IsSubType};
use frame_system::pallet_prelude::*;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_runtime::{
    impl_tx_ext_default,
    traits::{
        Bounded, DispatchInfoOf, DispatchOriginOf, SignedExtension, TransactionExtension,
        ValidateResult,
    },
    transaction_validity, DispatchResult,
};
use sp_std::{fmt::Debug, vec::Vec};
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

        /// The maximum length of an API tree server's endpoint address, in bytes.
        type MaxEndpointLength: Get<u32>;

        /// Weight information for the extrinsics in this module.
        type WeightInfo: WeightInfo;

        /// The handler to use when issuing and verifying attestations.
        type AttestationHandler: AttestationHandler<Self::AccountId>;
    }

    /// Information about an Forest server
    #[derive(
        Encode, Decode, Clone, Eq, PartialEq, RuntimeDebug, DecodeWithMemTracking, TypeInfo,
    )]
    #[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
    pub struct ForestServerInfo {
        pub x25519_public_key: X25519PublicKey,
        pub endpoint: Vec<u8>,
        /// The TDX quote provided when declaring the tree to the chain
        pub tdx_quote: Vec<u8>,
    }

    /// Tree signing account => Server Info
    #[pallet::storage]
    #[pallet::getter(fn get_trees)]
    pub type Trees<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, ForestServerInfo, OptionQuery>;

    #[pallet::error]
    pub enum Error<T> {
        /// Endpoint is too long
        EndpointTooLong,
        /// Tree account already exists
        TreeAccountAlreadyExists,
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
        TreeAdded { tree_account: T::AccountId, server_info: ForestServerInfo },
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(1)]
        #[pallet::weight((<T as Config>::WeightInfo::add_tree(), Pays::No))]
        pub fn add_tree(origin: OriginFor<T>, server_info: ForestServerInfo) -> DispatchResult {
            let tree_account = ensure_signed(origin.clone())?;

            ensure!(
                server_info.endpoint.len() as u32 <= T::MaxEndpointLength::get(),
                Error::<T>::EndpointTooLong
            );

            ensure!(!Trees::<T>::contains_key(&tree_account), Error::<T>::TreeAccountAlreadyExists);

            let _provisioning_certification_key =
                <T::AttestationHandler as entropy_shared::attestation::AttestationHandler<_>>::verify_quote(
                    &tree_account,
                    server_info.x25519_public_key,
                    server_info.tdx_quote.clone(),
                    QuoteContext::ForestAddTree,
                )
                .map_err(<VerifyQuoteError as Into<Error<T>>>::into)?;

            Trees::<T>::insert(&tree_account, server_info.clone());

            Self::deposit_event(Event::TreeAdded { tree_account, server_info });

            Ok(())
        }
    }

    #[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct ValidateAddTree<T: Config + Send + Sync>(pub PhantomData<T>);

    impl<T: Config + Send + Sync> core::fmt::Debug for ValidateAddTree<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(f, "ValidateAddTree")
        }
    }

    impl<T: Config + Send + Sync> ValidateAddTree<T>
    where
        <T as frame_system::Config>::RuntimeCall: IsSubType<Call<T>>,
    {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self(sp_std::marker::PhantomData)
        }
    }

    impl<T: Config + Send + Sync> TransactionExtension<<T as frame_system::Config>::RuntimeCall>
        for ValidateAddTree<T>
    where
        <T as frame_system::Config>::RuntimeCall: IsSubType<Call<T>>,
    {
        const IDENTIFIER: &'static str = "ValidateAddTree";
        type Implicit = ();
        type Pre = ();
        type Val = ();

        fn validate(
            &self,
            origin: DispatchOriginOf<<T as frame_system::Config>::RuntimeCall>,
            call: &<T as frame_system::Config>::RuntimeCall,
            _info: &DispatchInfoOf<<T as frame_system::Config>::RuntimeCall>,
            len: usize,
            _self_implicit: Self::Implicit,
            _inherited_implication: &impl Encode,
            _source: TransactionSource,
        ) -> ValidateResult<Self::Val, <T as frame_system::Config>::RuntimeCall> {
            // if the transaction is too big, just drop it.
            if len > 200 {
                return Err(InvalidTransaction::ExhaustsResources.into());
            }
            // check for `add_tree`
            let validity = match call.is_sub_type() {
                Some(Call::add_tree { server_info }) => {
                    sp_runtime::print("add_tree was received.");

                    if server_info.endpoint.len() as u32 >= T::MaxEndpointLength::get() {
                        return Err(TransactionValidityError::Invalid(
                            (InvalidTransaction::Custom(0)),
                        ));
                    }

                    let valid_tx =
                        ValidTransaction { priority: Bounded::max_value(), ..Default::default() };
                    valid_tx
                },
                _ => Default::default(),
            };
            Ok((validity, (), origin))
        }
        impl_tx_ext_default!(<T as frame_system::Config>::RuntimeCall; weight prepare);
    }
}
