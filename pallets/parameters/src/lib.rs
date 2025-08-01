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

//! # Parameters Pallet
//!
//! ## Overview
//!
//! A pallet to manage parameters by the threshold servers.
//!
//! By storing parameters onchain we can make sure all threshold servers are in consensus to what
//! the parameter values should be.
//!
//! Additionally, this gives the ability for on-chain governance to decide on what the values should
//! be.
//!
//! ## Interface
//!
//! ### Dispatchable Functions
//!
//! `change_request_limit` - Allows governance to change the request limit.
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unused_unit)]

use entropy_shared::MAX_SIGNERS;
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
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

/// Describes which service a given quote or accepted measurement relates to
#[derive(
    Clone,
    Encode,
    Decode,
    Debug,
    Eq,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    TypeInfo,
    DecodeWithMemTracking,
)]
#[repr(u32)]
#[non_exhaustive]
pub enum SupportedCvmServices {
    /// Entropy Threshold Signature Server
    EntropyTss,
    /// Tree service
    TreeService,
}

#[frame_support::pallet]
pub mod module {
    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_session::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// The origin which may set filter.
        type UpdateOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        /// Weight information for the extrinsics in this module.
        type WeightInfo: WeightInfo;
    }

    pub type MeasurementValues = Vec<BoundedVec<u8, ConstU32<32>>>;

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub request_limit: u32,
        pub max_instructions_per_programs: u64,
        pub threshold: u8,
        pub total_signers: u8,
        pub accepted_measurement_values: Vec<(SupportedCvmServices, MeasurementValues)>,
        #[serde(skip)]
        pub _config: sp_std::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            RequestLimit::<T>::put(self.request_limit);
            MaxInstructionsPerPrograms::<T>::put(self.max_instructions_per_programs);
            let signer_info = SignersSize {
                total_signers: self.total_signers,
                threshold: self.threshold,
                last_session_change: 0,
            };
            SignersInfo::<T>::put(signer_info);

            for (supported_cvm_service, measurement_values) in
                self.accepted_measurement_values.clone()
            {
                AcceptedMeasurementValues::<T>::insert(supported_cvm_service, measurement_values);
            }
        }
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Threshold can not be greater then signers
        ThresholdGreaterThenSigners,
        /// Threhsold has to be more than 0
        ThrehsoldTooLow,
        /// Signers over max signers, can happen however needs a benchmark rerun
        TooManySigners,
        /// Signers can only change by one at a time
        SignerDiffTooLarge,
        /// Can only do one change per session
        OneChangePerSession,
    }

    /// Signer info for the next reshare
    #[derive(
        Clone,
        Encode,
        Decode,
        Eq,
        PartialEqNoBound,
        RuntimeDebug,
        TypeInfo,
        Default,
        DecodeWithMemTracking,
    )]
    pub struct SignersSize {
        /// Next threshold amount
        pub threshold: u8,
        /// Total signers in signer party
        pub total_signers: u8,
        /// Last time it was changed (one change allowed per session)
        pub last_session_change: u32,
    }

    #[pallet::event]
    #[pallet::generate_deposit(fn deposit_event)]
    pub enum Event<T: Config> {
        /// Request limit changed
        RequestLimitChanged { request_limit: u32 },
        /// Max instructions per program changes
        MaxInstructionsPerProgramsChanged { max_instructions_per_programs: u64 },
        /// Signer Info changed
        SignerInfoChanged { signer_info: SignersSize },
        /// Accepted measurement values changed
        AcceptedMeasurementValuesChanged {
            accepted_measurement_values: Vec<(SupportedCvmServices, MeasurementValues)>,
        },
    }

    /// The request limit a user can ask to a specific set of TSS in a block
    #[pallet::storage]
    #[pallet::getter(fn request_limit)]
    pub type RequestLimit<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// The max instructions all programs can have
    #[pallet::storage]
    #[pallet::getter(fn max_instructions_per_programs)]
    pub type MaxInstructionsPerPrograms<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// The size of the signers and their threshold
    #[pallet::storage]
    #[pallet::getter(fn signers_info)]
    pub type SignersInfo<T: Config> = StorageValue<_, SignersSize, ValueQuery>;

    /// Accepted TDX measurement values - from the currently-supported releases of the supported services
    #[pallet::storage]
    #[pallet::getter(fn accepted_measurement_values)]
    pub type AcceptedMeasurementValues<T: Config> =
        StorageMap<_, Blake2_128Concat, SupportedCvmServices, MeasurementValues, OptionQuery>;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight( <T as Config>::WeightInfo::change_request_limit())]
        pub fn change_request_limit(origin: OriginFor<T>, request_limit: u32) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;
            RequestLimit::<T>::put(request_limit);
            Self::deposit_event(Event::RequestLimitChanged { request_limit });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight( <T as Config>::WeightInfo::change_max_instructions_per_programs())]
        pub fn change_max_instructions_per_programs(
            origin: OriginFor<T>,
            max_instructions_per_programs: u64,
        ) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;
            MaxInstructionsPerPrograms::<T>::put(max_instructions_per_programs);
            Self::deposit_event(Event::MaxInstructionsPerProgramsChanged {
                max_instructions_per_programs,
            });
            Ok(())
        }

        /// Changes the threshold related parameters for signing.
        #[pallet::call_index(2)]
        #[pallet::weight( <T as Config>::WeightInfo::change_signers_info())]
        pub fn change_signers_info(
            origin: OriginFor<T>,
            total_signers: u8,
            threshold: u8,
        ) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;
            ensure!(total_signers >= threshold, Error::<T>::ThresholdGreaterThenSigners);
            ensure!(threshold > 0, Error::<T>::ThrehsoldTooLow);
            ensure!(total_signers <= MAX_SIGNERS, Error::<T>::TooManySigners);

            let old_signer_info = Self::signers_info();
            ensure!(
                old_signer_info.total_signers.abs_diff(total_signers) <= 1,
                Error::<T>::SignerDiffTooLarge
            );

            let current_session = pallet_session::Pallet::<T>::current_index();
            ensure!(
                current_session > old_signer_info.last_session_change,
                Error::<T>::OneChangePerSession
            );

            let signer_info =
                SignersSize { total_signers, threshold, last_session_change: current_session };
            SignersInfo::<T>::put(&signer_info);
            Self::deposit_event(Event::SignerInfoChanged { signer_info });
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight( <T as Config>::WeightInfo::change_accepted_measurement_values())]
        pub fn change_accepted_measurement_values(
            origin: OriginFor<T>,
            accepted_measurement_values: Vec<(SupportedCvmServices, MeasurementValues)>,
        ) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;

            AcceptedMeasurementValues::<T>::remove(SupportedCvmServices::EntropyTss);
            AcceptedMeasurementValues::<T>::remove(SupportedCvmServices::TreeService);
            for (supported_cvm_service, measurement_values) in accepted_measurement_values.clone() {
                AcceptedMeasurementValues::<T>::insert(supported_cvm_service, measurement_values);
            }

            Self::deposit_event(Event::AcceptedMeasurementValuesChanged {
                accepted_measurement_values,
            });
            Ok(())
        }
    }
}
