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

//! # Programs Parameters
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

use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use sp_runtime::DispatchResult;

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

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// The origin which may set filter.
        type UpdateOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        /// Weight information for the extrinsics in this module.
        type WeightInfo: WeightInfo;
    }

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub request_limit: u32,
        pub max_instructions_per_programs: u64,
        #[serde(skip)]
        pub _config: sp_std::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            RequestLimit::<T>::put(self.request_limit);
            MaxInstructionsPerPrograms::<T>::put(self.max_instructions_per_programs);
        }
    }

    #[pallet::error]
    pub enum Error<T> {}

    #[pallet::event]
    #[pallet::generate_deposit(fn deposit_event)]
    pub enum Event<T: Config> {
        /// Request limit changed
        RequestLimitChanged { request_limit: u32 },
        /// Max instructions per program changes
        MaxInstructionsPerProgramsChanged { max_instructions_per_programs: u64 },
    }

    /// The request limit a user can ask to a specific set of TSS in a block
    #[pallet::storage]
    #[pallet::getter(fn request_limit)]
    pub type RequestLimit<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// The max instructions all programs can have
    #[pallet::storage]
    #[pallet::getter(fn max_instructions_per_programs)]
    pub type MaxInstructionsPerPrograms<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::change_request_limit())]
        pub fn change_request_limit(origin: OriginFor<T>, request_limit: u32) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;
            RequestLimit::<T>::put(request_limit);
            Self::deposit_event(Event::RequestLimitChanged { request_limit });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::max_instructions_per_programs())]
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
    }
}
