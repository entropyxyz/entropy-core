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

//! # Programs Oracle
//!
//! ## Overview
//!
//! A pallet to manage oracle data for programs.
//!
//! Oracle data is stored in OracleData storage and can be pointed to and pulled in for programs
//!
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unused_unit)]

use frame_support::pallet_prelude::*;
use frame_system::{pallet_prelude::*, WeightInfo};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

pub use module::*;

#[frame_support::pallet]
pub mod module {
    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// The maximum amount of owned programs.
        type MaxOracleKeyLength: Get<u32>;
        /// The maximum amount of owned programs.
        type MaxOracleValueLength: Get<u32>;
        /// Weight information for the extrinsics in this module.
        type WeightInfo: WeightInfo;
    }

    #[pallet::storage]
    #[pallet::getter(fn oracle_data)]
    // TODO: parameterize bounded vec constants
    pub type OracleData<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, T::MaxOracleKeyLength>,
        BoundedVec<u8, T::MaxOracleValueLength>,
        OptionQuery,
    >;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(block_number: BlockNumberFor<T>) -> Weight {
            OracleData::<T>::insert(
                BoundedVec::try_from("block_number_entropy".encode()).unwrap(),
                BoundedVec::try_from(block_number.encode()).unwrap(),
            );
            T::DbWeight::get().writes(1)
        }
    }

    #[pallet::error]
    pub enum Error<T> {}

    #[pallet::event]
    pub enum Event<T: Config> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {}
}
