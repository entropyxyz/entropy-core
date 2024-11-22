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
use frame_system::pallet_prelude::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
pub mod weights;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub use module::*;

#[frame_support::pallet]
pub mod module {
    use super::*;
    pub use crate::weights::WeightInfo;

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

    /// Oracle Info for oracle data
    #[derive(Clone, Encode, Decode, Eq, PartialEqNoBound, RuntimeDebug, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct OracleInfo<T: Config> {
        pub oracle_data: BoundedVec<u8, T::MaxOracleValueLength>,
        pub oracle_type: Vec<u8>,
    }

    /// Storage for oracle info to be passed to programs.
    #[pallet::storage]
    #[pallet::getter(fn oracle_data)]
    pub type OracleData<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, T::MaxOracleKeyLength>,
        OracleInfo<T>,
        OptionQuery,
    >;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        #[serde(skip)]
        _config: sp_std::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            // Makes sure key chosen can fit in bounded vec
            assert!("block_number_entropy".encode().len() as u32 <= T::MaxOracleKeyLength::get());
            // Makes sure block number can fit in bounded vec
            assert!(u64::MAX.encode().len() as u32 <= T::MaxOracleKeyLength::get());
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(block_number: BlockNumberFor<T>) -> Weight {
            OracleData::<T>::insert(
                BoundedVec::try_from("block_number_entropy".encode())
                    .expect("Key fits in bounded vec; qed"),
                OracleInfo {
                    oracle_data: BoundedVec::try_from(block_number.encode())
                        .expect("Block number fits in bounded vec; qed"),
                    oracle_type: "u32".as_bytes().to_vec(),
                },
            );
            T::WeightInfo::on_initialize()
        }
    }

    #[pallet::error]
    pub enum Error<T> {}

    #[pallet::event]
    pub enum Event<T: Config> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {}
}
