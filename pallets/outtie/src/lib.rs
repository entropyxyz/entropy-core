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

use entropy_shared::X25519PublicKey;
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

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_session::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// The maximum length of a threshold server's endpoint address, in bytes.
        type MaxEndpointLength: Get<u32>;

        /// Weight information for the extrinsics in this module.
        type WeightInfo: WeightInfo;
    }

    /// Information about a tdx server  
    #[derive(Encode, Decode, Clone, Eq, PartialEq, RuntimeDebug, TypeInfo)]
    #[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
    pub struct ServerInfo {
        pub x25519_public_key: X25519PublicKey,
        pub endpoint: Vec<u8>,
        //  pub provisioning_certification_key: VerifyingKey,
    }

    /// API box signing account => Server Info
    #[pallet::storage]
    #[pallet::getter(fn get_api_boxes)]
    pub type ApiBoxes<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, ServerInfo, OptionQuery>;

    #[pallet::error]
    pub enum Error<T> {
        /// Endpoint is too long
        EndpointTooLong,
        /// Box account already exists
        BoxAccountAlreadyExists,
    }

    #[pallet::event]
    #[pallet::generate_deposit(fn deposit_event)]
    pub enum Event<T: Config> {
        BoxAdded { box_account: T::AccountId, server_info: ServerInfo },
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
            server_info: ServerInfo,
            // quote: Vec<u8>,
        ) -> DispatchResult {
            let box_account = ensure_signed(origin.clone())?;

            ensure!(
                server_info.endpoint.len() as u32 <= T::MaxEndpointLength::get(),
                Error::<T>::EndpointTooLong
            );

            ensure!(
                !ApiBoxes::<T>::contains_key(&box_account),
                Error::<T>::BoxAccountAlreadyExists
            );

            // TODO assertion

            ApiBoxes::<T>::insert(&box_account, server_info.clone());

            Self::deposit_event(Event::BoxAdded { box_account, server_info });

            Ok(())
        }
    }
}
