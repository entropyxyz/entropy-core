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

#![cfg_attr(not(feature = "std"), no_std)]
//! # Propogation Pallet
//!
//! ## Overview
//!
//! Propgates messages to signing client through offchain worker
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use codec::Encode;
    use entropy_shared::{OcwMessageDkg, OcwMessageProactiveRefresh, ValidatorInfo};
    use frame_support::{dispatch::Vec, pallet_prelude::*, sp_runtime::traits::Saturating};
    use frame_system::pallet_prelude::*;
    use scale_info::prelude::vec;
    use sp_core;
    use sp_runtime::{
        offchain::{http, Duration},
        sp_std::str,
    };

    #[pallet::config]
    pub trait Config:
        frame_system::Config
        + pallet_authorship::Config
        + pallet_entropy_registry::Config
        + pallet_entropy_staking_extension::Config
    {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn offchain_worker(block_number: BlockNumberFor<T>) {
            let _ = Self::post_dkg(block_number);
            let _ = Self::post_proactive_refresh(block_number);
        }

        fn on_initialize(block_number: BlockNumberFor<T>) -> Weight {
            pallet_entropy_registry::Dkg::<T>::remove(block_number.saturating_sub(2u32.into()));
            pallet_entropy_staking_extension::ProactiveRefresh::<T>::take();
            T::DbWeight::get().writes(2)
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// DKG Message passed to validators
        /// parameters. [OcwMessageDkg]
        DkgMessagePassed(OcwMessageDkg),

        /// Proactive Refresh Message passed to validators
        /// parameters. [OcwMessageProactiveRefresh]
        ProactiveRefreshMessagePassed(OcwMessageProactiveRefresh),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {}

    impl<T: Config> Pallet<T> {
        pub fn post_dkg(block_number: BlockNumberFor<T>) -> Result<(), http::Error> {
            let messages =
                pallet_entropy_registry::Pallet::<T>::dkg(block_number.saturating_sub(1u32.into()));

            let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
            let kind = sp_core::offchain::StorageKind::PERSISTENT;
            let from_local = sp_io::offchain::local_storage_get(kind, b"propagation")
                .unwrap_or_else(|| b"http://localhost:3001/user/new".to_vec());
            let url = str::from_utf8(&from_local).unwrap_or("http://localhost:3001/user/new");

            log::warn!("propagation::post::messages: {:?}", &messages);
            let converted_block_number: u32 =
                BlockNumberFor::<T>::try_into(block_number).unwrap_or_default();
            let (servers_info, _i) =
                pallet_entropy_registry::Pallet::<T>::get_validator_info().unwrap_or_default();
            let validators_info = servers_info
                .iter()
                .map(|server_info| ValidatorInfo {
                    x25519_public_key: server_info.x25519_public_key,
                    ip_address: server_info.endpoint.clone(),
                    tss_account: server_info.tss_account.encode(),
                })
                .collect::<Vec<_>>();
            // the data is serialized / encoded to Vec<u8> by parity-scale-codec::encode()
            let req_body = OcwMessageDkg {
                // subtract 1 from blocknumber since the request is from the last block
                block_number: converted_block_number.saturating_sub(1),
                sig_request_accounts: messages,
                validators_info,
            };

            log::warn!("propagation::post::req_body: {:?}", &[req_body.encode()]);
            // We construct the request
            // important: the header->Content-Type must be added and match that of the receiving
            // party!!
            let pending = http::Request::post(url, vec![req_body.encode()])
                .deadline(deadline)
                .send()
                .map_err(|_| http::Error::IoError)?;

            // We await response, same as in fn get()
            let response =
                pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;

            // check response code
            if response.code != 200 {
                log::warn!("Unexpected status code: {}", response.code);
                return Err(http::Error::Unknown);
            }
            let _res_body = response.body().collect::<Vec<u8>>();

            Self::deposit_event(Event::DkgMessagePassed(req_body));

            Ok(())
        }

        pub fn post_proactive_refresh(_block_number: BlockNumberFor<T>) -> Result<(), http::Error> {
            let refresh_info = pallet_staking_extension::Pallet::<T>::proactive_refresh();
            if refresh_info.validators_info.is_empty() {
                return Ok(());
            }

            let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
            let kind = sp_core::offchain::StorageKind::PERSISTENT;
            let from_local = sp_io::offchain::local_storage_get(kind, b"refresh")
                .unwrap_or_else(|| b"http://localhost:3001/signer/proactive_refresh".to_vec());
            let url = str::from_utf8(&from_local)
                .unwrap_or("http://localhost:3001/signer/proactive_refresh");

            let req_body = OcwMessageProactiveRefresh {
                validators_info: refresh_info.validators_info,
                refreshes_done: refresh_info.refreshes_done,
            };
            log::warn!("propagation::post proactive refresh: {:?}", &[req_body.encode()]);

            // We construct the request
            // important: the header->Content-Type must be added and match that of the receiving
            // party!!
            let pending = http::Request::post(url, vec![req_body.encode()])
                .deadline(deadline)
                .send()
                .map_err(|_| http::Error::IoError)?;

            // We await response, same as in fn get()
            let response =
                pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;

            // check response code
            if response.code != 200 {
                log::warn!("Unexpected status code: {}", response.code);
                return Err(http::Error::Unknown);
            }
            let _res_body = response.body().collect::<Vec<u8>>();

            Self::deposit_event(Event::ProactiveRefreshMessagePassed(req_body));

            Ok(())
        }
    }
}
