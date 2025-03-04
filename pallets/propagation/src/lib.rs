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
//! # Propagation Pallet
//!
//! ## Overview
//!
//! Propagates messages to signing client through offchain worker
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod weights;

#[frame_support::pallet]
pub mod pallet {
    pub use crate::weights::WeightInfo;
    use codec::Encode;
    use entropy_shared::{
        OcwMessageAttestationRequest, OcwMessageDkg, OcwMessageProactiveRefresh, OcwMessageReshare,
    };
    use frame_support::{pallet_prelude::*, sp_runtime::traits::Saturating};
    use frame_system::pallet_prelude::*;
    use sp_runtime::{
        offchain::{http, Duration},
        sp_std::vec,
        sp_std::{str, vec::Vec},
    };

    #[pallet::config]
    pub trait Config:
        frame_system::Config
        + pallet_authorship::Config
        + pallet_registry::Config
        + pallet_staking_extension::Config
        + pallet_attestation::Config
    {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// The weight information of this pallet.
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn offchain_worker(block_number: BlockNumberFor<T>) {
            let _ = Self::post_dkg(block_number);
            let _ = Self::post_reshare(block_number);
            let _ = Self::post_proactive_refresh(block_number);
            let _ = Self::post_attestation_request(block_number);
            let _ = Self::post_rotate_network_key(block_number);
        }

        fn on_initialize(_block_number: BlockNumberFor<T>) -> Weight {
            pallet_staking_extension::ProactiveRefresh::<T>::take();
            <T as Config>::WeightInfo::on_initialize()
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

        /// Proactive Refresh Message passed to validators
        /// parameters. [OcwMessageReshare]
        KeyReshareMessagePassed(OcwMessageReshare),

        /// Attestations request message passed
        AttestationRequestMessagePassed(OcwMessageAttestationRequest),

        /// Key Rotate Message passed to validators
        /// parameters. [BlockNumberFor<T>]
        KeyRotatesMessagePassed(BlockNumberFor<T>),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {}

    impl<T: Config> Pallet<T> {
        /// Submits a distributed key generation request to jumpstart the network to the threshold
        /// servers.
        pub fn post_dkg(block_number: BlockNumberFor<T>) -> Result<(), http::Error> {
            let validators_info = pallet_registry::Pallet::<T>::jumpstart_dkg(
                block_number.saturating_sub(1u32.into()),
            );
            if validators_info.is_empty() {
                return Ok(());
            }
            let kind = sp_core::offchain::StorageKind::PERSISTENT;
            let from_local = sp_io::offchain::local_storage_get(kind, b"propagation")
                .unwrap_or_else(|| b"http://localhost:3001/generate_network_key".to_vec());
            let url =
                str::from_utf8(&from_local).unwrap_or("http://localhost:3001/generate_network_key");

            log::warn!("propagation::post::validators_info: {:?}", &validators_info);
            let converted_block_number: u32 =
                BlockNumberFor::<T>::try_into(block_number).unwrap_or_default();
            // the data is serialized / encoded to Vec<u8> by parity-scale-codec::encode()
            let req_body = OcwMessageDkg {
                // subtract 1 from blocknumber since the request is from the last block
                block_number: converted_block_number.saturating_sub(1),
                validators_info,
            };

            log::warn!("propagation::post::req_body: {:?}", &[req_body.encode()]);
            // We construct the request
            // important: the header->Content-Type must be added and match that of the receiving
            // party!!
            let pending = http::Request::post(url, vec![req_body.encode()])
                .send()
                .map_err(|_| http::Error::IoError)?;

            // We await response, same as in fn get()
            let response = pending.wait().map_err(|_| http::Error::DeadlineReached)?;

            // check response code
            if response.code != 200 {
                log::warn!(
                    "Unexpected status code: {} {:?}",
                    response.code,
                    response.body().clone().collect::<Vec<_>>()
                );
                return Err(http::Error::Unknown);
            }
            let _res_body = response.body().collect::<Vec<u8>>();

            Self::deposit_event(Event::DkgMessagePassed(req_body));

            Ok(())
        }

        /// Submits a request to do a key refresh on the signers parent key.
        pub fn post_reshare(block_number: BlockNumberFor<T>) -> Result<(), http::Error> {
            let reshare_data = pallet_staking_extension::Pallet::<T>::reshare_data();
            if reshare_data.block_number + sp_runtime::traits::One::one() != block_number {
                return Ok(());
            }

            let kind = sp_core::offchain::StorageKind::PERSISTENT;
            let from_local = sp_io::offchain::local_storage_get(kind, b"reshare_validators")
                .unwrap_or_else(|| b"http://localhost:3001/validator/reshare".to_vec());
            let url =
                str::from_utf8(&from_local).unwrap_or("http://localhost:3001/validator/reshare");
            let converted_block_number: u32 =
                BlockNumberFor::<T>::try_into(block_number).unwrap_or_default();

            let req_body = OcwMessageReshare {
                new_signers: reshare_data.new_signers,
                // subtract 1 from blocknumber since the request is from the last block
                block_number: converted_block_number.saturating_sub(1),
            };

            log::warn!("propagation::post::req_body reshare: {:?}", &[req_body.encode()]);

            // We construct the request
            // important: the header->Content-Type must be added and match that of the receiving
            // party!!
            let pending = http::Request::post(url, vec![req_body.encode()])
                .send()
                .map_err(|_| http::Error::IoError)?;

            // We await response, same as in fn get()
            let response = pending.wait().map_err(|_| http::Error::DeadlineReached)?;

            // check response code
            if response.code != 200 {
                log::warn!(
                    "Unexpected status code: {} {:?}",
                    response.code,
                    response.body().clone().collect::<Vec<_>>()
                );
                return Err(http::Error::Unknown);
            }
            let _res_body = response.body().collect::<Vec<u8>>();

            Self::deposit_event(Event::KeyReshareMessagePassed(req_body));

            Ok(())
        }

        /// Submits a request to perform a proactive refresh to the threshold servers.
        pub fn post_proactive_refresh(block_number: BlockNumberFor<T>) -> Result<(), http::Error> {
            let refresh_info = pallet_staking_extension::Pallet::<T>::proactive_refresh();
            if refresh_info.validators_info.is_empty() {
                return Ok(());
            }

            let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(20_000));
            let kind = sp_core::offchain::StorageKind::PERSISTENT;
            let from_local = sp_io::offchain::local_storage_get(kind, b"refresh")
                .unwrap_or_else(|| b"http://localhost:3001/signer/proactive_refresh".to_vec());
            let url = str::from_utf8(&from_local)
                .unwrap_or("http://localhost:3001/signer/proactive_refresh");

            let converted_block_number: u32 =
                BlockNumberFor::<T>::try_into(block_number).unwrap_or_default();

            let req_body = OcwMessageProactiveRefresh {
                // subtract 1 from blocknumber since the request is from the last block
                block_number: converted_block_number.saturating_sub(1),
                validators_info: refresh_info.validators_info,
                proactive_refresh_keys: refresh_info.proactive_refresh_keys,
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

        /// Submits a request to rotate parent network key the threshold servers.
        pub fn post_rotate_network_key(block_number: BlockNumberFor<T>) -> Result<(), http::Error> {
            let rotate_keyshares = pallet_staking_extension::Pallet::<T>::rotate_keyshares();
            if rotate_keyshares != block_number {
                return Ok(());
            }

            let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(20_000));
            let kind = sp_core::offchain::StorageKind::PERSISTENT;
            let from_local = sp_io::offchain::local_storage_get(kind, b"rotate_network_key")
                .unwrap_or_else(|| b"http://localhost:3001/rotate_network_key".to_vec());
            let url =
                str::from_utf8(&from_local).unwrap_or("http://localhost:3001/rotate_network_key");

            log::warn!("propagation::post rotate network key");

            let converted_block_number: u32 =
                BlockNumberFor::<T>::try_into(block_number).unwrap_or_default();

            // We construct the request
            // important: the header->Content-Type must be added and match that of the receiving
            // party!!
            let pending = http::Request::post(url, vec![converted_block_number.encode()])
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

            Self::deposit_event(Event::KeyRotatesMessagePassed(block_number));

            Ok(())
        }

        /// Submits a request for a TDX attestation.
        pub fn post_attestation_request(
            block_number: BlockNumberFor<T>,
        ) -> Result<(), http::Error> {
            if let Some(attestations_to_request) =
                pallet_attestation::Pallet::<T>::attestation_requests(block_number)
            {
                if attestations_to_request.is_empty() {
                    return Ok(());
                }

                let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(20_000));
                let kind = sp_core::offchain::StorageKind::PERSISTENT;
                let from_local = sp_io::offchain::local_storage_get(kind, b"attest")
                    .unwrap_or_else(|| b"http://localhost:3001/attest".to_vec());
                let url = str::from_utf8(&from_local).unwrap_or("http://localhost:3001/attest");
                let converted_block_number: u32 =
                    BlockNumberFor::<T>::try_into(block_number).unwrap_or_default();

                let req_body = OcwMessageAttestationRequest {
                    tss_account_ids: attestations_to_request
                        .into_iter()
                        .filter_map(|v| v.try_into().ok())
                        .collect(),
                    // subtract 1 from blocknumber since the request is from the last block
                    block_number: converted_block_number.saturating_sub(1),
                };
                log::debug!("propagation::post attestation: {:?}", &[req_body.encode()]);

                let pending = http::Request::post(url, vec![req_body.encode()])
                    .deadline(deadline)
                    .send()
                    .map_err(|_| http::Error::IoError)?;

                let response =
                    pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;

                if response.code != 200 {
                    log::warn!("Unexpected status code: {}", response.code);
                    return Err(http::Error::Unknown);
                }
                let _res_body = response.body().collect::<Vec<u8>>();

                Self::deposit_event(Event::AttestationRequestMessagePassed(req_body));
            };
            Ok(())
        }
    }
}
