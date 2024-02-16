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
#![allow(clippy::needless_range_loop)]
#![allow(clippy::or_fun_call)]
//! # Staking Pallet
//!
//!
//! ## Overview
//!
//! An extention on normal staking that adds the ability to add a threshold signer key
//! and an IP address for validators
//!
//! ### Public Functions
//!
//! change_endpoint - allows a user to change their designated endpoint (needed so signing nodes can
//! find coms manager) change_threshold_accounts - allows a user to change their threshold account
//! (needed so comms manager can confirm done) withdraw_unbonded - wraps substrate's call but clears
//! endpoint and threshold key if all is unbonded validate - wraps substrate's call but forces a
//! threshold key and endpoint

use core::convert::TryInto;

pub use pallet::*;
use pallet_staking::ValidatorPrefs;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

pub use crate::weights::WeightInfo;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;

pub mod weights;
use core::convert::TryFrom;

use sp_staking::SessionIndex;

use crate as pallet_session_handler;

#[frame_support::pallet]
pub mod pallet {
    use entropy_shared::{ValidatorInfo, X25519PublicKey, SIGNING_PARTY_SIZE};
    use frame_support::{
        dispatch::DispatchResult, pallet_prelude::*, traits::Currency, DefaultNoBound,
    };
    use frame_system::pallet_prelude::*;
    use sp_staking::StakingAccount;
    use sp_std::vec::Vec;

    use super::*;

    #[pallet::config]
    pub trait Config:
        pallet_session::Config
        + frame_system::Config
        + pallet_staking_extension::Config
        + pallet_relayer::Config
    {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// How many accounts will be checked to see if proactive refresh should be done
        type ProactiveRefreshChecks: Get<u32>;
        /// Caps the max proactive refreshes per session
        type MaxProactiveRefreshes: Get<u32>;
        /// The weight information of this pallet.
        type WeightInfo: WeightInfo;
    }
    // TODO: JA add build for initial endpoints

    /// A unique identifier of a subgroup or partition of validators that have the same set of
    /// threshold shares.
    pub type SubgroupId = u8;
    /// Endpoint where a threshold server can be reached at
    pub type TssServerURL = Vec<u8>;

    /// The balance type of this pallet.
    pub type BalanceOf<T> = <<T as pallet_staking::Config>::Currency as Currency<
        <T as frame_system::Config>::AccountId,
    >>::Balance;

    /// Information about a threshold server
    #[derive(Encode, Decode, Clone, Eq, PartialEq, RuntimeDebug, TypeInfo)]
    #[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
    pub struct ServerInfo<AccountId> {
        pub tss_account: AccountId,
        pub x25519_public_key: X25519PublicKey,
        pub endpoint: TssServerURL,
    }
    /// Info that is requiered to do a proactive refresh
    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo, Default)]
    pub struct RefreshInfo {
        pub validators_info: Vec<ValidatorInfo>,
        pub proactive_refresh_keys: Vec<Vec<u8>>,
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Stores the relationship between
    /// a validator's stash account and their threshold server's sr25519 and x25519 keys.
    ///
    /// Clients query this via state or `stakingExtension_getKeys` RPC and uses
    /// the x25519 pub key in noninteractive ECDH for authenticating/encrypting distribute TSS
    /// shares over HTTP.
    #[pallet::storage]
    #[pallet::getter(fn threshold_server)]
    pub type ThresholdServers<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        <T as pallet_session::Config>::ValidatorId,
        ServerInfo<T::AccountId>,
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn threshold_to_stash)]
    pub type ThresholdToStash<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        <T as pallet_session::Config>::ValidatorId,
        OptionQuery,
    >;

    /// Stores the relationship between a signing group (u8) and its member's (validator's)
    /// threshold server's account.
    #[pallet::storage]
    #[pallet::getter(fn signing_groups)]
    pub type SigningGroups<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        SubgroupId,
        Vec<<T as pallet_session::Config>::ValidatorId>,
        OptionQuery,
    >;

    /// Tracks wether the validator's kvdb is synced
    #[pallet::storage]
    #[pallet::getter(fn is_validator_synced)]
    pub type IsValidatorSynced<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        <T as pallet_session::Config>::ValidatorId,
        bool,
        ValueQuery,
    >;

    /// A trigger for the proactive refresh OCW
    #[pallet::storage]
    #[pallet::getter(fn proactive_refresh)]
    pub type ProactiveRefresh<T: Config> = StorageValue<_, RefreshInfo, ValueQuery>;

    /// A type used to simplify the genesis configuration definition.
    pub type ThresholdServersConfig<T> = (
        <T as pallet_session::Config>::ValidatorId,
        (<T as frame_system::Config>::AccountId, X25519PublicKey, TssServerURL),
    );

    #[pallet::genesis_config]
    #[derive(DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        /// validator info and accounts to take part in proactive refresh
        pub proactive_refresh_data: (Vec<ValidatorInfo>, Vec<Vec<u8>>),
        #[serde(skip)]
        pub _config: sp_std::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let refresh_info = RefreshInfo {
                validators_info: self.proactive_refresh_data.0.clone(),
                proactive_refresh_keys: self.proactive_refresh_data.1.clone(),
            };
            ProactiveRefresh::<T>::put(refresh_info);
        }
    }
    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        EndpointTooLong,
        NoBond,
        NotController,
        NoThresholdKey,
        InvalidValidatorId,
        SigningGroupError,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Validators subgroups rotated [old, new]
        ValidatorSubgroupsRotated(
            Vec<Vec<<T as pallet_session::Config>::ValidatorId>>,
            Vec<Vec<<T as pallet_session::Config>::ValidatorId>>,
        ),
    }


    impl<T: Config> Pallet<T> {
        pub fn new_session_handler(
            validators: &[<T as pallet_session::Config>::ValidatorId],
        ) -> Result<(), DispatchError> {
            // TODO add back in refresh trigger and refreshed counter https://github.com/entropyxyz/entropy-core/issues/511
            // Init a 2D Vec where indices and values represent subgroups and validators,
            // respectively.
            let mut new_validators_set: Vec<Vec<<T as pallet_session::Config>::ValidatorId>> =
                Vec::with_capacity(SIGNING_PARTY_SIZE);
            new_validators_set.resize(SIGNING_PARTY_SIZE, Vec::new());

            // Init current validators vec
            let mut curr_validators_set: Vec<Vec<<T as pallet_session::Config>::ValidatorId>> =
                Vec::with_capacity(SIGNING_PARTY_SIZE);
            curr_validators_set.resize(SIGNING_PARTY_SIZE, Vec::new());

            // Init new unplaced validator vec
            let mut unplaced_validators_set: Vec<<T as pallet_session::Config>::ValidatorId> =
                Vec::new();

            // Populate the current validators set
            for signing_group in 0..SIGNING_PARTY_SIZE {
                curr_validators_set[signing_group] =
                    pallet_staking_extension::Pallet::<T>::signing_groups(signing_group as u8)
                        .ok_or(Error::<T>::SigningGroupError)?;
            }

            // Replace existing validators into the same subgroups
            for new_validator in validators.iter() {
                let mut exists = false;
                for (sg, sg_validators) in curr_validators_set.iter().enumerate() {
                    if sg_validators.contains(new_validator) {
                        exists = true;
                        new_validators_set[sg].push(new_validator.clone());
                        break;
                    }
                }
                if !exists {
                    unplaced_validators_set.push(new_validator.clone());
                }
            }
            // Evenly distribute new validators.
            while let Some(curr) = unplaced_validators_set.pop() {
                let mut min_sg_len = u64::MAX;
                let mut min_sg = 0;
                for (sg, validators) in new_validators_set.iter().enumerate() {
                    let n = validators.len() as u64;
                    if n < min_sg_len {
                        min_sg_len = n;
                        min_sg = sg;
                    }
                }
                new_validators_set[min_sg].push(curr);
            }

            // Update the new validator set
            for (sg, vs) in new_validators_set.iter().enumerate() {
                pallet_staking_extension::SigningGroups::<T>::remove(sg as u8);
                pallet_staking_extension::SigningGroups::<T>::insert(sg as u8, vs);
            }
            Self::deposit_event(Event::ValidatorSubgroupsRotated(
                curr_validators_set.clone(),
                new_validators_set.clone(),
            ));
            frame_system::Pallet::<T>::register_extra_weight_unchecked(
                <T as pallet::Config>::WeightInfo::new_session_handler_helper(
                    curr_validators_set.len() as u32,
                    new_validators_set.len() as u32,
                ),
                DispatchClass::Mandatory,
            );
            Ok(())
        }

        pub fn partition_network_for_proactive_refresh() -> Result<(), DispatchError> {

           let accounts = pallet_relayer::pallet::Registered::<T>::iter();
            // get all accounts
            // go through the to max checks accounts pulling out any prior index
            // max checks or max proactice refreshes hit first
            // check to make sure they are not private accounts, collect all no private
            // increment the index
            // mark last index position checked
            // check last refresh
            // charge extra weight
            Ok(())
        }
    }

    pub struct SessionManager<I, T: Config>(
        sp_std::marker::PhantomData<I>,
        sp_std::marker::PhantomData<T>,
    );
    impl<
            I: pallet_session::SessionManager<ValidatorId>,
            ValidatorId,
            T: Config + pallet::Config<ValidatorId = ValidatorId>,
        > pallet_session::SessionManager<ValidatorId> for SessionManager<I, T>
    {
        fn new_session(new_index: SessionIndex) -> Option<Vec<ValidatorId>> {
            let new_session = I::new_session(new_index);
            if let Some(validators) = &new_session {
                let result = Pallet::<T>::new_session_handler(validators);
                if result.is_err() {
                    log::warn!("Error splitting validators, Session: {:?}", new_index)
                }
            }
            new_session
        }

        fn new_session_genesis(new_index: SessionIndex) -> Option<Vec<ValidatorId>> {
            I::new_session_genesis(new_index)
        }

        fn end_session(end_index: SessionIndex) {
            I::end_session(end_index);
        }

        fn start_session(start_index: SessionIndex) {
            I::start_session(start_index);
        }
    }
}
