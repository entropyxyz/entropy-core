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

use crate as pallet_staking_extension;

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
        pallet_session::Config + frame_system::Config + pallet_staking::Config
    {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Currency: Currency<Self::AccountId>;
        type MaxEndpointLength: Get<u32>;
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

    /// Stores the relationship between a validator's stash account and the information about their
    /// threshold server.
    ///
    /// # Note
    ///
    /// This mapping doesn't only include information about validators in the active set, but also
    /// information about validator candidates (i.e, those _might_ be part of the active set in the
    /// following era).
    #[pallet::storage]
    #[pallet::getter(fn threshold_server)]
    pub type ThresholdServers<T: Config> =
        StorageMap<_, Blake2_128Concat, T::ValidatorId, ServerInfo<T::AccountId>, OptionQuery>;

    /// A mapping between a threshold server's Account ID and its corresponding validator's stash
    /// account (i.e the reverse of [ThresholdServers]).
    ///
    /// # Note
    ///
    /// This mapping doesn't only include information about validators in the active set, but also
    /// information about validator candidates (i.e, those _might_ be part of the active set in the
    /// following era).
    #[pallet::storage]
    #[pallet::getter(fn threshold_to_stash)]
    pub type ThresholdToStash<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, T::ValidatorId, OptionQuery>;

    /// Keeps track of all the validators in a particular subgroup.
    ///
    /// Only active validators (so not candiates) should be assigned a subgroup and be included in
    /// this mapping.
    #[pallet::storage]
    #[pallet::getter(fn signing_groups)]
    pub type SigningGroups<T: Config> =
        StorageMap<_, Blake2_128Concat, SubgroupId, Vec<T::ValidatorId>, OptionQuery>;

    /// Mapping between a validator and their assigned subgroup for the given session.
    ///
    /// Only active validators (so not candidates) should be assigned a subgroup and be included in
    /// this mapping.
    #[pallet::storage]
    #[pallet::getter(fn validator_to_subgroup)]
    pub type ValidatorToSubgroup<T: Config> =
        StorageMap<_, Identity, T::ValidatorId, SubgroupId, OptionQuery>;

    /// Tracks wether the validator's kvdb is synced using a stash key as an identifier
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
        pub threshold_servers: Vec<ThresholdServersConfig<T>>,
        pub signing_groups: Vec<(u8, Vec<<T as pallet_session::Config>::ValidatorId>)>,
        /// validator info and accounts to take part in proactive refresh
        pub proactive_refresh_data: (Vec<ValidatorInfo>, Vec<Vec<u8>>),
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let _ = self
                .threshold_servers
                .clone()
                .into_iter()
                .map(|x| assert!(x.1 .2.len() as u32 <= T::MaxEndpointLength::get()));

            for (validator_stash, server_info_tuple) in &self.threshold_servers {
                let server_info = ServerInfo {
                    tss_account: server_info_tuple.0.clone(),
                    x25519_public_key: server_info_tuple.1,
                    endpoint: server_info_tuple.2.clone(),
                };

                ThresholdServers::<T>::insert(validator_stash, server_info.clone());
                ThresholdToStash::<T>::insert(&server_info.tss_account, validator_stash);
            }

            for (group_id, validator_ids) in &self.signing_groups {
                SigningGroups::<T>::insert(group_id, validator_ids);
                for validator_id in validator_ids {
                    IsValidatorSynced::<T>::insert(validator_id, true);
                    ValidatorToSubgroup::<T>::insert(validator_id, group_id);
                }
            }
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
        TssAccountAlreadyExists,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// An endpoint has been added or edited. [who, endpoint]
        EndpointChanged(T::AccountId, Vec<u8>),
        /// Node Info has been added or edited. [who, endpoint, threshold_account]
        NodeInfoChanged(T::AccountId, Vec<u8>, T::AccountId),
        /// A threshold account has been added or edited. [validator, threshold_account]
        ThresholdAccountChanged(
            <T as pallet_session::Config>::ValidatorId,
            ServerInfo<T::AccountId>,
        ),
        /// Node Info has been removed \[who\]
        NodeInfoRemoved(T::AccountId),
        /// Validator sync status changed [who, sync_status]
        ValidatorSyncStatus(<T as pallet_session::Config>::ValidatorId, bool),
        /// Validators subgroups rotated [old, new]
        ValidatorSubgroupsRotated(
            Vec<Vec<<T as pallet_session::Config>::ValidatorId>>,
            Vec<Vec<<T as pallet_session::Config>::ValidatorId>>,
        ),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Allows a validator to change their endpoint so signers can find them when they are coms
        /// manager `endpoint`: nodes's endpoint
        #[pallet::call_index(0)]
        #[pallet::weight(<T as Config>::WeightInfo::change_endpoint())]
        pub fn change_endpoint(origin: OriginFor<T>, endpoint: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                endpoint.len() as u32 <= T::MaxEndpointLength::get(),
                Error::<T>::EndpointTooLong
            );

            let ledger = pallet_staking::Pallet::<T>::ledger(StakingAccount::Stash(who.clone()))
                .map_err(|_| Error::<T>::NoBond)?;
            let validator_id = <T as pallet_session::Config>::ValidatorId::try_from(ledger.stash)
                .or(Err(Error::<T>::InvalidValidatorId))?;

            ThresholdServers::<T>::try_mutate(&validator_id, |maybe_server_info| {
                if let Some(server_info) = maybe_server_info {
                    server_info.endpoint.clone_from(&endpoint);
                    Ok(())
                } else {
                    Err(Error::<T>::NoBond)
                }
            })?;
            Self::deposit_event(Event::EndpointChanged(who, endpoint));
            Ok(())
        }

        /// Allows a validator to change their threshold key so can confirm done when coms manager
        /// `new_account`: nodes's threshold account
        #[pallet::call_index(1)]
        #[pallet::weight(<T as Config>::WeightInfo::change_threshold_accounts())]
        pub fn change_threshold_accounts(
            origin: OriginFor<T>,
            tss_account: T::AccountId,
            x25519_public_key: X25519PublicKey,
        ) -> DispatchResult {
            ensure!(
                !ThresholdToStash::<T>::contains_key(&tss_account),
                Error::<T>::TssAccountAlreadyExists
            );

            let who = ensure_signed(origin)?;
            let stash = Self::get_stash(&who)?;
            let validator_id = <T as pallet_session::Config>::ValidatorId::try_from(stash)
                .or(Err(Error::<T>::InvalidValidatorId))?;

            let new_server_info: ServerInfo<T::AccountId> =
                ThresholdServers::<T>::try_mutate(&validator_id, |maybe_server_info| {
                    if let Some(server_info) = maybe_server_info {
                        server_info.tss_account = tss_account.clone();
                        server_info.x25519_public_key = x25519_public_key;
                        ThresholdToStash::<T>::insert(&tss_account, &validator_id);
                        Ok(server_info.clone())
                    } else {
                        Err(Error::<T>::NoBond)
                    }
                })?;
            Self::deposit_event(Event::ThresholdAccountChanged(validator_id, new_server_info));
            Ok(())
        }

        /// Wraps's substrate withdraw unbonded but clears extra state if fully unbonded
        #[pallet::call_index(2)]
        #[pallet::weight(<T as Config>::WeightInfo::withdraw_unbonded())]
        pub fn withdraw_unbonded(
            origin: OriginFor<T>,
            num_slashing_spans: u32,
        ) -> DispatchResultWithPostInfo {
            let controller = ensure_signed(origin.clone())?;
            let ledger =
                pallet_staking::Pallet::<T>::ledger(StakingAccount::Controller(controller.clone()))
                    .map_err(|_| Error::<T>::NoThresholdKey)?;

            let validator_id = <T as pallet_session::Config>::ValidatorId::try_from(ledger.stash)
                .or(Err(Error::<T>::InvalidValidatorId))?;

            pallet_staking::Pallet::<T>::withdraw_unbonded(origin, num_slashing_spans)?;

            if pallet_staking::Pallet::<T>::bonded(&controller).is_none() {
                let server_info =
                    ThresholdServers::<T>::take(&validator_id).ok_or(Error::<T>::NoThresholdKey)?;
                ThresholdToStash::<T>::remove(&server_info.tss_account);
                IsValidatorSynced::<T>::remove(&validator_id);
                Self::deposit_event(Event::NodeInfoRemoved(controller));
            }
            Ok(().into())
        }

        /// Wrap's Substrate's `staking_pallet::validate()` extrinsic, but enforces that
        /// information about a validator's threshold server is provided.
        ///
        /// Note that - just like the original `validate()` extrinsic - the effects of this are
        /// only applied in the following era.
        #[pallet::call_index(3)]
        #[pallet::weight(<T as Config>::WeightInfo::validate())]
        pub fn validate(
            origin: OriginFor<T>,
            prefs: ValidatorPrefs,
            server_info: ServerInfo<T::AccountId>,
        ) -> DispatchResult {
            let who = ensure_signed(origin.clone())?;

            ensure!(
                server_info.endpoint.len() as u32 <= T::MaxEndpointLength::get(),
                Error::<T>::EndpointTooLong
            );

            ensure!(
                !ThresholdToStash::<T>::contains_key(&server_info.tss_account),
                Error::<T>::TssAccountAlreadyExists
            );

            pallet_staking::Pallet::<T>::validate(origin, prefs)?;

            let stash = Self::get_stash(&who)?;
            let validator_id =
                T::ValidatorId::try_from(stash).or(Err(Error::<T>::InvalidValidatorId))?;

            ThresholdServers::<T>::insert(&validator_id, server_info.clone());
            ThresholdToStash::<T>::insert(&server_info.tss_account, validator_id);

            Self::deposit_event(Event::NodeInfoChanged(
                who,
                server_info.endpoint,
                server_info.tss_account,
            ));

            Ok(())
        }

        /// Let a validator declare if their kvdb is synced or not synced
        /// `synced`: State of validator's kvdb
        #[pallet::call_index(4)]
        #[pallet::weight(<T as Config>::WeightInfo::declare_synced())]
        pub fn declare_synced(origin: OriginFor<T>, synced: bool) -> DispatchResult {
            let who = ensure_signed(origin.clone())?;
            let stash = Self::threshold_to_stash(who).ok_or(Error::<T>::NoThresholdKey)?;
            IsValidatorSynced::<T>::insert(&stash, synced);
            Self::deposit_event(Event::ValidatorSyncStatus(stash, synced));
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn get_stash(controller: &T::AccountId) -> Result<T::AccountId, DispatchError> {
            let ledger =
                pallet_staking::Pallet::<T>::ledger(StakingAccount::Controller(controller.clone()))
                    .map_err(|_| Error::<T>::NotController)?;
            Ok(ledger.stash)
        }

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

                // There's no easy way for us to get the difference between the old and new
                // validator sets, so we take the naive approach and just clear everybody's signing
                // group.
                //
                // We'll fill this out again later once we have the full, new, validator set.
                for validator in curr_validators_set[signing_group].iter() {
                    ValidatorToSubgroup::<T>::remove(validator);
                }
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
            for (subgroup, validator_set) in new_validators_set.iter().enumerate() {
                let subgroup = subgroup as u8;

                SigningGroups::<T>::remove(subgroup);
                SigningGroups::<T>::insert(subgroup, validator_set);

                for validator in validator_set.iter() {
                    ValidatorToSubgroup::<T>::insert(validator, subgroup);
                }
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
