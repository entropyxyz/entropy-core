#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::needless_range_loop)]
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
mod benchmarking;

pub mod weights;
use core::convert::TryFrom;

use sp_staking::SessionIndex;

use crate as pallet_staking_extension;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::{
        dispatch::DispatchResult, inherent::Vec, pallet_prelude::*, traits::Currency,
    };
    use frame_system::pallet_prelude::*;
    use substrate_common::SIGNING_PARTY_SIZE;

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
    /// X25519 public key used by the client in non-interactive ECDH to authenticate/encrypt
    /// interactions with the threshold server (eg distributing threshold shares).
    pub type X25519PublicKey = [u8; 32];
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

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
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

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        #[allow(clippy::type_complexity)]
        pub threshold_servers:
            Vec<(<T as pallet_session::Config>::ValidatorId, ServerInfo<T::AccountId>)>,
        pub signing_groups: Vec<(u8, Vec<<T as pallet_session::Config>::ValidatorId>)>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self { threshold_servers: Default::default(), signing_groups: Default::default() }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            let _ = self
                .threshold_servers
                .clone()
                .into_iter()
                .map(|x| assert!(x.1.endpoint.len() as u32 <= T::MaxEndpointLength::get()));

            for (validator_stash, server_info) in &self.threshold_servers {
                ThresholdServers::<T>::insert(validator_stash, server_info.clone());
                ThresholdToStash::<T>::insert(&server_info.tss_account, validator_stash);
            }

            for (group_id, validator_ids) in &self.signing_groups {
                SigningGroups::<T>::insert(group_id, validator_ids);
            }
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
        /// Node Info has been removed [who]
        NodeInfoRemoved(T::AccountId),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Allows a validator to change their endpoint so signers can find them when they are coms
        /// manager `endpoint`: nodes's endpoint
        #[pallet::weight(<T as Config>::WeightInfo::change_endpoint())]
        pub fn change_endpoint(origin: OriginFor<T>, endpoint: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                endpoint.len() as u32 <= T::MaxEndpointLength::get(),
                Error::<T>::EndpointTooLong
            );

            pallet_staking::Pallet::<T>::ledger(&who).ok_or(Error::<T>::NoBond)?;
            let ledger = pallet_staking::Pallet::<T>::ledger(&who).ok_or(Error::<T>::NoBond)?;
            let validator_id_res =
                <T as pallet_session::Config>::ValidatorId::try_from(ledger.stash)
                    .or(Err(Error::<T>::InvalidValidatorId));
            ensure!(
                validator_id_res.is_ok(),
                pallet_staking_extension::Error::<T>::InvalidValidatorId
            );
            let validator_id =
                validator_id_res.expect("Issue converting account id into validator id");
            ThresholdServers::<T>::try_mutate(&validator_id, |maybe_server_info| {
                if let Some(server_info) = maybe_server_info {
                    server_info.endpoint = endpoint.clone();
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
        #[pallet::weight(<T as Config>::WeightInfo::change_threshold_accounts())]
        pub fn change_threshold_accounts(
            origin: OriginFor<T>,
            tss_account: T::AccountId,
            x25519_public_key: X25519PublicKey,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let stash = Self::get_stash(&who)?;
            let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(stash)
                .or(Err(Error::<T>::InvalidValidatorId));
            ensure!(
                validator_id_res.is_ok(),
                pallet_staking_extension::Error::<T>::InvalidValidatorId
            );
            let validator_id =
                validator_id_res.expect("Issue converting account id into validator id");
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
        #[pallet::weight(<T as Config>::WeightInfo::withdraw_unbonded())]
        pub fn withdraw_unbonded(
            origin: OriginFor<T>,
            num_slashing_spans: u32,
        ) -> DispatchResultWithPostInfo {
            let controller = ensure_signed(origin.clone())?;
            match pallet_staking::Pallet::<T>::ledger(&controller) {
                Some(ledger) => {
                    let stash = ledger.stash;
                    let validator_id_res =
                        <T as pallet_session::Config>::ValidatorId::try_from(stash)
                            .or(Err(Error::<T>::InvalidValidatorId));
                    ensure!(
                        validator_id_res.is_ok(),
                        pallet_staking_extension::Error::<T>::InvalidValidatorId
                    );
                    let validator_id =
                        validator_id_res.expect("Issue converting account id into validator id");
                    pallet_staking::Pallet::<T>::withdraw_unbonded(origin, num_slashing_spans)?;
                    if pallet_staking::Pallet::<T>::ledger(&controller).is_none() {
                        let server_info = ThresholdServers::<T>::take(&validator_id)
                            .ok_or(Error::<T>::NoThresholdKey)?;
                        ThresholdToStash::<T>::remove(&server_info.tss_account);
                    }
                },
                None => return Err(Error::<T>::NotController.into()),
            }
            Self::deposit_event(Event::NodeInfoRemoved(controller));
            Ok(().into())
        }

        /// Wraps's substrate validate but forces threshold key and endpoint
        /// `endpoint`: nodes's endpoint
        /// `threshold_account`: nodes's threshold account
        #[pallet::weight(<T as Config>::WeightInfo::validate())]
        pub fn validate(
            origin: OriginFor<T>,
            prefs: ValidatorPrefs,
            endpoint: Vec<u8>,
            tss_account: T::AccountId,
            x25519_public_key: X25519PublicKey,
        ) -> DispatchResult {
            let who = ensure_signed(origin.clone())?;
            ensure!(
                endpoint.len() as u32 <= T::MaxEndpointLength::get(),
                Error::<T>::EndpointTooLong
            );
            let stash = Self::get_stash(&who)?;
            pallet_staking::Pallet::<T>::validate(origin, prefs)?;
            let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(stash)
                .or(Err(Error::<T>::InvalidValidatorId));
            ensure!(
                validator_id_res.is_ok(),
                pallet_staking_extension::Error::<T>::InvalidValidatorId
            );
            let validator_id =
                validator_id_res.expect("Issue converting account id into validator id");

            ThresholdServers::<T>::insert(
                validator_id.clone(),
                ServerInfo {
                    tss_account: tss_account.clone(),
                    x25519_public_key,
                    endpoint: endpoint.clone(),
                },
            );
            ThresholdToStash::<T>::insert(&tss_account, validator_id);

            Self::deposit_event(Event::NodeInfoChanged(who, endpoint, tss_account));
            Ok(())
        }
    }
    impl<T: Config> Pallet<T> {
        pub fn get_stash(controller: &T::AccountId) -> Result<T::AccountId, DispatchError> {
            let ledger =
                pallet_staking::Pallet::<T>::ledger(controller).ok_or(Error::<T>::NotController)?;
            Ok(ledger.stash)
        }

        pub fn new_session_handler(validators: &[<T as pallet_session::Config>::ValidatorId]) {
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
                        .unwrap();
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
                Pallet::<T>::new_session_handler(validators);
            }
            new_session
        }

        fn new_session_genesis(new_index: SessionIndex) -> Option<Vec<ValidatorId>> {
            log::info!("test inside gesnsisi");

            I::new_session_genesis(new_index)
        }

        fn end_session(end_index: SessionIndex) { I::end_session(end_index); }

        fn start_session(start_index: SessionIndex) { I::start_session(start_index); }
    }
}
