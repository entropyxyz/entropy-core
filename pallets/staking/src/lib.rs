#![cfg_attr(not(feature = "std"), no_std)]
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
    use core::convert::TryInto;

    use frame_support::{
        dispatch::DispatchResult, inherent::Vec, pallet_prelude::*, traits::Currency,
    };
    use frame_system::pallet_prelude::*;
    use pallet_staking::ValidatorPrefs;

    pub use crate::weights::WeightInfo;

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_staking::Config {
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
    /// Unique type to differentiate the threshold server's account ID from the validator's
    /// stash/controller accounts
    pub type TssServerAccount<AccountId> = AccountId;
    /// X25519 public key used by the client in non-interactive ECDH to authenticate/encrypt
    /// interactions with the threshold server (eg distributing threshold shares).
    pub type X25519PublicKey = [u8; 32];
    /// Endpoint where a threshold server can be reached at
    pub type TssServerURL = Vec<u8>;

    /// The balance type of this pallet.
    pub type BalanceOf<T> = <<T as pallet_staking::Config>::Currency as Currency<
        <T as frame_system::Config>::AccountId,
    >>::Balance;

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    // TODO JH We could prob use more efficient data structures (less duplicate data or query time)
    // for storing validator/server/endpoint/subgroup information

    /// Stores the relationship between a validator's stash account and the IP address/endpoint they
    /// can be reached at.
    #[pallet::storage]
    #[pallet::getter(fn endpoint_register)]
    pub type EndpointRegister<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, TssServerURL, OptionQuery>;

    /// Stores the relationship between
    /// a validator's stash account and their threshold server's sr25519 and x25519 keys.
    ///
    /// Clients query this via state or `stakingExtension_getKeys` RPC and uses
    /// the x25519 pub key in noninteractive ECDH for authenticating/encrypting distribute TSS
    /// shares over HTTP.
    #[pallet::storage]
    #[pallet::getter(fn threshold_account)]
    pub type ThresholdAccounts<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        (TssServerAccount<T::AccountId>, X25519PublicKey),
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
        Vec<TssServerAccount<T::AccountId>>,
        OptionQuery,
    >;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub endpoints: Vec<(T::AccountId, Vec<u8>)>,
        #[allow(clippy::type_complexity)]
        pub threshold_accounts: Vec<(T::AccountId, (T::AccountId, [u8; 32]))>,
        pub signing_groups: Vec<(u8, Vec<T::AccountId>)>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self {
                endpoints: Default::default(),
                threshold_accounts: Default::default(),
                signing_groups: Default::default(),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            let _ = self
                .endpoints
                .clone()
                .into_iter()
                .map(|x| assert!(x.1.len() as u32 <= T::MaxEndpointLength::get()));

            for (validator_stash, tss_endpoint_url) in &self.endpoints {
                EndpointRegister::<T>::insert(validator_stash, tss_endpoint_url);
            }

            for (validator_stash, tss_server_keys) in &self.threshold_accounts {
                ThresholdAccounts::<T>::insert(validator_stash, tss_server_keys);
            }

            for (group_id, tss_server_account) in &self.signing_groups {
                SigningGroups::<T>::insert(group_id, tss_server_account);
            }
        }
    }
    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        EndpointTooLong,
        NoBond,
        NotController,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// An endpoint has been added or edited. [who, endpoint]
        EndpointChanged(T::AccountId, Vec<u8>),
        /// Node Info has been added or edited. [who, endpoint, threshold_account]
        NodeInfoChanged(T::AccountId, Vec<u8>, T::AccountId),
        /// A threshold account has been added or edited. [validator, threshold_account]
        ThresholdAccountChanged(T::AccountId, (T::AccountId, [u8; 32])),
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
            EndpointRegister::<T>::insert(&who, &endpoint);
            Self::deposit_event(Event::EndpointChanged(who, endpoint));
            Ok(())
        }

        /// Allows a validator to change their threshold key so can confirm done when coms manager
        /// `new_account`: nodes's threshold account
        #[pallet::weight(<T as Config>::WeightInfo::change_threshold_accounts())]
        pub fn change_threshold_accounts(
            origin: OriginFor<T>,
            threshold_account: TssServerAccount<T::AccountId>,
            ecdh_pub_key: X25519PublicKey,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let stash = Self::get_stash(&who)?;
            ThresholdAccounts::<T>::insert(&stash, (&threshold_account, ecdh_pub_key));
            Self::deposit_event(Event::ThresholdAccountChanged(
                stash,
                (threshold_account, ecdh_pub_key),
            ));
            Ok(())
        }

        /// Wraps's substrate withdraw unbonded but clears extra state if fully unbonded
        #[pallet::weight(<T as Config>::WeightInfo::withdraw_unbonded())]
        pub fn withdraw_unbonded(
            origin: OriginFor<T>,
            num_slashing_spans: u32,
        ) -> DispatchResultWithPostInfo {
            let controller = ensure_signed(origin.clone())?;
            let stash = Self::get_stash(&controller)?;
            pallet_staking::Pallet::<T>::withdraw_unbonded(origin, num_slashing_spans)?;
            let ledger = pallet_staking::Pallet::<T>::ledger(&controller);
            if ledger.is_none() && Self::endpoint_register(&controller).is_some() {
                EndpointRegister::<T>::remove(&controller);
                ThresholdAccounts::<T>::remove(stash);
                Self::deposit_event(Event::NodeInfoRemoved(controller));
            }
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
            threshold_account: TssServerAccount<T::AccountId>,
            ecdh_pub_key: X25519PublicKey,
        ) -> DispatchResult {
            let who = ensure_signed(origin.clone())?;
            ensure!(
                endpoint.len() as u32 <= T::MaxEndpointLength::get(),
                Error::<T>::EndpointTooLong
            );
            let stash = Self::get_stash(&who)?;
            pallet_staking::Pallet::<T>::validate(origin, prefs)?;
            EndpointRegister::<T>::insert(&who, &endpoint);
            ThresholdAccounts::<T>::insert(&stash, (&threshold_account, ecdh_pub_key));
            Self::deposit_event(Event::NodeInfoChanged(who, endpoint, threshold_account));
            Ok(())
        }
    }
    impl<T: Config> Pallet<T> {
        pub fn get_stash(controller: &T::AccountId) -> Result<T::AccountId, DispatchError> {
            let ledger =
                pallet_staking::Pallet::<T>::ledger(controller).ok_or(Error::<T>::NotController)?;
            Ok(ledger.stash)
        }
    }
}
