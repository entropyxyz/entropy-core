//! # Relayer Pallet
//!
//!
//! ## Overview
//!
//! Allows a user to ask to sign, register with the network and allows a node to confirm
//! signing was completed properly.
//!
//! ### Public Functions
//!
//! prep_transaction - declares intent to sign, this gets relayed to thereshold network
//! register - register's a user and that they have created and distributed entropy shards
//! confirm_done - allows a node to confirm signing has happened and if a failure occured
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::new_without_default)]
#![allow(clippy::or_fun_call)]
#![allow(clippy::derive_partial_eq_without_eq)] // Substrate confuses clippy
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
    use entropy_shared::{Constraints, Message, SigRequest, SIGNING_PARTY_SIZE};
    use frame_support::{
        dispatch::{DispatchResult, DispatchResultWithPostInfo},
        inherent::Vec,
        pallet_prelude::*,
    };
    use frame_system::pallet_prelude::*;
    use pallet_constraints::{AllowedToModifyConstraints, Pallet as ConstraintsPallet};
    use pallet_staking_extension::ServerInfo;
    use scale_info::TypeInfo;
    use sp_std::vec;

    pub use crate::weights::WeightInfo;
    /// Configure the pallet by specifying the parameters and types on which it depends.
    #[pallet::config]
    pub trait Config:
        pallet_session::Config
        + frame_system::Config
        + pallet_authorship::Config
        + pallet_staking_extension::Config
        + pallet_constraints::Config
    {
        /// Because this pallet emits events, it depends on the runtime's definition of an event.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type PruneBlock: Get<Self::BlockNumber>;
        type SigningPartySize: Get<usize>;
        /// The weight information of this pallet.
        type WeightInfo: WeightInfo;
    }

    type MaxValidators<T> =  <<T as pallet_staking::Config>::BenchmarkingConfig as pallet_staking::BenchmarkingConfig>::MaxValidators;

    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct RegisteringDetails<T: Config> {
        pub is_registering: bool,
        pub constraint_account: T::AccountId,
        pub is_swapping: bool,
        pub confirmations: Vec<u8>,
        pub constraints: Option<Constraints>,
    }

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        #[allow(clippy::type_complexity)]
        pub registered_accounts: Vec<(T::AccountId, bool)>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self { Self { registered_accounts: Default::default() } }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            for (account, registered) in &self.registered_accounts {
                Registered::<T>::insert(account, registered);
                AllowedToModifyConstraints::<T>::insert(account, account, ());
            }
        }
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn messages)]
    pub type Messages<T: Config> =
        StorageMap<_, Blake2_128Concat, T::BlockNumber, Vec<Message>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn failures)]
    pub type Failures<T: Config> =
        StorageMap<_, Blake2_128Concat, T::BlockNumber, Vec<u32>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn registering)]
    pub type Registering<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, RegisteringDetails<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn registered)]
    pub type Registered<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, bool, OptionQuery>;

    // Pallets use events to inform users when important changes are made.
    // https://substrate.dev/docs/en/knowledgebase/runtime/events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A transaction has been propagated to the network. [who]
        SignatureRequested(Message),
        /// An account has signaled to be registered. [signature request account]
        SignalRegister(T::AccountId),
        /// An account has been registered. [who, signing_group]
        AccountRegistering(T::AccountId, u8),
        /// An account has been registered. [who]
        AccountRegistered(T::AccountId),
        /// An account has been registered. [who, block_number, failures]
        ConfirmedDone(T::AccountId, T::BlockNumber, Vec<u32>),
    }

    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        AlreadySubmitted,
        NoThresholdKey,
        NotRegistering,
        NotRegistered,
        InvalidSubgroup,
        AlreadyConfirmed,
        NotInSigningGroup,
        IpAddressError,
        SigningGroupError,
        NoSyncedValidators,
    }

    /// Allows a user to kick off signing process
    /// `sig_request`: signature request for user
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(<T as Config>::WeightInfo::prep_transaction(MaxValidators::<T>::get() / SIGNING_PARTY_SIZE as u32))]
        pub fn prep_transaction(
            origin: OriginFor<T>,
            sig_request: SigRequest,
        ) -> DispatchResultWithPostInfo {
            log::warn!("relayer::prep_transaction::sig_request: {:?}", sig_request);
            let who = ensure_signed(origin)?;
            ensure!(
                Self::registered(&who).ok_or(Error::<T>::NotRegistered)?,
                Error::<T>::NotRegistered
            );
            let (ip_addresses, i) = Self::get_ip_addresses()?;
            let message = Message { sig_request, account: who.encode(), ip_addresses };
            let block_number = <frame_system::Pallet<T>>::block_number();
            Messages::<T>::try_mutate(block_number, |request| -> Result<_, DispatchError> {
                request.push(message.clone());
                Ok(())
            })?;

            Self::deposit_event(Event::SignatureRequested(message));

            Ok(Some(<T as Config>::WeightInfo::prep_transaction(i)).into())
        }

        /// Signals that a user wants to register an account with Entropy.
        ///
        /// This should be called by the signature-request account, and specify the initial
        /// constraint-modification `AccountId` that can set constraints.
        #[pallet::weight({
            let (mut evm_acl_len, mut btc_acl_len) = (0, 0);
            if let Some(constraints) = &initial_constraints {
                (evm_acl_len, btc_acl_len) = ConstraintsPallet::<T>::constraint_weight_values(constraints);
            }
            <T as Config>::WeightInfo::register(evm_acl_len, btc_acl_len)
        })]
        pub fn register(
            origin: OriginFor<T>,
            constraint_account: T::AccountId,
            initial_constraints: Option<Constraints>,
        ) -> DispatchResult {
            let sig_req_account = ensure_signed(origin)?;

            // ensure account isn't already registered or has existing constraints
            ensure!(!Registered::<T>::contains_key(&sig_req_account), Error::<T>::AlreadySubmitted);
            ensure!(
                !Registering::<T>::contains_key(&sig_req_account),
                Error::<T>::AlreadySubmitted
            );
            if let Some(constraints) = &initial_constraints {
                ConstraintsPallet::<T>::validate_constraints(constraints)?;
            }

            // put account into a registering state
            Registering::<T>::insert(
                &sig_req_account,
                RegisteringDetails::<T> {
                    is_registering: true,
                    constraint_account: constraint_account.clone(),
                    is_swapping: false,
                    confirmations: vec![],
                    constraints: initial_constraints,
                },
            );

            Self::deposit_event(Event::SignalRegister(sig_req_account));

            Ok(())
        }

        /// Signals that a user wants to swap our their keys
        // TODO: John do benchmarks
        #[pallet::weight(<T as Config>::WeightInfo::register(0, 0))]
        pub fn swap_keys(origin: OriginFor<T>) -> DispatchResult {
            let sig_req_account = ensure_signed(origin)?;
            ensure!(
                Self::registered(&sig_req_account).ok_or(Error::<T>::NotRegistered)?,
                Error::<T>::NotRegistered
            );

            let registering_info = RegisteringDetails::<T> {
                is_registering: true,
                // This value doesn't get used in confirm_done() when is_swapping is true
                constraint_account: sig_req_account.clone(),
                is_swapping: true,
                confirmations: vec![],
                // This value doesn't get used in confirm_done() when is_swapping is true
                constraints: None,
            };

            Registered::<T>::remove(&sig_req_account);
            Registering::<T>::insert(&sig_req_account, registering_info);

            Self::deposit_event(Event::SignalRegister(sig_req_account));
            Ok(())
        }

        // TODO add benchmarks
        /// Used by validators to confirm they have received a key-share from a user that is
        /// registering. After a validator from each partition confirms they have a
        /// keyshare, this should get the user to a `Registered` state
        #[pallet::weight(T::DbWeight::get().writes(1))]
        pub fn confirm_register(
            origin: OriginFor<T>,
            sig_req_account: T::AccountId,
            signing_subgroup: u8,
        ) -> DispatchResult {
            let ts_server_account = ensure_signed(origin)?;
            let validator_stash =
                pallet_staking_extension::Pallet::<T>::threshold_to_stash(&ts_server_account)
                    .ok_or(Error::<T>::NoThresholdKey)?;

            let mut registering_info =
                Self::registering(&sig_req_account).ok_or(Error::<T>::NotRegistering)?;
            ensure!(
                !registering_info.confirmations.contains(&signing_subgroup),
                Error::<T>::AlreadyConfirmed
            );

            let signing_subgroup_addresses =
                pallet_staking_extension::Pallet::<T>::signing_groups(signing_subgroup)
                    .ok_or(Error::<T>::InvalidSubgroup)?;
            ensure!(
                signing_subgroup_addresses.contains(&validator_stash),
                Error::<T>::NotInSigningGroup
            );

            if registering_info.confirmations.len() == T::SigningPartySize::get() - 1 {
                Registered::<T>::insert(&sig_req_account, true);
                Registering::<T>::remove(&sig_req_account);
                if !registering_info.is_swapping {
                    AllowedToModifyConstraints::<T>::insert(
                        &registering_info.constraint_account,
                        sig_req_account.clone(),
                        (),
                    );

                    if let Some(constraints) = registering_info.constraints {
                        ConstraintsPallet::<T>::set_constraints_unchecked(
                            sig_req_account.clone(),
                            constraints,
                        );
                    }
                }

                Self::deposit_event(Event::AccountRegistered(sig_req_account));
            } else {
                registering_info.confirmations.push(signing_subgroup);
                Registering::<T>::insert(&sig_req_account, registering_info);
                Self::deposit_event(Event::AccountRegistering(sig_req_account, signing_subgroup));
            }
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn get_ip_addresses() -> Result<(Vec<Vec<u8>>, u32), Error<T>> {
            let mut ip_addresses: Vec<Vec<u8>> = vec![];
            let block_number = <frame_system::Pallet<T>>::block_number();

            // TODO: JA simple hacky way to do this, get the first address from each signing group
            // need good algorithim for this
            let mut l: u32 = 0;
            for i in 0..SIGNING_PARTY_SIZE {
                let tuple = Self::get_validator_rotation(i as u8, block_number)?;
                l = tuple.1;
                let ServerInfo { endpoint, .. } =
                    pallet_staking_extension::Pallet::<T>::threshold_server(&tuple.0)
                        .ok_or(Error::<T>::IpAddressError)?;
                ip_addresses.push(endpoint.clone());
            }
            Ok((ip_addresses, l))
        }

        pub fn get_validator_rotation(
            signing_group: u8,
            block_number: T::BlockNumber,
        ) -> Result<(<T as pallet_session::Config>::ValidatorId, u32), Error<T>> {
            let mut i: u32 = 0;
            let mut addresses =
                pallet_staking_extension::Pallet::<T>::signing_groups(signing_group)
                    .ok_or(Error::<T>::SigningGroupError)?;
            let converted_block_number: u32 =
                T::BlockNumber::try_into(block_number).unwrap_or_default();
            let address = loop {
                ensure!(!addresses.is_empty(), Error::<T>::NoSyncedValidators);
                let selection: u32 = converted_block_number % addresses.len() as u32;
                let address = &addresses[selection as usize];
                let address_state =
                    pallet_staking_extension::Pallet::<T>::is_validator_synced(address);
                if !address_state {
                    addresses.remove(selection as usize);
                    i += 1;
                } else {
                    i += 1;
                    break address;
                }
            };
            Ok((address.clone(), i))
        }
    }
}
