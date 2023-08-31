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
    use entropy_shared::{Constraints, KeyVisibility, SIGNING_PARTY_SIZE};
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

    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct RegisteringDetails<T: Config> {
        pub is_registering: bool,
        pub constraint_account: T::AccountId,
        pub is_swapping: bool,
        pub confirmations: Vec<u8>,
        pub constraints: Option<Constraints>,
        pub key_visibility: KeyVisibility,
    }

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        #[allow(clippy::type_complexity)]
        pub registered_accounts: Vec<(T::AccountId, u8)>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self { Self { registered_accounts: Default::default() } }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            for account_info in &self.registered_accounts {
                let key_visibility = match account_info.1 {
                    1 => KeyVisibility::Private,
                    2 => KeyVisibility::Permissioned,
                    _ => KeyVisibility::Public,
                };
                Registered::<T>::insert(account_info.0.clone(), key_visibility);
                AllowedToModifyConstraints::<T>::insert(
                    account_info.0.clone(),
                    account_info.0.clone(),
                    (),
                );
            }
        }
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn registering)]
    pub type Registering<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, RegisteringDetails<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn dkg)]
    pub type Dkg<T: Config> =
        StorageMap<_, Blake2_128Concat, T::BlockNumber, Vec<Vec<u8>>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn registered)]
    pub type Registered<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, KeyVisibility, OptionQuery>;

    // Pallets use events to inform users when important changes are made.
    // https://substrate.dev/docs/en/knowledgebase/runtime/events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// An account has signaled to be registered. [signature request account]
        SignalRegister(T::AccountId),
        /// An account has been registered. [who, signing_group]
        AccountRegistering(T::AccountId, u8),
        /// An account has been registered. \[who\]
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
        /// Signals that a user wants to register an account with Entropy.
        ///
        /// This should be called by the signature-request account, and specify the initial
        /// constraint-modification `AccountId` that can set constraints.
        #[pallet::call_index(0)]
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
            key_visibility: KeyVisibility,
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
            let block_number = <frame_system::Pallet<T>>::block_number();
            Dkg::<T>::try_mutate(block_number, |messages| -> Result<_, DispatchError> {
                messages.push(sig_req_account.clone().encode());
                Ok(())
            })?;
            // put account into a registering state
            Registering::<T>::insert(
                &sig_req_account,
                RegisteringDetails::<T> {
                    is_registering: true,
                    constraint_account: constraint_account.clone(),
                    is_swapping: false,
                    confirmations: vec![],
                    constraints: initial_constraints,
                    key_visibility,
                },
            );

            // TODO add dkg creators for dkg and prep offchain worker for dkg
            // also maybe need a second storage slot to delete after worker message has been sent

            Self::deposit_event(Event::SignalRegister(sig_req_account));

            Ok(())
        }

        /// Used by validators to confirm they have received a key-share from a user that is
        /// registering. After a validator from each partition confirms they have a
        /// keyshare, this should get the user to a `Registered` state
        #[pallet::call_index(2)]
        #[pallet::weight(<T as Config>::WeightInfo::confirm_register_swapping(SIGNING_PARTY_SIZE as u32))]
        pub fn confirm_register(
            origin: OriginFor<T>,
            sig_req_account: T::AccountId,
            signing_subgroup: u8,
        ) -> DispatchResultWithPostInfo {
            let ts_server_account = ensure_signed(origin)?;
            let validator_stash =
                pallet_staking_extension::Pallet::<T>::threshold_to_stash(&ts_server_account)
                    .ok_or(Error::<T>::NoThresholdKey)?;

            let mut registering_info =
                Self::registering(&sig_req_account).ok_or(Error::<T>::NotRegistering)?;
            let confirmation_length = registering_info.confirmations.len() as u32;
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
                let mut weight;
                Registered::<T>::insert(&sig_req_account, registering_info.key_visibility);
                Registering::<T>::remove(&sig_req_account);
                weight =
                    <T as Config>::WeightInfo::confirm_register_registered(confirmation_length);
                if !registering_info.is_swapping {
                    AllowedToModifyConstraints::<T>::insert(
                        &registering_info.constraint_account,
                        sig_req_account.clone(),
                        (),
                    );

                    if let Some(constraints) = registering_info.constraints {
                        ConstraintsPallet::<T>::set_constraints_unchecked(
                            &sig_req_account,
                            &constraints,
                        );
                    }
                    weight =
                        <T as Config>::WeightInfo::confirm_register_swapping(confirmation_length);
                }

                Self::deposit_event(Event::AccountRegistered(sig_req_account));
                Ok(Some(weight).into())
            } else {
                registering_info.confirmations.push(signing_subgroup);
                Registering::<T>::insert(&sig_req_account, registering_info);
                Self::deposit_event(Event::AccountRegistering(sig_req_account, signing_subgroup));
                Ok(Some(<T as Config>::WeightInfo::confirm_register_registering(
                    confirmation_length,
                ))
                .into())
            }
        }
    }

    impl<T: Config> Pallet<T> {
        #[allow(clippy::type_complexity)]
        pub fn get_validator_info() -> Result<(Vec<ServerInfo<T::AccountId>>, u32), Error<T>> {
            let mut validators_info: Vec<ServerInfo<T::AccountId>> = vec![];
            let block_number = <frame_system::Pallet<T>>::block_number();

            // TODO: JA simple hacky way to do this, get the first address from each signing group
            // need good algorithim for this
            let mut l: u32 = 0;
            for i in 0..SIGNING_PARTY_SIZE {
                let tuple = Self::get_validator_rotation(i as u8, block_number)?;
                l = tuple.1;
                let validator_info =
                    pallet_staking_extension::Pallet::<T>::threshold_server(&tuple.0)
                        .ok_or(Error::<T>::IpAddressError)?;
                validators_info.push(validator_info);
            }
            Ok((validators_info, l))
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
