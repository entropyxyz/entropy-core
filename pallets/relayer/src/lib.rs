//! # Relayer Pallet
//!
//! ## Overview
//!
//! Entrypoint into the Entropy network.
//!
//! It allows a user to submit a registration request to the network initiating the distributed key
//! generation (DKG) process.
//!
//! After this process validator nodes on the network can confirm that they have received a
//! key-share from the registering user. Once enough validators have signaled that they have the
//! user's key-share (right now this is one validator per partition) the user can be considered as
//! registered.
//!
//! ### Public Functions
//!
//! `register` - Allows a user to signal their intent to register onto the Entropy network.
//! `confirm_register` - Allows validator nodes to confirm that they have recieved a user's
//! key-share. After enough succesful confirmations from validators that user will be succesfully
//! registered.

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
    use entropy_shared::{KeyVisibility, SIGNING_PARTY_SIZE};
    use frame_support::{
        dispatch::{DispatchResult, DispatchResultWithPostInfo, Pays, Vec},
        pallet_prelude::*,
        traits::{ConstU32, IsSubType},
    };
    use frame_system::pallet_prelude::*;
    use pallet_staking_extension::ServerInfo;
    use scale_info::TypeInfo;
    use sp_runtime::traits::{DispatchInfoOf, SignedExtension};
    use sp_std::{fmt::Debug, vec};

    pub use crate::weights::WeightInfo;

    const VERIFICATION_KEY_LENGTH: u32 = 33;
    /// Configure the pallet by specifying the parameters and types on which it depends.
    #[pallet::config]
    pub trait Config:
        pallet_session::Config
        + frame_system::Config
        + pallet_authorship::Config
        + pallet_staking_extension::Config
        + pallet_programs::Config
    {
        /// Because this pallet emits events, it depends on the runtime's definition of an event.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type SigningPartySize: Get<usize>;
        /// The weight information of this pallet.
        type WeightInfo: WeightInfo;
    }

    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct RegisteringDetails<T: Config> {
        pub program_modification_account: T::AccountId,
        pub confirmations: Vec<u8>,
        pub program_pointer: T::Hash,
        pub key_visibility: KeyVisibility,
        pub verifying_key: Option<BoundedVec<u8, ConstU32<VERIFICATION_KEY_LENGTH>>>,
    }

    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct RegisteredInfo<Hash> {
        pub key_visibility: KeyVisibility,
        // TODO better type
        pub verifying_key: BoundedVec<u8, ConstU32<33>>,
        pub program_pointer: Hash,
    }

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        #[allow(clippy::type_complexity)]
        pub registered_accounts: Vec<(T::AccountId, u8, Option<[u8; 32]>)>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            for account_info in &self.registered_accounts {
                let key_visibility = match account_info.1 {
                    1 => KeyVisibility::Private(
                        account_info.2.expect("Private key visibility needs x25519 public key"),
                    ),
                    2 => KeyVisibility::Permissioned,
                    _ => KeyVisibility::Public,
                };
                Registered::<T>::insert(
                    account_info.0.clone(),
                    RegisteredInfo {
                        key_visibility,
                        verifying_key: BoundedVec::default(),
                        program_pointer: T::Hash::default(),
                    },
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
        StorageMap<_, Blake2_128Concat, BlockNumberFor<T>, Vec<Vec<u8>>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn registered)]
    pub type Registered<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, RegisteredInfo<T::Hash>, OptionQuery>;

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
        /// An account registration has failed
        FailedRegistration(T::AccountId),
        /// An account cancelled their registration
        RegistrationCancelled(T::AccountId),
        /// An account has been registered. [who, block_number, failures]
        ConfirmedDone(T::AccountId, BlockNumberFor<T>, Vec<u32>),
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
        MaxProgramLengthExceeded,
        NoVerifyingKey,
        NotAuthorized,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Allows a user to signal that they want to register an account with the Entropy network.
        ///
        /// The caller provides an initial program, if any, an account which is able to modify a
        /// the program, and the program's permission level on the network.
        ///
        /// Note that a user needs to be confirmed by validators through the
        /// [`Self::confirm_register`] extrinsic before they can be considered as registered on the
        /// network.
        #[pallet::call_index(0)]
        //TODO fix
        #[pallet::weight({
            <T as Config>::WeightInfo::register(0u32)
        })]
        pub fn register(
            origin: OriginFor<T>,
            program_modification_account: T::AccountId,
            key_visibility: KeyVisibility,
            program_pointer: T::Hash,
        ) -> DispatchResult {
            let sig_req_account = ensure_signed(origin)?;

            // Ensure account isn't already registered or has existing programs
            ensure!(!Registered::<T>::contains_key(&sig_req_account), Error::<T>::AlreadySubmitted);
            ensure!(
                !Registering::<T>::contains_key(&sig_req_account),
                Error::<T>::AlreadySubmitted
            );

            let block_number = <frame_system::Pallet<T>>::block_number();
            Dkg::<T>::try_mutate(block_number, |messages| -> Result<_, DispatchError> {
                messages.push(sig_req_account.clone().encode());
                Ok(())
            })?;

            // Put account into a registering state
            Registering::<T>::insert(
                &sig_req_account,
                RegisteringDetails::<T> {
                    program_modification_account,
                    confirmations: vec![],
                    program_pointer,
                    key_visibility,
                    verifying_key: None,
                },
            );

            // TODO add dkg creators for dkg and prep offchain worker for dkg
            // also maybe need a second storage slot to delete after worker message has been sent

            Self::deposit_event(Event::SignalRegister(sig_req_account));

            Ok(())
        }

        /// Allows a user to remove themselves from registering state if it has been longer than prune block
        #[pallet::call_index(1)]
        #[pallet::weight({
            <T as Config>::WeightInfo::prune_registration()
        })]
        pub fn prune_registration(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::registering(&who).ok_or(Error::<T>::NotRegistering)?;
            Registering::<T>::remove(&who);
            Self::deposit_event(Event::RegistrationCancelled(who));
            Ok(())
        }

        #[pallet::call_index(2)]
        // TODO fix bench
        #[pallet::weight({
     <T as Config>::WeightInfo::prune_registration()
 })]
        pub fn change_program_pointer(
            origin: OriginFor<T>,
            program_pointer: T::Hash,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Registering::<T>::try_mutate_exists(
                &who,
                |maybe_registerd_details| -> Result<_, DispatchError> {
                    let mut registerd_details =
                        maybe_registerd_details.take().ok_or(Error::<T>::NotRegistered)?;
                    ensure!(
                        who == registerd_details.program_modification_account,
                        Error::<T>::NotAuthorized
                    );
                    registerd_details.program_pointer = program_pointer;
                    Ok(())
                },
            )?;
            //  let registerd_details = Self::registering(&who).ok_or(Error::<T>::NotRegistering)?;

            //  Self::deposit_event(Event::RegistrationCancelled(who));
            Ok(())
        }

        /// Allows validators to confirm that they have received a key-share from a user that is
        /// in the process of registering.
        ///
        /// After a validator from each partition confirms they have a keyshare the user will be
        /// considered as registered on the network.
        #[pallet::call_index(3)]
        #[pallet::weight({
            let weight =
                <T as Config>::WeightInfo::confirm_register_registering(SIGNING_PARTY_SIZE as u32)
                .max(<T as Config>::WeightInfo::confirm_register_registered(SIGNING_PARTY_SIZE as u32))
                .max(<T as Config>::WeightInfo::confirm_register_failed_registering(SIGNING_PARTY_SIZE as u32));
            (weight, Pays::No)
        })]
        pub fn confirm_register(
            origin: OriginFor<T>,
            sig_req_account: T::AccountId,
            signing_subgroup: u8,
            verifying_key: BoundedVec<u8, ConstU32<VERIFICATION_KEY_LENGTH>>,
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
            // if no one has sent in a verifying key yet, use current
            if registering_info.verifying_key.is_none() {
                registering_info.verifying_key = Some(verifying_key.clone());
            }

            let registering_info_verifying_key =
                registering_info.verifying_key.clone().ok_or(Error::<T>::NoVerifyingKey)?;

            if registering_info.confirmations.len() == T::SigningPartySize::get() - 1 {
                // If verifying key does not match for everyone, registration failed
                if registering_info_verifying_key != verifying_key {
                    Registering::<T>::remove(&sig_req_account);
                    Self::deposit_event(Event::FailedRegistration(sig_req_account));
                    return Ok(Some(
                        <T as Config>::WeightInfo::confirm_register_failed_registering(
                            confirmation_length,
                        ),
                    )
                    .into());
                }
                Registered::<T>::insert(
                    &sig_req_account,
                    RegisteredInfo {
                        key_visibility: registering_info.key_visibility,
                        verifying_key,
                        program_pointer: registering_info.program_pointer,
                    },
                );
                Registering::<T>::remove(&sig_req_account);

                let weight =
                    <T as Config>::WeightInfo::confirm_register_registered(confirmation_length);

                Self::deposit_event(Event::AccountRegistered(sig_req_account));
                Ok(Some(weight).into())
            } else {
                // If verifying key does not match for everyone, registration failed
                if registering_info_verifying_key != verifying_key {
                    Registering::<T>::remove(&sig_req_account);
                    Self::deposit_event(Event::FailedRegistration(sig_req_account));
                    return Ok(Some(
                        <T as Config>::WeightInfo::confirm_register_failed_registering(
                            confirmation_length,
                        ),
                    )
                    .into());
                }
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
            block_number: BlockNumberFor<T>,
        ) -> Result<(<T as pallet_session::Config>::ValidatorId, u32), Error<T>> {
            let mut i: u32 = 0;
            let mut addresses =
                pallet_staking_extension::Pallet::<T>::signing_groups(signing_group)
                    .ok_or(Error::<T>::SigningGroupError)?;
            let converted_block_number: u32 =
                BlockNumberFor::<T>::try_into(block_number).unwrap_or_default();
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

    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct ValidateConfirmRegistered<T: Config + Send + Sync>(sp_std::marker::PhantomData<T>)
    where
        <T as frame_system::Config>::RuntimeCall: IsSubType<Call<T>>;

    impl<T: Config + Send + Sync> Debug for ValidateConfirmRegistered<T>
    where
        <T as frame_system::Config>::RuntimeCall: IsSubType<Call<T>>,
    {
        #[cfg(feature = "std")]
        fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
            write!(f, "ValidateConfirmRegistered")
        }

        #[cfg(not(feature = "std"))]
        fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
            Ok(())
        }
    }

    impl<T: Config + Send + Sync> ValidateConfirmRegistered<T>
    where
        <T as frame_system::Config>::RuntimeCall: IsSubType<Call<T>>,
    {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self(sp_std::marker::PhantomData)
        }
    }

    impl<T: Config + Send + Sync> SignedExtension for ValidateConfirmRegistered<T>
    where
        <T as frame_system::Config>::RuntimeCall: IsSubType<Call<T>>,
    {
        type AccountId = T::AccountId;
        type AdditionalSigned = ();
        type Call = <T as frame_system::Config>::RuntimeCall;
        type Pre = ();

        const IDENTIFIER: &'static str = "ValidateConfirmRegistered";

        fn additional_signed(&self) -> Result<Self::AdditionalSigned, TransactionValidityError> {
            Ok(())
        }

        fn pre_dispatch(
            self,
            who: &Self::AccountId,
            call: &Self::Call,
            info: &DispatchInfoOf<Self::Call>,
            len: usize,
        ) -> Result<Self::Pre, TransactionValidityError> {
            self.validate(who, call, info, len).map(|_| ())
        }

        fn validate(
            &self,
            who: &Self::AccountId,
            call: &Self::Call,
            _info: &DispatchInfoOf<Self::Call>,
            _len: usize,
        ) -> TransactionValidity {
            if let Some(Call::confirm_register { sig_req_account, signing_subgroup, .. }) =
                call.is_sub_type()
            {
                let validator_stash =
                    pallet_staking_extension::Pallet::<T>::threshold_to_stash(who)
                        .ok_or(InvalidTransaction::Custom(1))?;

                let registering_info =
                    Registering::<T>::get(sig_req_account).ok_or(InvalidTransaction::Custom(2))?;
                ensure!(
                    !registering_info.confirmations.contains(signing_subgroup),
                    InvalidTransaction::Custom(3)
                );
                let signing_subgroup_addresses =
                    pallet_staking_extension::Pallet::<T>::signing_groups(signing_subgroup)
                        .ok_or(InvalidTransaction::Custom(4))?;
                ensure!(
                    signing_subgroup_addresses.contains(&validator_stash),
                    InvalidTransaction::Custom(5)
                );
            }
            Ok(ValidTransaction::default())
        }
    }
}
