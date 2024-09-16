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

//! # Registry Pallet
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
    use entropy_shared::{ValidatorInfo, MAX_SIGNERS, NETWORK_PARENT_KEY};
    use frame_support::{
        dispatch::DispatchResultWithPostInfo, pallet_prelude::*, traits::ConstU32,
    };
    use frame_system::pallet_prelude::*;
    use pallet_staking_extension::{
        JumpStartDetails, JumpStartProgress, JumpStartStatus, ServerInfo, VerifyingKey,
    };
    use rand::seq::SliceRandom;
    use scale_info::TypeInfo;
    use sp_std::vec;
    use sp_std::vec::Vec;

    pub use crate::weights::WeightInfo;

    /// Max modifiable keys allowed for a program modification account
    pub const MAX_MODIFIABLE_KEYS: u32 = 25;

    /// Blocks to wait until we agree jump start network failed and to allow a retry
    pub const BLOCKS_TO_RESTART_JUMP_START: u32 = 50;

    /// Configure the pallet by specifying the parameters and types on which it depends.
    #[pallet::config]
    pub trait Config:
        pallet_session::Config
        + frame_system::Config
        + pallet_authorship::Config
        + pallet_staking_extension::Config
        + pallet_programs::Config
        + pallet_parameters::Config
    {
        /// Because this pallet emits events, it depends on the runtime's definition of an event.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// Max amount of programs associated for one account
        type MaxProgramHashes: Get<u32>;
        /// Current Version Number of keyshares
        type KeyVersionNumber: Get<u8>;
        /// The weight information of this pallet.
        type WeightInfo: WeightInfo;
    }
    pub type ProgramPointers<Hash, MaxProgramHashes> = BoundedVec<Hash, MaxProgramHashes>;

    #[derive(Clone, Encode, Decode, Eq, PartialEqNoBound, RuntimeDebugNoBound, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct ProgramInstance<T: Config> {
        pub program_pointer: T::Hash,
        pub program_config: Vec<u8>,
    }

    #[derive(Clone, Encode, Decode, Eq, PartialEqNoBound, RuntimeDebug, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct RegisteringDetails<T: Config> {
        pub program_modification_account: T::AccountId,
        pub confirmations: Vec<T::AccountId>,
        pub programs_data: BoundedVec<ProgramInstance<T>, T::MaxProgramHashes>,
        pub verifying_key: Option<VerifyingKey>,
        pub version_number: u8,
    }

    #[derive(Clone, Encode, Decode, Eq, PartialEqNoBound, RuntimeDebug, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct RegisteredInfo<T: Config> {
        pub programs_data: BoundedVec<ProgramInstance<T>, T::MaxProgramHashes>,
        pub program_modification_account: T::AccountId,
        /// The SCALE encoded BIP-32 `DerivationPath` used to register this account.
        pub derivation_path: Option<Vec<u8>>,
        pub version_number: u8,
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Used for triggering a network wide distributed key generation request via an offchain
    /// workerg. Maps block number to the selected validators for jumpstart DKG.
    #[pallet::storage]
    #[pallet::getter(fn jumpstart_dkg)]
    pub type JumpstartDkg<T: Config> =
        StorageMap<_, Blake2_128Concat, BlockNumberFor<T>, Vec<ValidatorInfo>, ValueQuery>;

    /// An item tracking all the users registered on the Entropy network.
    ///
    /// Notice that the registration state does not depend on any Substrate account being
    /// registered, but rather a _verifying key_, which represents the user beyond the scope of the
    /// Entropy network itself (e.g it can be an account on Bitcoin or Ethereum).
    #[pallet::storage]
    #[pallet::getter(fn registered)]
    pub type Registered<T: Config> =
        CountedStorageMap<_, Blake2_128Concat, VerifyingKey, RegisteredInfo<T>, OptionQuery>;

    /// Mapping of program_modification accounts to verifying keys they can control
    #[pallet::storage]
    #[pallet::getter(fn modifiable_keys)]
    pub type ModifiableKeys<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<VerifyingKey, ConstU32<MAX_MODIFIABLE_KEYS>>,
        ValueQuery,
    >;

    // Pallets use events to inform users when important changes are made.
    // https://substrate.dev/docs/en/knowledgebase/runtime/events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// The network has been jump started.
        StartedNetworkJumpStart(),
        /// The network has been jump started successfully.
        FinishedNetworkJumpStart(),
        /// The network has had a jump start confirmation. [who, confirmation_count]
        JumpStartConfirmation(T::ValidatorId, u8),
        /// An account has been registered. \[who, verifying_key]
        AccountRegistered(T::AccountId, VerifyingKey),
        /// An account hash changed their program info [who, new_program_instance]
        ProgramInfoChanged(T::AccountId, BoundedVec<ProgramInstance<T>, T::MaxProgramHashes>),
        /// An account has changed their program modification account [old, new, verifying_key]
        ProgramModificationAccountChanged(T::AccountId, T::AccountId, VerifyingKey),
    }

    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        NoThresholdKey,
        NotRegistered,
        AlreadyConfirmed,
        IpAddressError,
        NotAuthorized,
        NoProgramSet,
        TooManyModifiableKeys,
        MismatchedVerifyingKey,
        NotValidator,
        JumpStartProgressNotReady,
        JumpStartNotInProgress,
        JumpStartNotCompleted,
        NoRegisteringFromParentKey,
        InvalidBip32DerivationPath,
        Bip32AccountDerivationFailed,
        NotEnoughValidatorsForJumpStart,
        CannotFindValidatorInfo,
    }

    /// Allows anyone to create a parent key for the network if the network is read and a parent key
    /// does not exist
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight({
            <T as Config>::WeightInfo::jump_start_network()
        })]
        pub fn jump_start_network(origin: OriginFor<T>) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            let current_block_number = <frame_system::Pallet<T>>::block_number();
            let converted_block_number: u32 =
                BlockNumberFor::<T>::try_into(current_block_number).unwrap_or_default();
            let parent_key_threshold = pallet_parameters::Pallet::<T>::signers_info().threshold;
            // make sure jumpstart is ready, or in progress but X amount of time has passed
            match JumpStartProgress::<T>::get().jump_start_status {
                JumpStartStatus::Ready => (),
                JumpStartStatus::InProgress(started_block_number) => {
                    if converted_block_number.saturating_sub(started_block_number)
                        < BLOCKS_TO_RESTART_JUMP_START
                    {
                        return Err(Error::<T>::JumpStartProgressNotReady.into());
                    };
                },
                _ => return Err(Error::<T>::JumpStartProgressNotReady.into()),
            };

            // Ensure we have at least n validators
            // TODO (#923): Add other checks for network state.
            let total_signers = pallet_parameters::Pallet::<T>::signers_info().total_signers;
            let validators = pallet_session::Pallet::<T>::validators();
            ensure!(
                validators.len() >= total_signers.into(),
                Error::<T>::NotEnoughValidatorsForJumpStart
            );

            // Select validators for jump start
            let mut rng = pallet_staking_extension::Pallet::<T>::get_randomness();
            let selected_validators: Vec<_> =
                validators.choose_multiple(&mut rng, total_signers.into()).cloned().collect();

            // Get validator info for each selected validator
            let mut validators_info = Vec::new();
            for validator_address in selected_validators {
                let server_info =
                    pallet_staking_extension::Pallet::<T>::threshold_server(&validator_address)
                        .ok_or(Error::<T>::CannotFindValidatorInfo)?;
                validators_info.push(ValidatorInfo {
                    x25519_public_key: server_info.x25519_public_key,
                    ip_address: server_info.endpoint.clone(),
                    tss_account: server_info.tss_account.encode(),
                });
            }
            JumpstartDkg::<T>::set(current_block_number, validators_info);
            JumpStartProgress::<T>::put(JumpStartDetails {
                jump_start_status: JumpStartStatus::InProgress(converted_block_number),
                confirmations: vec![],
                verifying_key: None,
                parent_key_threshold,
            });
            Self::deposit_event(Event::StartedNetworkJumpStart());
            Ok(())
        }

        /// Allows validators to signal a successful network jumpstart
        #[pallet::call_index(1)]
        #[pallet::weight({
                <T as Config>::WeightInfo::confirm_jump_start_confirm(MAX_SIGNERS as u32)
                .max(<T as Config>::WeightInfo::confirm_jump_start_done(MAX_SIGNERS as u32))
        })]
        pub fn confirm_jump_start(
            origin: OriginFor<T>,
            verifying_key: VerifyingKey,
        ) -> DispatchResultWithPostInfo {
            // Chack that the confirmation is coming from one of the selected validators
            let ts_server_account = ensure_signed(origin)?;
            let (_block_number, selected_validators) =
                JumpstartDkg::<T>::iter().last().ok_or(Error::<T>::JumpStartNotInProgress)?;
            let selected_validators: Vec<_> =
                selected_validators.into_iter().map(|v| v.tss_account).collect();
            ensure!(
                selected_validators.contains(&ts_server_account.encode()),
                Error::<T>::NotValidator
            );

            let mut jump_start_info = JumpStartProgress::<T>::get();
            match jump_start_info.verifying_key {
                Some(ref key) => {
                    ensure!(key == &verifying_key, Error::<T>::MismatchedVerifyingKey);
                },
                None => {
                    jump_start_info.verifying_key = Some(verifying_key);
                },
            }

            // check in progress
            ensure!(
                matches!(jump_start_info.jump_start_status, JumpStartStatus::InProgress(_)),
                Error::<T>::JumpStartNotInProgress
            );

            let validator_stash =
                pallet_staking_extension::Pallet::<T>::threshold_to_stash(&ts_server_account)
                    .ok_or(Error::<T>::NoThresholdKey)?;

            ensure!(
                !jump_start_info.confirmations.contains(&validator_stash),
                Error::<T>::AlreadyConfirmed
            );

            // TODO (#927): Add another check, such as a signature or a verifying key comparison, to
            // ensure that registration was indeed successful.
            //
            // If it fails we'll need to allow another jumpstart.
            let signers_amount = pallet_parameters::Pallet::<T>::signers_info().total_signers;
            if jump_start_info.confirmations.len() == (signers_amount as usize - 1) {
                // registration finished, lock call
                jump_start_info.confirmations.push(validator_stash);
                let confirmations = jump_start_info.confirmations.len();

                JumpStartProgress::<T>::put(JumpStartDetails {
                    jump_start_status: JumpStartStatus::Done,
                    confirmations: vec![],
                    verifying_key: jump_start_info.verifying_key,
                    parent_key_threshold: jump_start_info.parent_key_threshold,
                });
                // Jumpstart participants become first network signers
                pallet_staking_extension::Signers::<T>::put(jump_start_info.confirmations);
                Self::deposit_event(Event::FinishedNetworkJumpStart());

                return Ok(Some(<T as Config>::WeightInfo::confirm_jump_start_done(
                    confirmations as u32,
                ))
                .into());
            } else {
                // Add confirmation wait for next one
                jump_start_info.confirmations.push(validator_stash.clone());
                let confirmations = jump_start_info.confirmations.len();

                JumpStartProgress::<T>::put(jump_start_info);

                Self::deposit_event(Event::JumpStartConfirmation(
                    validator_stash,
                    confirmations as u8,
                ));

                return Ok(Some(<T as Config>::WeightInfo::confirm_jump_start_confirm(
                    confirmations as u32,
                ))
                .into());
            }
        }

        /// Allows a user to signal that they want to register an account with the Entropy network.
        ///
        /// The caller provides an initial program pointer.
        ///
        /// Note: Substrate origins are allowed to register as many accounts as they wish. Each
        /// registration request will produce a different verifying key.
        #[pallet::call_index(2)]
        #[pallet::weight({
            <T as Config>::WeightInfo::register(<T as Config>::MaxProgramHashes::get())
        })]
        pub fn register(
            origin: OriginFor<T>,
            program_modification_account: T::AccountId,
            programs_data: BoundedVec<ProgramInstance<T>, T::MaxProgramHashes>,
        ) -> DispatchResultWithPostInfo {
            use core::str::FromStr;
            use synedrion::{ecdsa::VerifyingKey as SynedrionVerifyingKey, DeriveChildKey};

            let signature_request_account = ensure_signed(origin)?;

            ensure!(
                signature_request_account.encode() != NETWORK_PARENT_KEY.encode(),
                Error::<T>::NoRegisteringFromParentKey
            );

            let num_programs = programs_data.len();
            ensure!(num_programs != 0, Error::<T>::NoProgramSet);

            // Change program ref counter
            for program_instance in &programs_data {
                pallet_programs::Programs::<T>::try_mutate(
                    program_instance.program_pointer,
                    |maybe_program_info| {
                        if let Some(program_info) = maybe_program_info {
                            program_info.ref_counter = program_info.ref_counter.saturating_add(1);
                            Ok(())
                        } else {
                            Err(Error::<T>::NoProgramSet)
                        }
                    },
                )?;
            }

            let network_verifying_key =
                if let Some(key) = <JumpStartProgress<T>>::get().verifying_key {
                    SynedrionVerifyingKey::try_from(key.as_slice())
                        .expect("The network verifying key must be valid.")
                } else {
                    return Err(Error::<T>::JumpStartNotCompleted.into());
                };

            // TODO (#984): For a `CountedStorageMap` there is the possibility that the counter
            // can decrease as storage entries are removed from the map. In our case we don't ever
            // remove entries from the `Registered` map so the counter should never
            // decrease. If it does we will end up with the same verifying key for different
            // accounts, which would be bad.
            //
            // For a V1 of this flow it's fine, but we'll need to think about a better solution
            // down the line.
            let count = Registered::<T>::count();
            let inner_path = scale_info::prelude::format!("m/0/{}", count);
            let path = bip32::DerivationPath::from_str(&inner_path)
                .map_err(|_| Error::<T>::InvalidBip32DerivationPath)?;
            let child_verifying_key = network_verifying_key
                .derive_verifying_key_bip32(&path)
                .map_err(|_| Error::<T>::Bip32AccountDerivationFailed)?;

            let child_verifying_key = BoundedVec::try_from(
                child_verifying_key.to_encoded_point(true).as_bytes().to_vec(),
            )
            .expect("Synedrion must have returned a valid verifying key.");

            Registered::<T>::insert(
                child_verifying_key.clone(),
                RegisteredInfo {
                    programs_data,
                    program_modification_account: program_modification_account.clone(),
                    derivation_path: Some(inner_path.encode()),
                    version_number: T::KeyVersionNumber::get(),
                },
            );

            ModifiableKeys::<T>::try_mutate(
                program_modification_account,
                |verifying_keys| -> Result<(), DispatchError> {
                    verifying_keys
                        .try_push(child_verifying_key.clone())
                        .map_err(|_| Error::<T>::TooManyModifiableKeys)?;
                    Ok(())
                },
            )?;

            Self::deposit_event(Event::AccountRegistered(
                signature_request_account,
                child_verifying_key,
            ));

            Ok(Some(<T as Config>::WeightInfo::register(num_programs as u32)).into())
        }

        /// Allows a user's program modification account to change their program pointer
        #[pallet::call_index(3)]
        #[pallet::weight({
             <T as Config>::WeightInfo::change_program_instance(
                 <T as Config>::MaxProgramHashes::get(),
                 <T as Config>::MaxProgramHashes::get()
             )
         })]
        pub fn change_program_instance(
            origin: OriginFor<T>,
            verifying_key: VerifyingKey,
            new_program_instance: BoundedVec<ProgramInstance<T>, T::MaxProgramHashes>,
        ) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;
            ensure!(!new_program_instance.is_empty(), Error::<T>::NoProgramSet);
            // change program ref counter
            for program_instance in &new_program_instance {
                pallet_programs::Programs::<T>::try_mutate(
                    program_instance.program_pointer,
                    |maybe_program_info| {
                        if let Some(program_info) = maybe_program_info {
                            program_info.ref_counter = program_info.ref_counter.saturating_add(1);
                            Ok(())
                        } else {
                            Err(Error::<T>::NoProgramSet)
                        }
                    },
                )?;
            }

            let mut old_programs_length = 0;
            let programs_data =
                Registered::<T>::try_mutate(&verifying_key, |maybe_registered_details| {
                    if let Some(registered_details) = maybe_registered_details {
                        ensure!(
                            who == registered_details.program_modification_account,
                            Error::<T>::NotAuthorized
                        );
                        // decrement ref counter of not used programs
                        for program_instance in &registered_details.programs_data {
                            pallet_programs::Programs::<T>::mutate(
                                program_instance.program_pointer,
                                |maybe_program_info| {
                                    if let Some(program_info) = maybe_program_info {
                                        program_info.ref_counter =
                                            program_info.ref_counter.saturating_sub(1);
                                    }
                                },
                            );
                        }
                        old_programs_length = registered_details.programs_data.len();
                        registered_details.programs_data = new_program_instance.clone();
                        Ok(new_program_instance)
                    } else {
                        Err(Error::<T>::NotRegistered)
                    }
                })?;

            Self::deposit_event(Event::ProgramInfoChanged(who, programs_data.clone()));

            Ok(Some(<T as Config>::WeightInfo::change_program_instance(
                programs_data.len() as u32,
                old_programs_length as u32,
            ))
            .into())
        }

        /// Allows a user's program modification account to change itself.
        #[pallet::call_index(4)]
        #[pallet::weight({
                 <T as Config>::WeightInfo::change_program_modification_account(MAX_MODIFIABLE_KEYS)
             })]
        pub fn change_program_modification_account(
            origin: OriginFor<T>,
            verifying_key: VerifyingKey,
            new_program_mod_account: T::AccountId,
        ) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;

            Registered::<T>::try_mutate(&verifying_key, |maybe_registered_details| {
                if let Some(registered_details) = maybe_registered_details {
                    ensure!(
                        who == registered_details.program_modification_account,
                        Error::<T>::NotAuthorized
                    );
                    registered_details.program_modification_account =
                        new_program_mod_account.clone();
                    Ok(())
                } else {
                    Err(Error::<T>::NotRegistered)
                }
            })?;

            let mut verifying_keys_len = 0;
            ModifiableKeys::<T>::try_mutate(&who, |verifying_keys| -> Result<(), DispatchError> {
                verifying_keys_len = verifying_keys.len();
                let pos = verifying_keys
                    .iter()
                    .position(|k| *k == verifying_key)
                    .ok_or(Error::<T>::NotAuthorized)?;
                verifying_keys.remove(pos);
                Ok(())
            })?;

            ModifiableKeys::<T>::try_mutate(
                &new_program_mod_account,
                |verifying_keys| -> Result<(), DispatchError> {
                    verifying_keys
                        .try_push(verifying_key.clone())
                        .map_err(|_| Error::<T>::TooManyModifiableKeys)?;
                    Ok(())
                },
            )?;

            Self::deposit_event(Event::ProgramModificationAccountChanged(
                who,
                new_program_mod_account,
                verifying_key,
            ));

            Ok(Some(<T as Config>::WeightInfo::change_program_modification_account(
                verifying_keys_len as u32,
            ))
            .into())
        }
    }

    impl<T: Config> Pallet<T> {
        #[allow(clippy::type_complexity)]
        pub fn get_validators_info() -> Result<Vec<ServerInfo<T::AccountId>>, Error<T>> {
            let mut validators_info: Vec<ServerInfo<T::AccountId>> = vec![];
            let validators = pallet_session::Pallet::<T>::validators();

            for validator_address in validators {
                let validator_info =
                    pallet_staking_extension::Pallet::<T>::threshold_server(&validator_address)
                        .ok_or(Error::<T>::IpAddressError)?;
                validators_info.push(validator_info);
            }

            Ok(validators_info)
        }
    }
}
