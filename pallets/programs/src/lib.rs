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

//! # Programs Pallet
//!
//! ## Overview
//!
//! This pallet stores the WebAssembly (Wasm) program bytecode on-chain at the hash of the program code and interface
//!
//! A program is a piece of logic which is run by the network when a signing operation is requested.
//! The succesful execution of a program indicates to validators on the network that they should
//! sign a given message.
//!
//! Programs are initially registered through the Registry pallet's `register` extrinsic.
//!
//! ## Interface
//!
//! ### Dispatchable Functions
//!
//! #### Public
//!
//! `set_program` - Allows a deployer account to create a program.
//! `remove_program` - Allows a deployer to remove a program if not in use.

#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;

pub mod weights;

#[frame_support::pallet]
pub mod pallet {

    use frame_support::{
        pallet_prelude::*,
        traits::{Currency, ReservableCurrency},
    };
    use frame_system::{pallet_prelude::*, Config as SystemConfig};
    use sp_runtime::{sp_std::str, traits::Hash, Saturating};
    use sp_std::{vec, vec::Vec};

    pub use crate::weights::WeightInfo;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Describes the weights of the dispatchables exposed by this pallet.
        type WeightInfo: WeightInfo;

        /// The maximum length of a program that may be stored on-chain.
        type MaxBytecodeLength: Get<u32>;

        /// The maximum amount of owned programs.
        type MaxOwnedPrograms: Get<u32>;

        /// The amount to charge, per byte, for storing a program on-chain.
        type ProgramDepositPerByte: Get<BalanceOf<Self>>;

        /// The currency mechanism, used to take storage deposits for example.
        type Currency: ReservableCurrency<Self::AccountId>;
    }

    type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as SystemConfig>::AccountId>>::Balance;

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        #[allow(clippy::type_complexity)]
        pub inital_programs: Vec<(T::Hash, Vec<u8>, Vec<u8>, T::AccountId, u128)>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            for program_info in &self.inital_programs {
                assert!(
                    program_info.1.clone().len() as u32 + program_info.2.clone().len() as u32
                        <= T::MaxBytecodeLength::get(),
                    "bytecode and config data too long"
                );
                Programs::<T>::insert(
                    program_info.0,
                    ProgramInfo {
                        bytecode: program_info.1.clone(),
                        interface_description: program_info.2.clone(),
                        deployer: program_info.3.clone(),
                        ref_counter: program_info.4,
                    },
                );
            }
        }
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Information on the program
    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
    pub struct ProgramInfo<AccountId> {
        /// The bytecode of the program.
        pub bytecode: Vec<u8>,
        /// The schema for the Program's configuration parameters.
        ///
        /// While this isn't strictly enforced, it is recommended to follow something like
        /// [JSON Schema](https://json-schema.org/) in order to simplify the life of off-chain
        /// actors.
        pub configuration_schema: Vec<u8>,
        /// The schema for the Program's auxiliary data.
        ///
        /// While this isn't strictly enforced, it is recommended to follow something like
        /// [JSON Schema](https://json-schema.org/) in order to simplify the life of off-chain
        /// actors.
        pub auxiliary_data_schema: Vec<u8>,
        /// Deployer of the program
        pub deployer: AccountId,
        /// Accounts that use this program
        pub ref_counter: u128,
    }

    /// Stores the program info for a given program hash.
    /// A program hash is a combination of the bytecode and configuration_schema and auxiliary_data_schema
    #[pallet::storage]
    #[pallet::getter(fn programs)]
    pub type Programs<T: Config> =
        StorageMap<_, Blake2_128Concat, T::Hash, ProgramInfo<T::AccountId>, OptionQuery>;

    /// Maps an account to all the programs it owns
    #[pallet::storage]
    #[pallet::getter(fn owned_programs)]
    pub type OwnedPrograms<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<T::Hash, T::MaxOwnedPrograms>,
        ValueQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// The bytecode of a program was created.
        ProgramCreated {
            /// The deployer account which created the program.
            deployer: T::AccountId,

            /// The new program hash.
            program_hash: T::Hash,

            /// The new program configuration schema.
            configuration_schema: Vec<u8>,

            /// The new program auxiliary data schema.
            auxiliary_data_schema: Vec<u8>,
        },
        /// The bytecode of a program was removed.
        ProgramRemoved {
            /// The depoyer account which removed the program.
            deployer: T::AccountId,

            /// The hash of the removed program.
            old_program_hash: T::Hash,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Program modification account doesn't have permission to modify this program.
        NotAuthorized,
        /// The program length is too long.
        ProgramLengthExceeded,
        /// No program defined at hash.
        NoProgramDefined,
        /// Program already set at hash.
        ProgramAlreadySet,
        /// User owns too many programs.
        TooManyProgramsOwned,
        /// Program is being used by an account
        ProgramInUse,
        /// Arithmetic overflow error
        ArithmeticError,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Sets the program and uses hash of program config and aux description as key.
        ///
        /// Note that the caller becomes the deployer account.
        #[pallet::call_index(0)]
        #[pallet::weight({<T as Config>::WeightInfo::set_program()})]
        pub fn set_program(
            origin: OriginFor<T>,
            new_program: Vec<u8>,
            configuration_schema: Vec<u8>,
            auxiliary_data_schema: Vec<u8>,
        ) -> DispatchResult {
            let deployer = ensure_signed(origin)?;
            let mut hash_input = vec![];
            hash_input.extend(&new_program);
            hash_input.extend(&configuration_schema);
            hash_input.extend(&auxiliary_data_schema);
            let program_hash = T::Hashing::hash(&hash_input);
            let new_program_length = new_program
                .len()
                .checked_add(configuration_schema.len())
                .ok_or(Error::<T>::ArithmeticError)?
                .checked_add(auxiliary_data_schema.len())
                .ok_or(Error::<T>::ArithmeticError)?;
            ensure!(
                new_program_length as u32 <= T::MaxBytecodeLength::get(),
                Error::<T>::ProgramLengthExceeded
            );
            ensure!(!Programs::<T>::contains_key(program_hash), Error::<T>::ProgramAlreadySet);

            Self::reserve_program_deposit(&deployer, new_program_length)?;

            Programs::<T>::insert(
                program_hash,
                &ProgramInfo {
                    bytecode: new_program.clone(),
                    configuration_schema: configuration_schema.clone(),
                    auxiliary_data_schema: auxiliary_data_schema.clone(),
                    deployer: deployer.clone(),
                    ref_counter: 0u128,
                },
            );
            OwnedPrograms::<T>::try_mutate(
                &deployer,
                |owned_programs| -> Result<(), DispatchError> {
                    owned_programs
                        .try_push(program_hash)
                        .map_err(|_| Error::<T>::TooManyProgramsOwned)?;
                    Ok(())
                },
            )?;
            Self::deposit_event(Event::ProgramCreated {
                deployer,
                program_hash,
                configuration_schema,
                auxiliary_data_schema,
            });
            Ok(())
        }

        /// Removes a program at a specific hash
        ///
        /// Caller must be the deployer account for said program.
        #[pallet::call_index(1)]
        #[pallet::weight({<T as Config>::WeightInfo::remove_program( <T as Config>::MaxOwnedPrograms::get())})]
        pub fn remove_program(
            origin: OriginFor<T>,
            program_hash: T::Hash,
        ) -> DispatchResultWithPostInfo {
            let deployer = ensure_signed(origin)?;
            let old_program_info =
                Self::programs(program_hash).ok_or(Error::<T>::NoProgramDefined)?;
            ensure!(old_program_info.deployer == deployer, Error::<T>::NotAuthorized);
            ensure!(old_program_info.ref_counter == 0, Error::<T>::ProgramInUse);
            Self::unreserve_program_deposit(
                &old_program_info.deployer,
                old_program_info.bytecode.len()
                    + old_program_info.configuration_schema.len()
                    + old_program_info.auxiliary_data_schema.len(),
            );
            let mut owned_programs_length = 0;
            OwnedPrograms::<T>::try_mutate(
                &deployer,
                |owned_programs| -> Result<(), DispatchError> {
                    owned_programs_length = owned_programs.len();
                    let pos = owned_programs
                        .iter()
                        .position(|&h| h == program_hash)
                        .ok_or(Error::<T>::NotAuthorized)?;
                    owned_programs.remove(pos);
                    Ok(())
                },
            )?;
            Programs::<T>::remove(program_hash);
            Self::deposit_event(Event::ProgramRemoved { deployer, old_program_hash: program_hash });
            Ok(Some(<T as Config>::WeightInfo::remove_program(owned_programs_length as u32)).into())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Takes some balance from an account as a storage deposit based off the length of the
        /// program they wish to store on-chain.
        ///
        /// This helps prevent state bloat by ensuring that storage is paid for and encouraging that
        /// unused programs eventually get cleaned up.
        ///
        /// The deposit can be returned using the [`Self::unreserve_program_deposit`] function.
        pub fn reserve_program_deposit(from: &T::AccountId, program_len: usize) -> DispatchResult {
            let deposit =
                T::ProgramDepositPerByte::get().saturating_mul((program_len as u32).into());

            T::Currency::reserve(from, deposit)
        }

        /// Returns a storage deposit placed by [`Self::reserve_program_deposit`].
        pub fn unreserve_program_deposit(from: &T::AccountId, program_len: usize) -> BalanceOf<T> {
            let deposit =
                T::ProgramDepositPerByte::get().saturating_mul((program_len as u32).into());

            T::Currency::unreserve(from, deposit)
        }

        /// Updates the storage deposit associated with a particular program.
        ///
        /// This will either try and reserve a bigger deposit or return a deposit depending on the
        /// size of the updated program.
        pub fn update_program_storage_deposit(
            from: &T::AccountId,
            old_program_length: usize,
            new_program_length: usize,
        ) -> DispatchResult {
            if old_program_length > new_program_length {
                let len_diff = old_program_length - new_program_length;
                Self::unreserve_program_deposit(from, len_diff);
            }
            if new_program_length > old_program_length {
                let len_diff = new_program_length - old_program_length;
                Self::reserve_program_deposit(from, len_diff)?;
            }

            Ok(())
        }
    }
}
