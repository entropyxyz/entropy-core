//! # Constraints Pallet
//!
//! ## Overview
//!
//! This pallet stores the WebAssembly (Wasm) program bytecode on-chain and allows users to change
//! it as required.
//!
//! A program is a piece of logic which is run by the network when a signing operation is requested.
//! The succesful execution of a program indicates to validators on the network that they should
//! sign a given message.
//!
//! Programs are initially registered through the Relayer pallet's `register` extrinsic.
//!
//! ## Interface
//!
//! ### Dispatchable Functions
//!
//! #### Public
//!
//! `update_program` - Allows a program-modification account to change the program associated with
//! a particular signature-request account.

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
        inherent::Vec,
        pallet_prelude::{ResultQuery, *},
        traits::{Currency, ReservableCurrency},
    };
    use frame_system::{pallet_prelude::*, Config as SystemConfig};
    use sp_runtime::{sp_std::str, Saturating};
    use sp_std::vec;

    pub use crate::weights::WeightInfo;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Describes the weights of the dispatchables exposed by this pallet.
        type WeightInfo: WeightInfo;

        /// The maximum length of a program that may be stored on-chain.
        type MaxBytecodeLength: Get<u32>;

        /// The amount to charge, per byte, for storing a program on-chain.
        type ProgramDepositPerByte: Get<BalanceOf<Self>>;

        /// The currency mechanism, used to take storage deposits for example.
        type Currency: ReservableCurrency<Self::AccountId>;
    }

    type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as SystemConfig>::AccountId>>::Balance;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// A mapping for checking whether a program-modification account is allowed to update a
    /// program on behalf of a signature-request account.
    ///
    /// If the program-modification account and signature-request account pair is found in storage
    /// then program modification is allowed.
    #[pallet::storage]
    #[pallet::getter(fn sig_req_accounts)]
    pub type AllowedToModifyProgram<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId, // Program-modification account
        Blake2_128Concat,
        T::AccountId, // Signature-request account
        (),
        ResultQuery<Error<T>::NotAuthorized>,
    >;

    /// Stores the program bytecode for a given signature-request account.
    #[pallet::storage]
    #[pallet::getter(fn bytecode)]
    pub type Bytecode<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, Vec<u8>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// The bytecode of a program was updated.
        ProgramUpdated {
            /// The program modification account which updated the program.
            program_modification_account: T::AccountId,

            /// The new program bytecode.
            new_program: Vec<u8>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Program modification account doesn't have permission to modify this program.
        NotAuthorized,

        /// The program length is too long.
        ProgramLengthExceeded,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Sets or clears the program for a given signature-request account.
        ///
        /// Note that the call must be sent from a program-modification account.
        #[pallet::call_index(0)]
        #[pallet::weight({<T as Config>::WeightInfo::update_program()})]
        pub fn update_program(
            origin: OriginFor<T>,
            sig_req_account: T::AccountId,
            new_program: Vec<u8>,
        ) -> DispatchResult {
            let program_modification_account = ensure_signed(origin)?;
            let new_program_length = new_program.len();
            ensure!(
                new_program_length as u32 <= T::MaxBytecodeLength::get(),
                Error::<T>::ProgramLengthExceeded
            );

            ensure!(
                AllowedToModifyProgram::<T>::contains_key(
                    &program_modification_account,
                    &sig_req_account
                ),
                Error::<T>::NotAuthorized
            );
            let old_program_length = Self::bytecode(&sig_req_account).unwrap_or_default().len();

            Self::update_program_storage_deposit(
                &program_modification_account,
                old_program_length,
                new_program_length,
            )?;

            Bytecode::<T>::insert(&sig_req_account, &new_program);
            Self::deposit_event(Event::ProgramUpdated {
                program_modification_account,
                new_program,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Write a program for a given signature-request account directly into storage.
        ///
        /// # Note
        ///
        /// This does not perform any checks against the submitter of the request and whether or
        /// not they are allowed to update a program for the given account.
        pub fn set_program_unchecked(
            sig_req_account: &T::AccountId,
            program: Vec<u8>,
        ) -> Result<(), Error<T>> {
            ensure!(
                program.len() as u32 <= T::MaxBytecodeLength::get(),
                Error::<T>::ProgramLengthExceeded
            );

            Bytecode::<T>::insert(sig_req_account, program);

            Ok(())
        }

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
