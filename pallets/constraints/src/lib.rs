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
//! `update_constraints` - Allows a user to either add or remove a set of constraints for a
//! particular signature-request account.

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

    pub use entropy_shared::{Acl, AclKind, Arch, Constraints};
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
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type WeightInfo: WeightInfo;
        type MaxAclLength: Get<u32>;
        type MaxBytecodeLength: Get<u32>;
        type ConstraintsDepositPerByte: Get<BalanceOf<Self>>;
        /// The currency mechanism.
        type Currency: ReservableCurrency<Self::AccountId>;
    }

    type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as SystemConfig>::AccountId>>::Balance;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// If the constraint-modification `AccountId` and signature-request `AccountId` tuple as a key
    /// exists, then the constraint-modification `AccountId` is authorized to modify the
    /// constraints for this account
    #[pallet::storage]
    #[pallet::getter(fn sig_req_accounts)]
    pub type AllowedToModifyConstraints<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        T::AccountId,
        (),
        ResultQuery<Error<T>::NotAuthorized>,
    >;

    /// Stores the set of constraints for a given account.
    #[pallet::storage]
    #[pallet::getter(fn bytecode)]
    pub type Bytecode<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, Vec<u8>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// All new constraints. [constraint_account, constraints]
        ConstraintsUpdated(T::AccountId, Vec<u8>),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Constraint account doesn't have permission to modify these constraints
        NotAuthorized,
        /// Constraint length is too long
        ConstraintLengthExceeded,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Sets or clears the constraints for a given signature-request account.
        ///
        /// Note that the call must be sent from a constraint-modification account.
        #[pallet::call_index(0)]
        #[pallet::weight({<T as Config>::WeightInfo::update_constraints()})]
        pub fn update_constraints(
            origin: OriginFor<T>,
            sig_req_account: T::AccountId,
            new_constraints: Vec<u8>,
        ) -> DispatchResult {
            let constraint_account = ensure_signed(origin)?;
            let new_constraints_length = new_constraints.len();
            ensure!(
                new_constraints_length as u32 <= T::MaxBytecodeLength::get(),
                Error::<T>::ConstraintLengthExceeded
            );

            ensure!(
                AllowedToModifyConstraints::<T>::contains_key(
                    &constraint_account,
                    &sig_req_account
                ),
                Error::<T>::NotAuthorized
            );
            let old_constraints_length = Self::bytecode(&sig_req_account).unwrap_or_default().len();

            Self::update_program_storage_deposit(
                &constraint_account,
                old_constraints_length,
                new_constraints_length,
            )?;

            Bytecode::<T>::insert(&sig_req_account, &new_constraints);
            Self::deposit_event(Event::ConstraintsUpdated(sig_req_account, new_constraints));
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
                Error::<T>::ConstraintLengthExceeded
            );

            Bytecode::<T>::insert(sig_req_account, program);

            Ok(())
        }

        /// Sets the constraints for a given signature-request account without validating the
        /// constraints (eg ACL length checks, etc.)
        pub fn set_constraints_unchecked(
            _sig_req_account: &T::AccountId,
            _constraints: &Constraints,
        ) {
            todo!("Jake, do we need this anymore?")
        }

        /// Validates constraints before they are stored anywhere as a set of valid constraints
        pub fn validate_constraints(_constraints: &Constraints) -> Result<(), Error<T>> {
            todo!("Jake, do we need this anymore?")
        }

        /// Validates an ACL before it is stored anywhere as a valid constraint
        fn _validate_acl<A>(_acl: &Option<Acl<A>>) -> Result<(), Error<T>> {
            todo!("Jake, do we need this anymore?")
        }

        /// Returns information about Constraints that can be used to calculate weights.
        /// Used as values in some `#[pallet::weight]` macros.
        pub fn constraint_weight_values(_constraints: &Constraints) -> (u32, u32) {
            todo!("Jake, do we need this anymore?")
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
                T::ConstraintsDepositPerByte::get().saturating_mul((program_len as u32).into());

            T::Currency::reserve(from, deposit)
        }

        /// Returns a storage deposit placed by [`Self::reserve_program_deposit`].
        pub fn unreserve_program_deposit(from: &T::AccountId, program_len: usize) -> BalanceOf<T> {
            let deposit =
                T::ConstraintsDepositPerByte::get().saturating_mul((program_len as u32).into());

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
