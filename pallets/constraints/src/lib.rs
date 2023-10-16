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

            Self::charge_constraint_fee(
                constraint_account,
                old_constraints_length as u32,
                new_constraints_length as u32,
            )?;

            Bytecode::<T>::insert(&sig_req_account, &new_constraints);
            Self::deposit_event(Event::ConstraintsUpdated(sig_req_account, new_constraints));
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
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

        pub fn charge_constraint_fee(
            from: T::AccountId,
            old_constraints_length: u32,
            new_constraints_length: u32,
        ) -> DispatchResult {
            if old_constraints_length > new_constraints_length {
                let charge = T::ConstraintsDepositPerByte::get()
                    .saturating_mul((old_constraints_length - new_constraints_length).into());
                T::Currency::unreserve(&from, charge);
            }
            if new_constraints_length > old_constraints_length {
                let charge = T::ConstraintsDepositPerByte::get()
                    .saturating_mul((new_constraints_length - old_constraints_length).into());
                T::Currency::reserve(&from, charge)?;
            }
            Ok(())
        }
    }
}
