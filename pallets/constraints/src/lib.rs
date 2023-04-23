//! # Constraint Pallet
//!
//! ## Overview
//!
//! Holds the onchain constraints for users
//!
//!
//! ### Public Functions
//!
//! update_constraints - lets a user update their constraints

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
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::sp_std::str;

    pub use crate::weights::WeightInfo;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type WeightInfo: WeightInfo;
        type MaxAclLength: Get<u32>;
        type MaxV2Constraint: Get<u32>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
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

    /// 2-ary set associating a signature-request account to the architectures it has active
    /// constraints on.
    #[pallet::storage]
    #[pallet::getter(fn active_constraints_by_arch)]
    pub type ActiveArchitectures<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        Arch,
        (),
        ResultQuery<Error<T>::ArchitectureDisabled>,
    >;

    /// Stores the EVM ACL of each user
    #[pallet::storage]
    #[pallet::getter(fn evm_acl)]
    pub type EvmAcl<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Acl<[u8; 20]>,
        ResultQuery<Error<T>::ArchitectureDisabled>,
    >;

    /// Stores the BTC ACL of each user
    #[pallet::storage]
    #[pallet::getter(fn btc_acl)]
    pub type BtcAcl<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Acl<[u8; 32]>,
        ResultQuery<Error<T>::ArchitectureDisabled>,
    >;

    /// Stores V2 storage blob
    #[pallet::storage]
    #[pallet::getter(fn v2_storage)]
    pub type V2Storage<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, Vec<u8>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// All new constraints. [constraint_account, constraints]
        ConstraintsUpdated(T::AccountId, Constraints),
        /// All new V2 constraints. [constraint_account, constraints]
        ConstraintsV2Updated(T::AccountId, Vec<u8>),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Constraint account doesn't have permission to modify these constraints
        NotAuthorized,
        /// User has disabled signing for this architecture
        ArchitectureDisabled,
        /// ACL is too long, make it smaller
        AclLengthExceeded,
        /// V2 constraint length is too long
        V2ConstraintLengthExceeded,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Sets or clears the constraints for a given signature-request account.
        /// If the members of `new_constraints` are `None`, those constraints will be removed.
        /// Must be sent from a constraint-modification account.
        /// TODO update weights
        #[pallet::weight({
            let (evm_acl_len, btc_acl_len) = Pallet::<T>::constraint_weight_values(new_constraints);
            <T as Config>::WeightInfo::update_constraints(evm_acl_len, btc_acl_len)
        })]
        pub fn update_constraints(
            origin: OriginFor<T>,
            sig_req_account: T::AccountId,
            new_constraints: Constraints,
        ) -> DispatchResult {
            let constraint_account = ensure_signed(origin)?;

            ensure!(
                AllowedToModifyConstraints::<T>::contains_key(
                    &constraint_account,
                    &sig_req_account
                ),
                Error::<T>::NotAuthorized
            );

            Self::validate_constraints(&new_constraints)?;
            Self::set_constraints_unchecked(&sig_req_account, &new_constraints);

            Self::deposit_event(Event::ConstraintsUpdated(sig_req_account, new_constraints));

            Ok(())
        }

        #[pallet::weight({<T as Config>::WeightInfo::update_v2_constraints()})]
        pub fn update_v2_constraints(
            origin: OriginFor<T>,
            sig_req_account: T::AccountId,
            new_constraints: Vec<u8>,
        ) -> DispatchResult {
            let constraint_account = ensure_signed(origin)?;

            ensure!(
                new_constraints.len() as u32 <= T::MaxV2Constraint::get(),
                Error::<T>::V2ConstraintLengthExceeded
            );

            ensure!(
                AllowedToModifyConstraints::<T>::contains_key(
                    &constraint_account,
                    &sig_req_account
                ),
                Error::<T>::NotAuthorized
            );
            // TODO: 1 milicent per byte charge

            V2Storage::<T>::insert(&sig_req_account, &new_constraints);
            Self::deposit_event(Event::ConstraintsV2Updated(sig_req_account, new_constraints));
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Sets the constraints for a given signature-request account without validating the
        /// constraints (eg ACL length checks, etc.)
        pub fn set_constraints_unchecked(
            sig_req_account: &T::AccountId,
            constraints: &Constraints,
        ) {
            let Constraints { evm_acl, btc_acl } = constraints;

            match evm_acl {
                Some(acl) => {
                    EvmAcl::<T>::insert(sig_req_account.clone(), acl);
                    ActiveArchitectures::<T>::insert(sig_req_account.clone(), Arch::Evm, ());
                },
                None => {
                    ActiveArchitectures::<T>::remove(sig_req_account.clone(), Arch::Evm);
                    EvmAcl::<T>::remove(sig_req_account.clone());
                },
            }
            match btc_acl {
                Some(acl) => {
                    BtcAcl::<T>::insert(sig_req_account.clone(), acl);
                    ActiveArchitectures::<T>::insert(sig_req_account, Arch::Btc, ());
                },
                None => {
                    ActiveArchitectures::<T>::remove(sig_req_account.clone(), Arch::Btc);
                    BtcAcl::<T>::remove(sig_req_account);
                },
            }
        }

        /// Validates constraints before they are stored anywhere as a set of valid constraints
        pub fn validate_constraints(constraints: &Constraints) -> Result<(), Error<T>> {
            let Constraints { evm_acl, btc_acl } = constraints;

            Self::validate_acl(evm_acl)?;
            Self::validate_acl(btc_acl)?;

            Ok(())
        }

        /// Validates an ACL before it is stored anywhere as a valid constraint
        fn validate_acl<A>(acl: &Option<Acl<A>>) -> Result<(), Error<T>> {
            if let Some(acl) = acl {
                ensure!(
                    acl.addresses.len() as u32 <= T::MaxAclLength::get(),
                    Error::<T>::AclLengthExceeded
                );
            }

            Ok(())
        }

        /// Returns information about Constraints that can be used to calculate weights.
        /// Used as values in some `#[pallet::weight]` macros.
        pub fn constraint_weight_values(constraints: &Constraints) -> (u32, u32) {
            let Constraints { evm_acl, btc_acl } = constraints;

            let mut evm_acl_len: u32 = 0;
            if let Some(acl) = evm_acl {
                evm_acl_len += acl.addresses.len() as u32;
            }
            let mut btc_acl_len: u32 = 0;
            if let Some(acl) = btc_acl {
                btc_acl_len += acl.addresses.len() as u32;
            }

            (evm_acl_len, btc_acl_len)
        }
    }
}
