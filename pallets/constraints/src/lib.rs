//! # Constraint Pallet
//!
//! ## Overview
//!
//! Holds the onchain constraints for users
//!
//!
//! ### Public Functions
//!
//! update_acl - lets a user update their acl

#![cfg_attr(not(feature = "std"), no_std)]
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

    use frame_support::{
        dispatch::DispatchResultWithPostInfo,
        pallet_prelude::{ResultQuery, *},
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::sp_std::str;
    pub use substrate_common::{Acl, AclKind, Arch, H160};

    pub use crate::weights::WeightInfo;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// The weight information of this pallet.
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn sig_req_accounts)]
    /// Maps constraint-modification `AccountId`s to the signature-request accounts they're allowed
    /// to modify the constraints of.
    pub type SigReqAccounts<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        T::AccountId,
        (),
        ResultQuery<Error<T>::NotAuthorized>,
    >;

    /// Stores the ACL of each user for every architecture. Maps a signature-request AccountId and a
    /// platform to the platform-specific constraints
    #[pallet::storage]
    #[pallet::getter(fn acl)]
    pub type AclAddresses<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        Arch,
        Acl<H160>,
        ResultQuery<Error<T>::AccountDoesNotExist>,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// All whitelisted addresses in call. [constraint_account, arch]
        AclUpdated(T::AccountId, Arch),
    }

    #[derive(PartialEq, Eq)]
    #[pallet::error]
    pub enum Error<T> {
        /// TODO ACL is too large
        AclTooLarge,
        /// Constraint account doesn't have permission to modify these constraionts
        NotAuthorized,
        /// Threshold account has never had constraints set
        AccountDoesNotExist,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Sets or clears the ACL for a given signature-request account and architecture.
        /// If `new_acl` is `None`, the ACL is cleared.
        /// Must be sent from a constraint-modification account.
        /// TODO update weights
        #[pallet::weight((<T as Config>::WeightInfo::update_acl(25), Pays::No))]
        pub fn update_acl(
            origin: OriginFor<T>,
            sig_req_account: T::AccountId,
            arch: Arch,
            new_acl: Option<Acl<H160>>,
        ) -> DispatchResultWithPostInfo {
            let constraint_account = ensure_signed(origin)?;

            // ensure registered and account has permission to modify constraints
            ensure!(
                SigReqAccounts::<T>::contains_key(&constraint_account, &sig_req_account),
                Error::<T>::NotAuthorized
            );

            // update the ACL, clearing it if `new_acl` is `None`
            match new_acl {
                Some(acl) => {
                    AclAddresses::<T>::insert(sig_req_account.clone(), arch, acl);
                },
                None => {
                    AclAddresses::<T>::remove(sig_req_account.clone(), arch);
                },
            }

            Self::deposit_event(Event::AclUpdated(constraint_account, arch));

            // TODO new weight
            Ok(Some(<T as Config>::WeightInfo::update_acl(3)).into())
        }
    }
}
