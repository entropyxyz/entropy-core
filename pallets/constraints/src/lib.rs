//! # Constraint Pallet
//!
//! ## Overview
//!
//! Holds the onchain constraints for users
//!
//!
//! ### Public Functions
//!
//! add_whitelist_address - lets a user add a whitelisted address to their account

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

    pub use crate::weights::WeightInfo;
    use core::fmt::Debug;
    use frame_support::{
        dispatch::DispatchResultWithPostInfo, inherent::Vec, pallet_prelude::*, traits::ConstU32,
        BoundedVec,
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::sp_std::str;
    use substrate_common::types::Arch;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type MaxWhitelist: Get<u32>;
        type MaxAddressLength: Get<u32>;

        /// The weight information of this pallet.
        type WeightInfo: WeightInfo;

        #[pallet::constant]
        type MaxAclLength: Get<u32> + Debug;
    }

    /// Represents an ACL allow/deny list; takes list of (platform-id, address) hashes
    /// TODO make this size configurable, instead of a static `25` addresses
    #[derive(
        CloneNoBound, Debug, Encode, Decode, PartialEq, Eq, scale_info::TypeInfo, MaxEncodedLen,
    )]
    pub enum Acl {
        Allow(BoundedVec<[u8; 32], ConstU32<25>>),
        Deny(BoundedVec<[u8; 32], ConstU32<25>>),
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    // TODO Get rid of this
    #[pallet::storage]
    #[pallet::getter(fn address_whitelist)]
    /// Mapping of whitelisted addresses
    pub type AddressWhitelist<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, Vec<Vec<u8>>, ValueQuery>;

    #[pallet::storage]
    // #[pallet::getter(fn )]
    /// Maps constraint-modification `AccountId`s to the signature-request accounts they're allowed to modify the constraints of.
    pub type SigReqAccounts<T: Config> =
        StorageDoubleMap<_, Blake2_128Concat, T::AccountId, Blake2_128Concat, T::AccountId, ()>;

    /// Stores the ACL of each user for every architecture. Maps a signature-request AccountId and a platform to the platform-specific constraints
    #[pallet::storage]
    #[pallet::getter(fn acl)]
    pub type AclAddresses<T: Config> =
        StorageDoubleMap<_, Blake2_128Concat, T::AccountId, Blake2_128Concat, Arch, Acl>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// All whitelisted addresses in call. [who, whitelisted_addresses]
        AclUpdated(T::AccountId, Arch),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// ACL is too large.
        MaxWhitelist,
        /// Address already whitelisted.
        AlreadyWhitelisted,
        // TODO get rid of
        /// Address to whitelist is too long.
        AddressTooLong,
        /// Constraint account doesn't have permission to modify these constraionts
        NotAuthorized,
        /// Constraint account is not a registered account on the network
        NotRegistered,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Sets or clears the ACL for a given signature-request account and architecture.
        /// If `new_acl` is `None`, the ACL is cleared.
        /// Must be sent from a constraint-modification account.
        /// TODO update weights
        #[pallet::weight((<T as Config>::WeightInfo::add_whitelist_address(25), Pays::No))]
        pub fn update_acl(
            origin: OriginFor<T>,
            sig_req_account: T::AccountId,
            arch: Arch,
            new_acl: Option<Acl>,
        ) -> DispatchResultWithPostInfo {
            let constraint_account = ensure_signed(origin)?;

            // ensure registered and account has permission to modify constraints
            ensure!(
                SigReqAccounts::<T>::contains_key(&constraint_account, &sig_req_account),
                Error::<T>::NotAuthorized
            );

            // update the ACL, clearing it if `new_acl` is `None`
            AclAddresses::<T>::mutate_exists(sig_req_account.clone(), arch, |current_acl| {
                *current_acl = new_acl.clone();
            });

            Self::deposit_event(Event::AclUpdated(constraint_account, arch));

            // TODO new weight
            Ok(Some(<T as Config>::WeightInfo::add_whitelist_address(3)).into())
        }
    }
}
