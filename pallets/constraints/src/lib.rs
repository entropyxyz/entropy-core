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
    pub trait Config: frame_system::Config + pallet_relayer::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type MaxWhitelist: Get<u32>;
        type MaxAddressLength: Get<u32>;

        /// The weight information of this pallet.
        type WeightInfo: WeightInfo;

        #[pallet::constant]
        type MaxAclLength: Get<u32> + Debug;
    }

    /// Represents an ACL allow/deny list; takes list of (platform-id, address) hashes
    #[derive(
        CloneNoBound, Debug, Encode, Decode, PartialEq, Eq, scale_info::TypeInfo, MaxEncodedLen,
    )]
    // #[scale_info(skip_type_params(T))]
    // #[codec(mel_bound())]
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
    /// Maps AccountIds that can modify constraints to the accounts they're allowed to modify the constraints of.
    pub type SigReqAccounts<T: Config> =
        StorageDoubleMap<_, Blake2_128Concat, T::AccountId, Blake2_128Concat, T::AccountId, ()>;

    /// Stores the ACL of each user for every architecture. Maps signature-request AccountId and the platform in question to their constraints
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
        /// Set the ACL for a given user and architecture
        #[pallet::weight((<T as Config>::WeightInfo::add_whitelist_address(T::MaxWhitelist::get()), Pays::No))]
        pub fn set_acl(
            origin: OriginFor<T>,
            sig_req_account: T::AccountId,
            arch: Arch,
            acl: Acl,
        ) -> DispatchResultWithPostInfo {
            let constraint_account = ensure_signed(origin)?;
            // ensure registered
            ensure!(
                pallet_relayer::Pallet::<T>::registered(&constraint_account).is_some(),
                Error::<T>::NotRegistered
            );
            // make sure constraint account has permission to modify constraints
            ensure!(
                SigReqAccounts::<T>::contains_key(&constraint_account, &sig_req_account),
                Error::<T>::NotAuthorized
            );
            // make sure the acl length is not too long
            let acl_length = match acl.clone() {
                Acl::Allow(acl) => acl.len() as u32,
                Acl::Deny(acl) => acl.len() as u32,
            };
            ensure!(acl_length <= T::MaxAclLength::get(), Error::<T>::MaxWhitelist);

            // insert them into storage
            AclAddresses::<T>::set(sig_req_account.clone(), arch, Some(acl.clone()));

            Self::deposit_event(Event::AclUpdated(constraint_account, arch));
            Ok(Some(<T as Config>::WeightInfo::add_whitelist_address(acl_length)).into())
        }
    }
}
