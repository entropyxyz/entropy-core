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

    use frame_support::{
        dispatch::DispatchResultWithPostInfo, inherent::Vec, pallet_prelude::*, BoundedVec,
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::sp_std::str;
    use substrate_common::types::Arch;

    pub use crate::weights::WeightInfo;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type MaxWhitelist: Get<u32>;
        type MaxAddressLength: Get<u32>;

        /// The weight information of this pallet.
        type WeightInfo: WeightInfo;

        #[pallet::constant]
        type MaxAclLength: Get<u32>;
    }

    /// Represents an ACL allow/deny list; takes list of (platform-id, address) hashes
    #[derive(Clone, RuntimeDebug, Encode, Decode, scale_info::TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub enum Acl<T: Config> {
        Allow(BoundedVec<[u8; 32], T::MaxAclLength>),
        Deny(BoundedVec<[u8; 32], T::MaxAclLength>),
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
        StorageDoubleMap<_, Blake2_128Concat, T::AccountId, Blake2_128Concat, Arch, Acl<T>>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// All whitelisted addresses in call. [who, whitelisted_addresses]
        AddressesWhitelisted(T::AccountId, Vec<Vec<u8>>),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Max amount of whitelisted addresses reached.
        MaxWhitelist,
        /// Address already whitelisted.
        AlreadyWhitelisted,
        /// Address to whitelist is too long.
        AddressTooLong,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Adds an address to be whitelisted
        /// - `whitelist_addresses`: Addresses to be whitelisted
        #[pallet::weight((T::WeightInfo::add_whitelist_address(T::MaxWhitelist::get()), Pays::No))]
        pub fn add_whitelist_address(
            origin: OriginFor<T>,
            whitelist_addresses: Vec<Vec<u8>>,
        ) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;
            // TODO ensure registered
            if whitelist_addresses
                .clone()
                .into_iter()
                .any(|address| address.len() as u32 > T::MaxAddressLength::get())
            {
                Err(Error::<T>::AddressTooLong)?
            }
            ensure!(
                whitelist_addresses.len() as u32 <= T::MaxWhitelist::get(),
                Error::<T>::MaxWhitelist
            );
            let whitelist_length = AddressWhitelist::<T>::try_mutate(
                who.clone(),
                |addresses| -> Result<usize, DispatchError> {
                    if (addresses.len() as u32 + whitelist_addresses.len() as u32)
                        > T::MaxWhitelist::get()
                    {
                        Err(Error::<T>::MaxWhitelist)?
                    }
                    if addresses.iter().any(|address| {
                        whitelist_addresses
                            .clone()
                            .into_iter()
                            .any(|address_to_whitelist| *address == address_to_whitelist)
                    }) {
                        Err(Error::<T>::AlreadyWhitelisted)?
                    }
                    addresses.extend(whitelist_addresses.clone().into_iter().collect::<Vec<_>>());
                    Ok(addresses.len())
                },
            )?;
            Self::deposit_event(Event::AddressesWhitelisted(who, whitelist_addresses));
            Ok(Some(T::WeightInfo::add_whitelist_address(whitelist_length as u32)).into())
        }
    }
}
