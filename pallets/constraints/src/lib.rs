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
	use frame_support::{
		dispatch::{DispatchResult, DispatchResultWithPostInfo},
		inherent::Vec,
		pallet_prelude::*,
	};
	use frame_system::pallet_prelude::*;
	use sp_runtime::sp_std::str;

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		type MaxWhitelist: Get<u32>;
		type MaxAddressLength: Get<u32>;

		/// The weight information of this pallet.
		type WeightInfo: WeightInfo;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	#[pallet::getter(fn address_whitelist)]
	/// Mapping of whitelisted addresses
	pub type AddressWhitelist<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, Vec<Vec<u8>>, ValueQuery>;

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
		#[pallet::weight((T::WeightInfo::add_whitelist_address(T::MaxWhitelist::get() as u32), Pays::No))]
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
					if addresses.into_iter().any(|address| {
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
