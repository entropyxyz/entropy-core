#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// <https://substrate.dev/docs/en/knowledgebase/runtime/frame>
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[frame_support::pallet]
pub mod pallet {
	use frame_support::{dispatch::DispatchResult, inherent::Vec, pallet_prelude::*};
	use frame_system::pallet_prelude::*;
	use sp_runtime::sp_std::str;
	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

		type MaxWhitelist: Get<u32>;
		type MaxAddressLength: Get<u32>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	// #[pallet::hooks]
	// impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::storage]
	#[pallet::getter(fn address_whitelist)]
	/// Mapping of whitelisted addresses
	pub type AddressWhitelist<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, Vec<Vec<u8>>, ValueQuery>;

	// Pallets use events to inform users when important changes are made.
	// https://substrate.dev/docs/en/knowledgebase/runtime/events
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// All whitelisted addresses in call. [who, whitelisted_addresses]
		AddressesWhitelisted(T::AccountId, Vec<Vec<u8>>),
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		/// Error names should be descriptive.
		NoneValue,
		/// Errors should have helpful documentation associated with them.
		StorageOverflow,
		MaxWhitelist,
		AlreadyWhitelisted,
		AddressTooLong,
	}

	// Dispatchable functions allows users to interact with the pallet and invoke state changes.
	// These functions materialize as "extrinsics", which are often compared to transactions.
	// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight((10_000 + T::DbWeight::get().writes(1), Pays::No))]
		pub fn add_whitelist_address(
			origin: OriginFor<T>,
			whitelist_addresses: Vec<Vec<u8>>,
		) -> DispatchResult {
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
			let _whitelist_length = AddressWhitelist::<T>::try_mutate(
				who.clone(),
				|addresses| -> Result<usize, DispatchError> {
					if (addresses.len() as u32 + whitelist_addresses.len() as u32) >
						T::MaxWhitelist::get()
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
			Ok(())
		}
	}
}
