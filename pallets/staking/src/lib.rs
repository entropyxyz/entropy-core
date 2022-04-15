#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[frame_support::pallet]
pub mod pallet {
	use core::convert::TryInto;
	use frame_support::{
		dispatch::DispatchResult, inherent::Vec, pallet_prelude::*, traits::Currency,
	};
	use frame_system::pallet_prelude::*;
	use pallet_staking::ValidatorPrefs;

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_staking::Config {
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		type Currency: Currency<Self::AccountId>;
		type MaxEndpointLength: Get<u32>;
	}
	// TODO: JA add build for initial endpoints

	/// The balance type of this pallet.
	pub type BalanceOf<T> = <<T as pallet_staking::Config>::Currency as Currency<
		<T as frame_system::Config>::AccountId,
	>>::Balance;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	#[pallet::getter(fn endpoint_register)]
	pub type EndpointRegister<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, Vec<u8>, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn threshold_account)]
	pub type ThresholdAccounts<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, T::AccountId, OptionQuery>;

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub endpoints: Vec<(T::AccountId, Vec<u8>)>,
		pub threshold_accounts: Vec<(T::AccountId, T::AccountId)>
	}

	#[cfg(feature = "std")]
	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			Self { endpoints: Default::default(), threshold_accounts: Default::default() }
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
			let _ = self
				.endpoints
				.clone()
				.into_iter()
				.map(|x| assert!(x.1.len() as u32 <= T::MaxEndpointLength::get()));

			for (account, endpoint) in &self.endpoints {
				EndpointRegister::<T>::insert(account, endpoint);
			}

			for (stash_account, threshold_account) in &self.threshold_accounts {
				ThresholdAccounts::<T>::insert(stash_account, threshold_account);
			}
		}
	}
	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		EndpointTooLong,
		NoBond,
		NotController
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// An endpoint has been added or edited. [who, endpoint]
		EndpointChanged(T::AccountId, Vec<u8>),
		/// Node Info has been added or edited. [who, endpoint, threshold_account]
		NodeInfoChanged(T::AccountId, Vec<u8>, T::AccountId),
		/// A threshold account has been added or edited. [validator, threshold_account]
		ThresholdAccountChanged(T::AccountId, T::AccountId),
		/// Node Info has been removed [who]
		NodeInfoRemoved(T::AccountId),
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn change_endpoint(origin: OriginFor<T>, endpoint: Vec<u8>) -> DispatchResult {
			let who = ensure_signed(origin.clone())?;
			ensure!(
				endpoint.len() as u32 <= T::MaxEndpointLength::get(),
				Error::<T>::EndpointTooLong
			);
			pallet_staking::Pallet::<T>::ledger(&who).ok_or(Error::<T>::NoBond)?;
			EndpointRegister::<T>::insert(&who, &endpoint);
			Self::deposit_event(Event::EndpointChanged(who, endpoint));
			Ok(())
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn change_threshold_accounts(origin: OriginFor<T>, new_account: T::AccountId) -> DispatchResult {
			let who = ensure_signed(origin.clone())?;
			let stash = Self::get_stash(&who)?;
			ThresholdAccounts::<T>::insert(&stash, &new_account);
			Self::deposit_event(Event::ThresholdAccountChanged(stash, new_account));
			Ok(())
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn withdraw_unbonded(
			origin: OriginFor<T>,
			num_slashing_spans: u32,
		) -> DispatchResultWithPostInfo {
			let controller = ensure_signed(origin.clone())?;
			let stash = Self::get_stash(&controller)?;
			pallet_staking::Pallet::<T>::withdraw_unbonded(origin, num_slashing_spans)?;
			let ledger = pallet_staking::Pallet::<T>::ledger(&controller);
			if ledger.is_none() && Self::endpoint_register(&controller).is_some() {
				EndpointRegister::<T>::remove(&controller);
				ThresholdAccounts::<T>::remove(stash);
				Self::deposit_event(Event::NodeInfoRemoved(controller));
			}
			Ok(().into())
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn validate(
			origin: OriginFor<T>,
			prefs: ValidatorPrefs,
			endpoint: Vec<u8>,
			threshold_account: T::AccountId
		) -> DispatchResult {
			let who = ensure_signed(origin.clone())?;
			ensure!(
				endpoint.len() as u32 <= T::MaxEndpointLength::get(),
				Error::<T>::EndpointTooLong
			);
			let stash = Self::get_stash(&who)?;
			pallet_staking::Pallet::<T>::validate(origin, prefs)?;
			EndpointRegister::<T>::insert(&who, &endpoint);
			ThresholdAccounts::<T>::insert(&stash, &threshold_account);
			Self::deposit_event(Event::NodeInfoChanged(who, endpoint, threshold_account));
			Ok(())
		}
	}
	impl<T: Config> Pallet<T> {
		pub fn get_stash(controller: &T::AccountId) -> Result<T::AccountId, DispatchError> {
			let ledger = pallet_staking::Pallet::<T>::ledger(controller).ok_or(Error::<T>::NotController)?;
			Ok(ledger.stash)
		}
	}
}
