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
	use frame_support::{dispatch::DispatchResult, pallet_prelude::*, traits::Currency, inherent::Vec};
	use frame_system::pallet_prelude::*;
	use pallet_staking::{EraIndex, RewardDestination, ValidatorPrefs};
	use sp_runtime::{traits::StaticLookup, Percent};

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_staking::Config {
		type Currency: Currency<Self::AccountId>;
		type MaxEndpointLength: Get<u32>;
	}

	/// The balance type of this pallet.
	pub type BalanceOf<T> = <<T as pallet_staking::Config>::Currency as Currency<
		<T as frame_system::Config>::AccountId,
	>>::Balance;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	#[pallet::getter(fn endpoint_register)]
	pub type EndpointRegister<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, Vec<u8>, ValueQuery>;

	// // Pallets use events to inform users when important changes are made.
	// // https://substrate.dev/docs/en/knowledgebase/runtime/events
	// #[pallet::event]
	// #[pallet::generate_deposit(pub(super) fn deposit_event)]
	// pub enum Event<T: Config> {
	// 	/// Event documentation should end with an array that provides descriptive names for event
	// 	/// parameters. [something, who]
	// 	SomethingStored(u32, T::AccountId),
	// }

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		EndpointTooLong
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn bond(
			origin: OriginFor<T>,
			controller: <T::Lookup as StaticLookup>::Source,
			#[pallet::compact] value: BalanceOf<T>,
			payee: RewardDestination<T::AccountId>,
			endpoint: Vec<u8>
		) -> DispatchResult {
			let who = ensure_signed(origin.clone())?;
			ensure!(
				endpoint.len() as u32 <= T::MaxEndpointLength::get(),
				Error::<T>::EndpointTooLong
			);
			pallet_staking::Pallet::<T>::bond(origin, controller, value, payee)?;
			EndpointRegister::<T>::insert(who, endpoint);
			Ok(())
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn change_endpoint(origin: OriginFor<T>, endpoint: Vec<u8>) -> DispatchResult {
			let who = ensure_signed(origin.clone())?;
			ensure!(
				endpoint.len() as u32 <= T::MaxEndpointLength::get(),
				Error::<T>::EndpointTooLong
			);
			let stash = pallet_staking::Pallet::<T>::bonded(who.clone());
			EndpointRegister::<T>::insert(who, endpoint);
			Ok(())
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn bond_extra(
			origin: OriginFor<T>,
			#[pallet::compact] max_additional: BalanceOf<T>,
		) -> DispatchResult {
			pallet_staking::Pallet::<T>::bond_extra(origin, max_additional)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn unbond(
			origin: OriginFor<T>,
			#[pallet::compact] value: BalanceOf<T>,
		) -> DispatchResult {
			pallet_staking::Pallet::<T>::unbond(origin, value)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn withdraw_unbonded(
			origin: OriginFor<T>,
			num_slashing_spans: u32,
		) -> DispatchResultWithPostInfo {
			pallet_staking::Pallet::<T>::withdraw_unbonded(origin, num_slashing_spans)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn validate(origin: OriginFor<T>, prefs: ValidatorPrefs) -> DispatchResult {
			pallet_staking::Pallet::<T>::validate(origin, prefs)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn nominate(
			origin: OriginFor<T>,
			targets: Vec<<T::Lookup as StaticLookup>::Source>,
		) -> DispatchResult {
			pallet_staking::Pallet::<T>::nominate(origin, targets)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn chill(origin: OriginFor<T>) -> DispatchResult {
			pallet_staking::Pallet::<T>::chill(origin)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn set_payee(
			origin: OriginFor<T>,
			payee: RewardDestination<T::AccountId>,
		) -> DispatchResult {
			pallet_staking::Pallet::<T>::set_payee(origin, payee)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn set_controller(
			origin: OriginFor<T>,
			controller: <T::Lookup as StaticLookup>::Source,
		) -> DispatchResult {
			pallet_staking::Pallet::<T>::set_controller(origin, controller)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn set_validator_count(
			origin: OriginFor<T>,
			#[pallet::compact] new: u32,
		) -> DispatchResult {
			pallet_staking::Pallet::<T>::set_validator_count(origin, new)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn scale_validator_count(origin: OriginFor<T>, factor: Percent) -> DispatchResult {
			pallet_staking::Pallet::<T>::scale_validator_count(origin, factor)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn force_no_eras(origin: OriginFor<T>) -> DispatchResult {
			pallet_staking::Pallet::<T>::force_no_eras(origin)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn force_new_era(origin: OriginFor<T>) -> DispatchResult {
			pallet_staking::Pallet::<T>::force_new_era(origin)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn set_invulnerables(
			origin: OriginFor<T>,
			invulnerables: Vec<T::AccountId>,
		) -> DispatchResult {
			pallet_staking::Pallet::<T>::set_invulnerables(origin, invulnerables)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn force_unstake(
			origin: OriginFor<T>,
			stash: T::AccountId,
			num_slashing_spans: u32,
		) -> DispatchResult {
			pallet_staking::Pallet::<T>::force_unstake(origin, stash, num_slashing_spans)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn force_new_era_always(origin: OriginFor<T>) -> DispatchResult {
			pallet_staking::Pallet::<T>::force_new_era_always(origin)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn cancel_deferred_slash(
			origin: OriginFor<T>,
			era: EraIndex,
			slash_indices: Vec<u32>,
		) -> DispatchResult {
			pallet_staking::Pallet::<T>::cancel_deferred_slash(origin, era, slash_indices)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn payout_stakers(
			origin: OriginFor<T>,
			validator_stash: T::AccountId,
			era: EraIndex,
		) -> DispatchResultWithPostInfo {
			pallet_staking::Pallet::<T>::payout_stakers(origin, validator_stash, era)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn rebond(
			origin: OriginFor<T>,
			#[pallet::compact] value: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			pallet_staking::Pallet::<T>::rebond(origin, value)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn set_history_depth(
			origin: OriginFor<T>,
			#[pallet::compact] new_history_depth: EraIndex,
			#[pallet::compact] _era_items_deleted: u32,
		) -> DispatchResult {
			pallet_staking::Pallet::<T>::set_history_depth(
				origin,
				new_history_depth,
				_era_items_deleted,
			)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn reap_stash(
			origin: OriginFor<T>,
			stash: T::AccountId,
			num_slashing_spans: u32,
		) -> DispatchResultWithPostInfo {
			pallet_staking::Pallet::<T>::reap_stash(origin, stash, num_slashing_spans)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn kick(
			origin: OriginFor<T>,
			who: Vec<<T::Lookup as StaticLookup>::Source>,
		) -> DispatchResult {
			pallet_staking::Pallet::<T>::kick(origin, who)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn set_staking_limits(
			origin: OriginFor<T>,
			min_nominator_bond: BalanceOf<T>,
			min_validator_bond: BalanceOf<T>,
			max_nominator_count: Option<u32>,
			max_validator_count: Option<u32>,
			threshold: Option<Percent>,
		) -> DispatchResult {
			pallet_staking::Pallet::<T>::set_staking_limits(
				origin,
				min_nominator_bond,
				min_validator_bond,
				max_nominator_count,
				max_validator_count,
				threshold,
			)
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn chill_other(origin: OriginFor<T>, controller: T::AccountId) -> DispatchResult {
			pallet_staking::Pallet::<T>::chill_other(origin, controller)
		}
	}
}
