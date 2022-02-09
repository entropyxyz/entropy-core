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
	use frame_support::{
		dispatch::DispatchResult,
		inherent::Vec,
		pallet_prelude::*,
		traits::{ValidatorSet, ValidatorSetWithIdentification},
	};
	use frame_system::pallet_prelude::*;
	use sp_application_crypto::RuntimeAppPublic;
	use sp_runtime::{sp_std::str, traits::Convert};
	use sp_staking::{
		offence::{Kind, Offence, ReportOffence},
		SessionIndex,
	};

	use frame_support::sp_runtime::{Perbill, RuntimeDebug};
	use scale_info::prelude::vec;

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		type AuthorityId: Member
			+ Parameter
			+ RuntimeAppPublic
			+ Ord
			+ MaybeSerializeDeserialize
			+ MaxEncodedLen;
		/// A type that gives us the ability to submit unresponsiveness offence reports.
		type ReportBad: ReportOffence<
			Self::AccountId,
			IdentificationTuple<Self>,
			TuxAngry<IdentificationTuple<Self>>,
		>;
		type ValidatorIdOf: Convert<Self::AccountId, Option<ValidatorId<Self>>>;

		/// A type for retrieving the validators supposed to be online in a session.
		type ValidatorSet: ValidatorSetWithIdentification<Self::AccountId>;
		type MinValidators: Get<u32>;
	}

	/// A type for representing the validator id in a session.
	pub type ValidatorId<T> = <<T as Config>::ValidatorSet as ValidatorSet<
		<T as frame_system::Config>::AccountId,
	>>::ValidatorId;

	/// A tuple of (ValidatorId, Identification) where `Identification` is the full identification
	/// of `ValidatorId`.
	pub type IdentificationTuple<T> = (
		ValidatorId<T>,
		<<T as Config>::ValidatorSet as ValidatorSetWithIdentification<
			<T as frame_system::Config>::AccountId,
		>>::Identification,
	);

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		/// Error names should be descriptive.
		NoneValue,
		/// Errors should have helpful documentation associated with them.
		StorageOverflow,
		/// Error in the DKG.
		KeyGenInternalError,
		NoAssociatedValidatorId,
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A custom offence has been logged. [who, offenders]
		Offence(T::AccountId, Vec<T::AccountId>),
	}

	// Dispatchable functions allows users to interact with the pallet and invoke state changes.
	// These functions materialize as "extrinsics", which are often compared to transactions.
	// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// An example dispatchable that may throw a custom error.
		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn demo_offence<'a>(origin: OriginFor<T>, offenders: Vec<T::AccountId>) -> DispatchResult  {
			// TODO remove this function, it is for demo purposes only
			let who = ensure_signed(origin)?;
			Self::do_offence(who, offenders)?;
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		pub fn do_offence(
			who: T::AccountId,
			offender_addresses: Vec<T::AccountId>,
		) -> DispatchResult
		{

			let offenders = offender_addresses
				.clone()
				.into_iter()
				.filter_map(|account| T::ValidatorIdOf::convert(account))
				.filter_map(|id| {
					<T::ValidatorSet as ValidatorSetWithIdentification<T::AccountId>>::IdentificationOf::convert(
				id.clone()
			).map(|full_id| (id, full_id))
				})
				.collect::<Vec<IdentificationTuple<T>>>();

			let session_index = T::ValidatorSet::session_index();
			let current_validators = T::ValidatorSet::validators();
			let validator_set_count = current_validators.clone().len() as u32;
			if validator_set_count.saturating_sub(offenders.len() as u32) <= T::MinValidators::get()
			{
				log::info!("Min validators not slashed: {:?}", offenders);
			} else {
				log::info!("session_index: {:?}", session_index);
				log::info!("offenders: {:?}", offenders);

				let offence =
					TuxAngry { session_index, validator_set_count, offenders: offenders };

				log::info!("offence: {:?}", offence);
				if let Err(e) = T::ReportBad::report_offence(vec![who.clone()], offence) {
					log::error!("error: {:?}", e);
				};
			}
			Self::deposit_event(Event::Offence(who, offender_addresses));
			Ok(())
		}
	}

	/// An offence that is filed if a validator didn't send a heartbeat message.
	#[derive(RuntimeDebug)]
	#[cfg_attr(feature = "std", derive(Clone, PartialEq, Eq))]
	pub struct TuxAngry<Offender> {
		/// The current session index in which we report the unresponsive validators.
		///
		/// It acts as a time measure for unresponsiveness reports and effectively will always
		/// point at the end of the session.
		pub session_index: SessionIndex,
		/// The size of the validator set in current session/era.
		pub validator_set_count: u32,
		/// Authorities that were unresponsive during the current era.
		pub offenders: Vec<Offender>,
	}

	impl<Offender: Clone> Offence<Offender> for TuxAngry<Offender> {
		const ID: Kind = *b"tux-really-angry";
		type TimeSlot = SessionIndex;

		fn offenders(&self) -> Vec<Offender> {
			self.offenders.clone()
		}

		fn session_index(&self) -> SessionIndex {
			self.session_index
		}

		fn validator_set_count(&self) -> u32 {
			self.validator_set_count
		}

		fn time_slot(&self) -> Self::TimeSlot {
			self.session_index
		}

		fn slash_fraction(_offenders: u32, _validator_set_count: u32) -> Perbill {
			Perbill::from_perthousand(0)
		}
	}
}
