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
		dispatch::DispatchResult, inherent::Vec, pallet_prelude::*, traits::IsSubType,
		weights::Pays,
	};
	use frame_system::pallet_prelude::*;
	use scale_info::TypeInfo;
	use sp_runtime::{
		traits::{DispatchInfoOf, SignedExtension, Saturating},
		transaction_validity::{TransactionValidity, TransactionValidityError, ValidTransaction},
	};
	use sp_std::fmt::Debug;
	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		type PruneBlock: Get<Self::BlockNumber>;
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(block_number: T::BlockNumber) -> Weight {
			Self::move_active_to_pending(block_number);
			0
		}
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, TypeInfo)]
	pub struct Message {
		pub data_1: u128,
		pub data_2: u128,
	}

	#[pallet::storage]
	#[pallet::getter(fn messages)]
	pub type Messages<T: Config> = StorageMap<_, Blake2_128Concat, T::BlockNumber, Vec<Message>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn pending)]
	pub type Pending<T: Config> = StorageMap<_, Blake2_128Concat, T::BlockNumber, Vec<Message>, ValueQuery>;
	// Pallets use events to inform users when important changes are made.
	// https://substrate.dev/docs/en/knowledgebase/runtime/events
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A transaction has been propagated to the network. [who]
		TransactionPropagated(T::AccountId),
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		Test,
	}

	// Dispatchable functions allows users to interact with the pallet and invoke state changes.
	// These functions materialize as "extrinsics", which are often compared to transactions.
	// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// An example dispatchable that takes a singles value as a parameter, writes the value to
		/// storage and emits an event. This function must be dispatched by a signed extrinsic.
		#[pallet::weight((10_000 + T::DbWeight::get().writes(1), Pays::No))]
		pub fn prep_transaction(
			origin: OriginFor<T>,
			data_1: u128,
			data_2: u128,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let new_message = Message { data_1, data_2 };
			let blockNumber = <frame_system::Pallet<T>>::block_number();
			Messages::<T>::try_mutate(blockNumber, |messages| -> Result<_, DispatchError> {
				messages.push(new_message);
				Ok(())
			})?;

			Self::deposit_event(Event::TransactionPropagated(who));
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		pub fn move_active_to_pending(block_number: T::BlockNumber) {
			let target_block = block_number.saturating_sub(2u32.into());
			let messages = 	Messages::<T>::take(target_block);

			if messages.len() > 0 {
				Messages::<T>::insert(target_block, messages);
			}

			let prune_block = block_number.saturating_sub(T::PruneBlock::get());
			Pending::<T>::remove(prune_block);

			// TODO check and point a validator who does not declare done before prune

		}
	}


	/// Validate `attest` calls prior to execution. Needed to avoid a DoS attack since they are
	/// otherwise free to place on chain.
	#[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
	#[scale_info(skip_type_params(T))]
	pub struct PrevalidateRelayer<T: Config + Send + Sync>(sp_std::marker::PhantomData<T>)
	where
		<T as frame_system::Config>::Call: IsSubType<Call<T>>;

	impl<T: Config + Send + Sync> Debug for PrevalidateRelayer<T>
	where
		<T as frame_system::Config>::Call: IsSubType<Call<T>>,
	{
		#[cfg(feature = "std")]
		fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
			write!(f, "PrevalidateRelayer")
		}

		#[cfg(not(feature = "std"))]
		fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
			Ok(())
		}
	}

	impl<T: Config + Send + Sync> PrevalidateRelayer<T>
	where
		<T as frame_system::Config>::Call: IsSubType<Call<T>>,
	{
		/// Create new `SignedExtension` to check runtime version.
		pub fn new() -> Self {
			Self(sp_std::marker::PhantomData)
		}
	}

	impl<T: Config + Send + Sync> SignedExtension for PrevalidateRelayer<T>
	where
		<T as frame_system::Config>::Call: IsSubType<Call<T>>,
	{
		type AccountId = T::AccountId;
		type Call = <T as frame_system::Config>::Call;
		type AdditionalSigned = ();
		type Pre = ();
		const IDENTIFIER: &'static str = "PrevalidateRelayer";

		fn additional_signed(&self) -> Result<Self::AdditionalSigned, TransactionValidityError> {
			Ok(())
		}

		// <weight>
		// The weight of this logic is included in the `attest` dispatchable.
		// </weight>
		fn validate(
			&self,
			_who: &Self::AccountId,
			call: &Self::Call,
			_info: &DispatchInfoOf<Self::Call>,
			_len: usize,
		) -> TransactionValidity {
			if let Some(local_call) = call.is_sub_type() {
				if let Call::prep_transaction { data_1, .. } = local_call {
					ensure!(*data_1 != 43u128, InvalidTransaction::Custom(1.into()));
					//TODO apply filter logic
				}
			}
			Ok(ValidTransaction::default())
		}
	}
}
