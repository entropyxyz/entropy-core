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
		traits::{DispatchInfoOf, Saturating, SignedExtension},
		transaction_validity::{TransactionValidity, TransactionValidityError, ValidTransaction},
	};
	use sp_std::fmt::Debug;
	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_authorship::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		type PruneBlock: Get<Self::BlockNumber>;
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(block_number: T::BlockNumber) -> Weight {
			Self::move_active_to_pending(block_number);
			Self::note_responsibility(block_number);
			0
		}
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	// // type SigRequest = common::SigRequest;
	// #[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, TypeInfo)]
	// pub struct Message {
	// 	sig_request: common::SigRequest,
	// }

	#[pallet::storage]
	#[pallet::getter(fn messages)]
	pub type Messages<T: Config> =
		StorageMap<_, Blake2_128Concat, T::BlockNumber, Vec<Message>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn pending)]
	pub type Pending<T: Config> =
		StorageMap<_, Blake2_128Concat, T::BlockNumber, Vec<Message>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn failures)]
	pub type Failures<T: Config> =
		StorageMap<_, Blake2_128Concat, T::BlockNumber, Vec<u32>, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn unresponsive)]
	pub type Unresponsive<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, u32, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn responsibility)]
	pub type Responsibility<T: Config> =
		StorageMap<_, Blake2_128Concat, T::BlockNumber, T::AccountId, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn registered)]
	pub type Registered<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, bool, ValueQuery>;

	pub type SigResponse = common::SigResponse;
	pub type RegResponse = common::RegistrationResponse;
	pub type SigRequest = common::SigRequest;
	pub type Message = common::SigRequest;

	// Pallets use events to inform users when important changes are made.
	// https://substrate.dev/docs/en/knowledgebase/runtime/events
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A transaction has been propagated to the network. [who, signature_response]
		TransactionPropagated(T::AccountId, SigResponse),
		/// An account has been registered. [who]
		AccountRegistered(T::AccountId),
		/// An account has been registered. [who, block_number, failures]
		ConfirmedDone(T::AccountId, T::BlockNumber, Vec<u32>),
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		Test,
		NotYourResponsibility,
		NoResponsibility,
		AlreadySubmitted,
	}

	// Dispatchable functions allows users to interact with the pallet and invoke state changes.
	// These functions materialize as "extrinsics", which are often compared to transactions.
	// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight((10_000 + T::DbWeight::get().writes(1), Pays::No))]
		pub fn prep_transaction(origin: OriginFor<T>, sig_request: SigRequest) -> DispatchResult {
			log::warn!("relayer::prep_transaction::sig_request: {:?}", sig_request);
			let who = ensure_signed(origin)?;

			let block_number = <frame_system::Pallet<T>>::block_number();
			Messages::<T>::try_mutate(block_number, |request| -> Result<_, DispatchError> {
				request.push(sig_request);
				Ok(())
			})?;
			// ToDo: get random signeing-nodes
			//let sig_response = get_signers();
			let sig_response = SigResponse { signing_nodes: sp_std::vec![1], com_manager: 1 };

			Self::deposit_event(Event::TransactionPropagated(who, sig_response));
			Ok(())
		}

		/// Register a account with the entropy-network
		/// accounts are identified by the public group key of the user.
		// ToDo: see https://github.com/Entropyxyz/entropy-core/issues/29
		#[pallet::weight((10_000 + T::DbWeight::get().writes(1), Pays::No))]
		pub fn register(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			// TODO proof
			Registered::<T>::insert(&who, true);
			Self::deposit_event(Event::AccountRegistered(who));

			Ok(())
		}

		#[pallet::weight((10_000 + T::DbWeight::get().writes(1), Pays::No))]
		pub fn confirm_done(
			origin: OriginFor<T>,
			block_number: T::BlockNumber,
			failures: Vec<u32>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let responsibility =
				Self::responsibility(block_number).ok_or(Error::<T>::NoResponsibility)?;
			ensure!(responsibility == who, Error::<T>::NotYourResponsibility);
			let current_failures = Self::failures(block_number);

			ensure!(current_failures.is_none(), Error::<T>::AlreadySubmitted);
			Failures::<T>::insert(block_number, &failures);
			Self::deposit_event(Event::ConfirmedDone(who, block_number, failures));
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		pub fn move_active_to_pending(block_number: T::BlockNumber) {
			let target_block = block_number.saturating_sub(2u32.into());
			let current_failures = Self::failures(block_number);
			let prune_block = block_number.saturating_sub(T::PruneBlock::get());
			let responsibility = Self::responsibility(target_block);
			if responsibility.is_none() {
				log::warn!("responsibility not found {:?}", target_block)
			}
			if responsibility.is_none() {
				return;
			}
			// TODO EH is there a better way to handle this
			let unwrapped = responsibility.unwrap();

			if current_failures.is_none() {
				Unresponsive::<T>::mutate(unwrapped, |dings| *dings += 1);

			//TODO slash or point for failure then slash after pointed a few times
			// If someone is slashed they probably should reset their unresponsive dings
			} else {
				Failures::<T>::remove(prune_block);
				Unresponsive::<T>::remove(unwrapped);
			}

			let messages = Messages::<T>::take(target_block);

			if messages.len() > 0 {
				Pending::<T>::insert(target_block, messages);
			}

			Pending::<T>::remove(prune_block);
		}

		pub fn note_responsibility(block_number: T::BlockNumber) {
			let target_block = block_number.saturating_sub(1u32.into());
			let block_author = pallet_authorship::Pallet::<T>::author();

			if block_author.is_none() {
				return;
			}

			Responsibility::<T>::insert(target_block, block_author.unwrap());

			let prune_block = block_number.saturating_sub(T::PruneBlock::get());
			Responsibility::<T>::remove(prune_block);
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

		fn pre_dispatch(
			self,
			who: &Self::AccountId,
			call: &Self::Call,
			info: &DispatchInfoOf<Self::Call>,
			len: usize,
		) -> Result<Self::Pre, TransactionValidityError> {
			Ok(self.validate(who, call, info, len).map(|_| ())?)
		}

		// <weight>
		// The weight of this logic is included in the `attest` dispatchable.
		// </weight>
		fn validate(
			&self,
			who: &Self::AccountId,
			call: &Self::Call,
			_info: &DispatchInfoOf<Self::Call>,
			_len: usize,
		) -> TransactionValidity {
			if let Some(local_call) = call.is_sub_type() {
				if let Call::prep_transaction { .. } = local_call {
					ensure!(Registered::<T>::get(who), InvalidTransaction::Custom(1.into()));
					//TODO apply filter logic
				}

				if let Call::register { .. } = local_call {
					//TODO ensure proof
				}

				if let Call::confirm_done { block_number, .. } = local_call {
					let responsibility = Responsibility::<T>::get(block_number)
						.ok_or(InvalidTransaction::Custom(2.into()))?;
					ensure!(responsibility == *who, InvalidTransaction::Custom(3.into()));
					let current_failures = Failures::<T>::get(block_number);
					ensure!(current_failures.is_none(), InvalidTransaction::Custom(4.into()));
				}
			}
			Ok(ValidTransaction::default())
		}
	}
}
