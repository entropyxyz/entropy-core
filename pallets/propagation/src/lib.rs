#![cfg_attr(not(feature = "std"), no_std)]
//! # Propogation Pallet
//!
//! ## Overview
//!
//! Propgates messages to signing client through offchain worker
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[frame_support::pallet]
pub mod pallet {
	use codec::Encode;
	use frame_support::{inherent::Vec, pallet_prelude::*, sp_runtime::traits::Saturating};
	use frame_system::pallet_prelude::*;
	use helpers::unwrap_or_return_db_read;
	use scale_info::prelude::vec;
	use sp_core;
	use sp_runtime::{
		offchain::{http, Duration},
		sp_std::str,
	};

	#[pallet::config]
	pub trait Config:
		frame_system::Config + pallet_authorship::Config + pallet_relayer::Config
	{
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
	}

	pub type Message = shared_types::Message;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	#[pallet::getter(fn get_block_author)]
	pub type BlockAuthor<T: Config> =
		StorageMap<_, Blake2_128Concat, T::BlockNumber, T::AccountId, OptionQuery>;

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(block_number: T::BlockNumber) -> Weight {
			// TODO: JA return one DB read
			// also maybe less efficient can get this from rpc and digest
			let block_author = unwrap_or_return_db_read!(
				pallet_authorship::Pallet::<T>::author(),
				1,
				"on_init block_author"
			);

			BlockAuthor::<T>::insert(block_number, block_author);
			BlockAuthor::<T>::remove(block_number.saturating_sub(20u32.into()));
			T::DbWeight::get().reads_writes(1, 2)
		}

		fn offchain_worker(block_number: T::BlockNumber) {
			let _ = Self::post(block_number);
		}
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// Messages passed to this signer
		/// parameters. [messages]
		MessagesPassed(Vec<Message>),
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {}

	impl<T: Config> Pallet<T> {
		pub fn post(block_number: T::BlockNumber) -> Result<(), http::Error> {
			let messages =
				pallet_relayer::Pallet::<T>::messages(block_number.saturating_sub(1u32.into()));

			let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
			let kind = sp_core::offchain::StorageKind::PERSISTENT;
			let from_local = sp_io::offchain::local_storage_get(kind, b"propagation")
				.unwrap_or_else(|| b"http://localhost:3001/sign".to_vec());
			let url = str::from_utf8(&from_local).unwrap_or("http://localhost:3001/sign");

			log::warn!("propagation::post::messages: {:?}", &messages);
			// the data is serialized / encoded to Vec<u8> by parity-scale-codec::encode()
			let req_body = messages.encode();

			log::warn!("propagation::post::req_body: {:?}", &[req_body.clone()]);
			// We construct the request
			// important: the header->Content-Type must be added and match that of the receiving
			// party!!
			let pending = http::Request::post(url, vec![req_body]) // scheint zu klappen
				.deadline(deadline)
				.add_header("Content-Type", "application/x-parity-scale-codec")
				.send()
				.map_err(|_| http::Error::IoError)?;

			// We await response, same as in fn get()
			let response =
				pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;

			// check response code
			if response.code != 200 {
				log::warn!("Unexpected status code: {}", response.code);
				return Err(http::Error::Unknown)
			}
			let _res_body = response.body().collect::<Vec<u8>>();
			// ToDo: DF: handle _res_body
			Self::deposit_event(Event::MessagesPassed(messages));

			Ok(())
		}
	}
}
