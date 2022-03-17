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
	use codec::Encode;
	use frame_support::{inherent::Vec, pallet_prelude::*, sp_runtime::traits::Saturating};
	use frame_system::{pallet_prelude::*, offchain::AppCrypto};
	use scale_info::prelude::vec;
	use sp_core;
	use sp_runtime::{
		RuntimeAppPublic,
		traits::AccountIdConversion,
		offchain::{http, Duration},
		sp_std::str, AccountId32
	};


	pub const KEY_TYPE: sp_core::crypto::KeyTypeId = sp_application_crypto::key_types::BABE;


	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config:
		frame_system::Config
		+ pallet_authorship::Config
		+ pallet_relayer::Config
		+ pallet_staking_extension::Config
	{
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		/// The identifier type for an authority.
		type AuthorityId: Member
		+ Parameter
		+ RuntimeAppPublic
		+ Ord
		+ MaybeSerializeDeserialize
		+ MaxEncodedLen;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(block_number: T::BlockNumber) {
			let _ = Self::post(block_number);
		}
	}

	// The pallet's runtime storage items.
	// https://substrate.dev/docs/en/knowledgebase/runtime/storage
	#[pallet::storage]
	#[pallet::getter(fn something)]
	// Learn more about declaring storage items:
	// https://substrate.dev/docs/en/knowledgebase/runtime/storage#declaring-storage-items
	pub type Something<T> = StorageValue<_, u32>;

	// Pallets use events to inform users when important changes are made.
	// https://substrate.dev/docs/en/knowledgebase/runtime/events
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// Messages passed to this signer
		/// parameters. [signer, author_endpoint]
		MessagesPassed(T::AccountId, Vec<u8>),
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		/// Error names should be descriptive.
		NoneValue,
		/// Errors should have helpful documentation associated with them.
		StorageOverflow,
		/// Error in the DKG.
		KeyGenInternalError,
	}

	// Dispatchable functions allows users to interact with the pallet and invoke state changes.
	// These functions materialize as "extrinsics", which are often compared to transactions.
	// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
	#[pallet::call]
	impl<T: Config> Pallet<T> {}

	impl<T: Config> Pallet<T> {

		pub fn get_local_keys() -> Result<T::AccountId, &'static str> {
			let public_keys: Vec<sp_core::sr25519::Public> =
				sp_io::crypto::sr25519_public_keys(KEY_TYPE);
			let account = AccountId32::new(
				public_keys.first().ok_or("No public keys for crypto key type `orac`")?.0,
			);
			let mut to32 = AccountId32::as_ref(&account);
			let address: T::AccountId =
				T::AccountId::decode(&mut to32).map_err(|_| "Could not decode account")?;
				dbg!(address.clone());
			Ok(address)
		}

		pub fn post(block_number: T::BlockNumber) -> Result<(), http::Error> {
			// get deadline, same as in fn get()
			let messages =
				pallet_relayer::Pallet::<T>::messages(block_number.saturating_sub(1u32.into()));
			let block_author = pallet_authorship::Pallet::<T>::author();
			// TODO JA: handle better
			if block_author.is_none() {
				return Ok(());
			}
			let author_endpoint = pallet_staking_extension::Pallet::<T>::endpoint_register(
				block_author.clone().unwrap(),
			);

			// TODO JA: handle better
			if author_endpoint.is_none() {
				return Ok(());
			}
			// TODO fix unwrap
			let mut local_key = Self::get_local_keys().unwrap();


			let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
			let kind = sp_core::offchain::StorageKind::PERSISTENT;
			let from_local = sp_io::offchain::local_storage_get(kind, b"propagation")
				.unwrap_or_else(|| b"http://localhost:3001/sign".to_vec());
			let url = str::from_utf8(&from_local).unwrap_or("http://localhost:3001/sign");

			log::warn!("propagation::post::messages: {:?}", &messages);
			// the data is serialized / encoded to Vec<u8> by parity-scale-codec::encode()
			// TODO: JA finalize what needs to be sent in this
			let req_body = [
				block_author.clone().unwrap().encode(),
				author_endpoint.clone().unwrap().encode(),
				messages.encode(),
				local_key.encode()
			]
			.encode();

			log::warn!("propagation::post::req_body: {:?}", &req_body);

			// We construct the request
			// important: the header->Content-Type must be added and match that of the receiving
			// party!!
			let pending =
				// http::Request::post(&url, vec![block_author.clone().unwrap().encode(), req_body])
				http::Request::post(&url, vec![req_body]) // scheint zu klappen
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
				return Err(http::Error::Unknown);
			}
			let _res_body = response.body().collect::<Vec<u8>>();
			// ToDo: DF: handle _res_body
			Self::deposit_event(Event::MessagesPassed(
				block_author.unwrap(),
				author_endpoint.unwrap(),
			));

			Ok(())
		}
	}
}
