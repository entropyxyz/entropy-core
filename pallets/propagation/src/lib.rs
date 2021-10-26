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
	use lite_json::json::JsonValue;
	use sp_runtime::{
		offchain::{http, Duration},
		sp_std::str,
	};
	use sp_staking::{
		offence::{Kind, Offence, ReportOffence},
		SessionIndex,
	};

	use frame_support::sp_runtime::{
		traits::{Convert, Saturating},
		Perbill, RuntimeDebug,
	};
	use scale_info::prelude::vec;

	use codec::{Decode, Encode};

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config:
		frame_system::Config + pallet_authorship::Config + pallet_relayer::Config
	{
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(_block_number: T::BlockNumber) {
			let messages = pallet_relayer::Pallet::<T>::messages();
			log::info!("logging messages: {:#?}", messages);
			log::info!("-----------testing get_enc------------");
			let bad_struct = DemoStruct { demo: 1u32 };
			let res: DemoStruct =
				Self::get_enc(&"http://localhost:3001/bob").unwrap_or(bad_struct.clone());
			log::info!("GET  receiving res.body: {:?}", res);
			let number = res.demo + 1;

			log::info!("-----------testing post--------------");
			log::info!("POST sending   req.body: {:?}", DemoStruct { demo: number });
			let res: DemoStruct =
				Self::post_enc(&"http://localhost:3001/bob", DemoStruct { demo: number })
					.unwrap_or(bad_struct);
			log::info!("POST receiving res.body: {:?}", res);

			//			pub fn post<S: Encode>(path: &str, data: S) -> Result<u64, http::Error> {
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
		/// Event documentation should end with an array that provides descriptive names for event
		/// parameters. [something, who]
		SomethingStored(u32, T::AccountId),
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		/// Error names should be descriptive.
		NoneValue,
		/// Errors should have helpful documentation associated with them.
		StorageOverflow,
		/// Error in the http protocols
		httpError,
		/// Error in the DKG.
		KeyGenInternalError,
	}

	// Dispatchable functions allows users to interact with the pallet and invoke state changes.
	// These functions materialize as "extrinsics", which are often compared to transactions.
	// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
	#[pallet::call]
	impl<T: Config> Pallet<T> {}

	#[derive(Debug, Decode, Encode, Clone)]
	struct DemoStruct {
		demo: u32,
	}

	impl<T: Config> Pallet<T> {
		pub fn get() -> Result<u64, http::Error> {
			// We want to keep the offchain worker execution time reasonable, so we set a hard-coded
			// deadline to 2s to complete the external call.
			// You can also wait idefinitely for the response, however you may still get a timeout
			// coming from the host machine.
			let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
			let request = http::Request::get(&"http://localhost:3001");

			log::info!("request incoming {:#?}", &request);

			// We set the deadline for sending of the request, note that awaiting response can
			// have a separate deadline. Next we send the request, before that it's also possible
			// to alter request headers or stream body content in case of non-GET requests.
			let pending = request.deadline(deadline).send().map_err(|_| http::Error::IoError)?;

			// The request is already being processed by the host, we are free to do anything
			// else in the worker (we can send multiple concurrent requests too).
			// At some point however we probably want to check the response though,
			// so we can block current thread and wait for it to finish.
			// Note that since the request is being driven by the host, we don't have to wait
			// for the request to have it complete, we will just not read the response.
			let response = pending.try_wait(deadline).map_err(|_| {
				log::info!("DeadlineReached");
				http::Error::DeadlineReached
			})??;
			// Let's check the status code before we proceed to reading the response.
			if response.code != 200 {
				log::warn!("Unexpected status code: {}", response.code);
				return Err(http::Error::Unknown)
			}

			// Next we want to fully read the response body and collect it to a vector of bytes.
			// Note that the return object allows you to read the body in chunks as well
			// with a way to control the deadline.
			let body = response.body().collect::<Vec<u8>>();

			// Create a str slice from the body.
			let body_str = sp_runtime::sp_std::str::from_utf8(&body).map_err(|_| {
				log::warn!("No UTF8 body");
				http::Error::Unknown
			})?;

			let price = match Self::parse_price(body_str) {
				Some(price) => Ok(price),
				None => {
					log::warn!("Unable to extract price from the response: {:?}", body_str);
					Err(http::Error::Unknown)
				},
			}?;

			log::warn!("Got price: {} cents", price);

			Ok(price)
		}

		/// POST-request, which sends and receives parity-scale-codec::decode()'ed data.
		/// takes a struct that will be serialized by parity-scale-codec::encode(), see https://crates.io/crates/parity-scale-codec.
		/// req.body will be this serialization
		/// res.body will again be parity-scale-codec::encode()'ed and is then decoded.
		pub fn post_enc<S: Encode, R: Decode>(path: &str, data: S) -> Result<R, http::Error> {
			// get deadline, same as in fn get()
			let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));

			// the data is serialized / encoded to Vec<u8> by parity-scale-codec::encode()
			let req_body = data.encode();

			// We construct the request
			// important: the header->Content-Type must be added and match that of the receiving
			// party!!
			let pending = http::Request::post(path, vec![req_body])
				.deadline(deadline)
				.add_header("Content-Type", "application/x-parity-scale-codec--DemoStruct")
				.send()
				.map_err(|_| http::Error::IoError)?;
			// let request = http::Request::post(path, vec![req_body])
			// 	.deadline(deadline)
			// 	.add_header("Content-Type", "application/x-parity-scale-codec--DemoStruct");
			// let pending = request.send().map_err(|_| http::Error::IoError)?;

			// We await response, same as in fn get()
			let response =
				pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;

			// check response code
			if response.code != 200 {
				log::warn!("Unexpected status code: {}", response.code);
				return Err(http::Error::Unknown)
			}
			let res_body = response.body().collect::<Vec<u8>>();

			// the response is parity-scale-codec::encode()'ed, so we have to decode it.
			// the type that the response is decoded to has to be passed indirectly to post() by
			// implying the type.
			let body = R::decode(&mut res_body.as_ref()).ok().unwrap();

			Ok(body)
		}

		/// GET-method that receives parity-scale-codec::encode()'ed data and decodes it
		pub fn get_enc<R: Decode>(path: &str) -> Result<R, http::Error> {
			// Result<R, http::Error> {
			// get deadline, same as in fn get()
			let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));

			let pending = http::Request::get(path)
				.deadline(deadline)
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
			let res_body = response.body().collect::<Vec<u8>>();

			// the response is parity-scale-codec::encode()'ed, so we have to decode it.
			// the type that the response is decoded to has to be passed indirectly to post() by
			// implying the type.
			let body = R::decode(&mut res_body.as_ref()).ok().unwrap();

			Ok(body)
		}

		pub fn parse_price(price_str: &str) -> Option<u64> {
			let val = lite_json::parse_json(price_str);
			let price = match val.ok()? {
				JsonValue::Object(obj) => {
					let (_, v) =
						obj.into_iter().find(|(k, _)| k.iter().copied().eq("demo".chars()))?;
					match v {
						JsonValue::Number(number) => number,
						_ => return None,
					}
				},
				_ => return None,
			};
			Some(price.integer as u64)
		}
	}
}
