#![cfg_attr(not(feature = "std"), no_std)]

//! TODO JH: This is NOT SAFE for production yet. This is an MVP and totally DoS-able.

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// <https://docs.substrate.io/reference/frame-pallets/>
pub use pallet::*;

#[cfg(test)] mod mock;

#[cfg(test)] mod tests;

#[cfg(feature = "runtime-benchmarks")] mod benchmarking;

#[frame_support::pallet]
pub mod pallet {
  use frame_support::{
    dispatch::Dispatchable,
    pallet_prelude::*,
    weights::{GetDispatchInfo, PostDispatchInfo},
  };
  use frame_system::{pallet_prelude::*, RawOrigin};
  use sp_runtime::DispatchResultWithInfo;
  use sp_std::prelude::*;

  #[pallet::config]
  pub trait Config: frame_system::Config {
    /// Pallet emits events
    type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

    /// Requirements for callable functions
    type Call: Parameter
      + Dispatchable<Origin = Self::Origin, PostInfo = PostDispatchInfo>
      + GetDispatchInfo;
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Try to call an extrinsic using the account's available free calls.
    ///
    /// If free calls are available, a free call is used and the account will pay zero tx fees,
    /// regardless of the call's result.
    ///
    /// If no free calls are available, account pays the stupidity fee of ((base fee) + (WeightAsFee
    /// for querying free calls)).
    #[pallet::weight({
			let dispatch_info = call.get_dispatch_info();
			(dispatch_info.weight.saturating_add(10_000), dispatch_info.class, Pays::No)
		})]
    pub fn try_free_call(
      origin: OriginFor<T>,
      call: Box<<T as Config>::Call>,
    ) -> DispatchResultWithPostInfo {
      let sender = ensure_signed(origin)?;

      ensure!(Self::process_free_call(&sender), Error::<T>::NoFreeCallsAvailable);

      // TODO JH
      // Check these in order of cheapest to most expensive
      // - ensure call is contextually valid (maybe only extrinsics from relayer pallet?)
      // - max weight check
      // - make sure `call` isn't another `try_free_call()` or get WastingFreeCalls

      // cool, now dispatch call with account's origin
      let res = call.dispatch(RawOrigin::Signed(sender.clone()).into());
      Self::deposit_event(Event::FreeCallIssued(sender, res.map(|_| ()).map_err(|e| e.error)));

      // account pays no fees
      Ok()
    }
  }

  impl<T: Config> Pallet<T> {
    // TODO JH
    /// Checks if user can do a free tx, and by what method. Process any state changes, too, unless
    /// false.
    fn process_free_call(_account_id: &<T>::AccountId) -> bool { true }
  }

  #[pallet::pallet]
  #[pallet::generate_store(pub(super) trait Store)]
  pub struct Pallet<T>(_);

  #[pallet::storage]
  #[pallet::getter(fn something)]
  pub type Something<T> = StorageValue<_, u32>;

  #[pallet::event]
  #[pallet::generate_deposit(pub(super) fn deposit_event)]
  pub enum Event<T: Config> {
    /// A user used a free call to dispatch a transaction; the account did not pay any transaction
    /// fees.
    FreeCallIssued(T::AccountId, DispatchResult),
  }

  #[pallet::error]
  pub enum Error<T> {
    /// Account has no free calls left. Call the extrinsic directly or use `try_free_call_or_pay()`
    NoFreeCallsAvailable,
    /// Are you fuzzing, or are you just dumb?
    WastingFreeCalls,
  }

  // TODO JH for default storage values (free tx per era, etc) if not part of Config
  // #[pallet::genesis_config]
  // pub struct GenesisConfig<T: Config> {
  // 	/// The `AccountId` of the sudo key.
  // 	pub key: Option<T::AccountId>,
  // }
  //
  // #[cfg(feature = "std")]
  // impl<T: Config> Default for GenesisConfig<T> {
  // 	fn default() -> Self {
  // 		Self { key: None }
  // 	}
  // }
  //
  // #[pallet::genesis_build]
  // impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
  // 	fn build(&self) {
  // 		if let Some(ref key) = self.key {
  // 			Key::<T>::put(key);
  // 		}
  // 	}
  // }
}
