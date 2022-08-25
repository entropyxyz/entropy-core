#![cfg_attr(not(feature = "std"), no_std)]

//! TODO JH: This is NOT SAFE for production yet. This is an MVP and totally DoS-able.

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// <https://docs.substrate.io/reference/frame-pallets/>
pub use pallet::*;

#[cfg(test)] mod mock;

#[cfg(test)] mod tests;

#[cfg(feature = "runtime-benchmarks")] mod benchmarking;

pub mod weights;

#[frame_support::pallet]
pub mod pallet {
  use frame_support::{
    dispatch::Dispatchable,
    pallet_prelude::*,
    traits::IsSubType,
    weights::{GetDispatchInfo, PostDispatchInfo},
  };
  use frame_system::{pallet_prelude::*, RawOrigin};
  use sp_runtime::{
    traits::{DispatchInfoOf, SignedExtension},
    transaction_validity::{InvalidTransaction, TransactionValidityError},
  };
  use sp_std::{fmt::Debug, prelude::*};

  pub use crate::weights::WeightInfo;

  #[pallet::config]
  pub trait Config: frame_system::Config {
    /// Pallet emits events
    type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

    /// Requirements for callable functions
    type Call: Parameter
      + Dispatchable<Origin = Self::Origin, PostInfo = PostDispatchInfo>
      + GetDispatchInfo
      + From<frame_system::Call<Self>>;

    // The weight information of this pallet.
    type WeightInfo: WeightInfo;
  }

  #[pallet::pallet]
  #[pallet::generate_store(pub(super) trait Store)]
  pub struct Pallet<T>(_);

  #[pallet::storage]
  #[pallet::getter(fn free_calls_left)]
  pub type FreeCallsLeft<T> = StorageValue<_, u8>;

  #[derive(Default)]
  #[pallet::genesis_config]
  pub struct GenesisConfig {
    pub free_calls_left: u8,
  }

  #[pallet::genesis_build]
  impl<T: Config> GenesisBuild<T> for GenesisConfig {
    fn build(&self) { <FreeCallsLeft<T>>::put(&self.free_calls_left); }
  }

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
      let base_weight = <T as Config>::WeightInfo::try_free_call();
      (base_weight.saturating_add(dispatch_info.weight), dispatch_info.class, Pays::No)
      // (dispatch_info.weight.saturating_add(10_000), dispatch_info.class, Pays::No)
    })]
    #[allow(clippy::boxed_local)]
    pub fn try_free_call(
      origin: OriginFor<T>,
      call: Box<<T as Config>::Call>,
    ) -> DispatchResultWithPostInfo {
      let sender = ensure_signed(origin)?;

      ensure!(Self::has_free_call(&sender), Error::<T>::NoFreeCallsAvailable);
      Self::consume_free_call(&sender)?;

      // TODO JH
      // Check these in order of cheapest to most expensive
      // - ensure call is contextually valid (maybe only extrinsics from relayer pallet?)
      // - max weight check
      // - make sure `call` isn't another `try_free_call()` or get WastingFreeCalls

      // cool, now dispatch call with account's origin
      let res = call.dispatch(RawOrigin::Signed(sender.clone()).into());
      Self::deposit_event(Event::FreeCallIssued(sender, res.map(|_| ()).map_err(|e| e.error)));

      res
    }
  }

  impl<T: Config> Pallet<T> {
    /// Checks if account has any free txs.
    pub fn has_free_call(_account_id: &<T>::AccountId) -> bool {
      if let Some(calls) = Self::free_calls_left() {
        if calls > 0 {
          return true;
        }
      }
      false
    }

    pub fn consume_free_call(_account_id: &<T>::AccountId) -> Result<(), Error<T>> {
      <FreeCallsLeft<T>>::mutate(|calls| {
        if let Some(calls) = calls {
          *calls = calls.saturating_sub(1u8);
        }
      });
      Ok(())
    }
  }

  #[derive(Debug, Clone)]
  pub enum FreeCallMethod {
    EraAllowance,
    ProofOfWork,
  }

  /// Verifies that the account has free calls available before executing or broadcasting to other
  /// validators.
  #[allow(clippy::derive_partial_eq_without_eq)]
  #[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
  #[scale_info(skip_type_params(T))]
  pub struct InterrogateFreeTransaction<T: Config + Send + Sync>(sp_std::marker::PhantomData<T>)
  where <T as frame_system::Config>::Call: IsSubType<Call<T>>;

  impl<T: Config + Send + Sync> Debug for InterrogateFreeTransaction<T>
  where <T as frame_system::Config>::Call: IsSubType<Call<T>>
  {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
      write!(f, "InterrogateFreeTransaction")
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result { Ok(()) }
  }

  impl<T: Config + Send + Sync> InterrogateFreeTransaction<T>
  where <T as frame_system::Config>::Call: IsSubType<Call<T>>
  {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self { Self(sp_std::marker::PhantomData) }
  }

  impl<T: Config + Send + Sync> SignedExtension for InterrogateFreeTransaction<T>
  where <T as frame_system::Config>::Call: IsSubType<Call<T>>
  {
    type AccountId = T::AccountId;
    type AdditionalSigned = ();
    type Call = <T as frame_system::Config>::Call;
    type Pre = ();

    const IDENTIFIER: &'static str = "InterrogateFreeTransaction";

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
      self.validate(who, call, info, len).map(|_| ())
    }

    fn validate(
      &self,
      who: &Self::AccountId,
      call: &Self::Call,
      _info: &DispatchInfoOf<Self::Call>,
      _len: usize,
    ) -> TransactionValidity {
    #[allow(clippy::collapsible_match)]
      if let Some(local_call) = call.is_sub_type() {
        if let Call::try_free_call { .. } = local_call {
          return match Pallet::<T>::has_free_call(who) {
            false => Err(TransactionValidityError::Invalid(InvalidTransaction::Payment)),
            true => Ok(ValidTransaction::default()),
          };
        }
      }
      Ok(ValidTransaction::default())
    }
  }
}
