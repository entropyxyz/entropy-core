#![cfg_attr(not(feature = "std"), no_std)]

//! TODO JH: This is NOT SAFE for production yet. This is an MVP and likely DoS-able.

//! TODO JH: Free Transactions per Era
//! [x] FreeTxPerEra StorageValue - Enable pallet by setting it to Some(u16)
//! [x] FreeTxLeft StorageMap(AccountId, u16) - store the number of free transactions left for each
//!   account
//! [x] try_free_tx modification
//! [x] SignedExtension modification
//! [] on_idle hook (optional/future) - prunes FreeCallsRemaining
//! [x] reset_free_tx - root function clears FreeTxLeft
//!
//! [] Remove GenesisConfig and fix tests - remove genesis config
//! [] new tests

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
  use scale_info::TypeInfo;
  use sp_runtime::{
    traits::{DispatchInfoOf, SignedExtension},
    transaction_validity::{InvalidTransaction, TransactionValidityError},
  };
  use sp_staking::EraIndex;
  use sp_std::{fmt::Debug, prelude::*};

  pub use crate::weights::WeightInfo;

  #[pallet::config]
  pub trait Config: frame_system::Config + StakingCurrentEra {
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

  /// Represents the number of free calls a user can have
  pub type FreeCallCount = u16;

  /// Stores how many free calls a user has left and which era it applies to.
  ///
  /// This is used to track how many free calls are left per user WITHOUT requiring FreeCallsPerEra
  /// to be pruned every era.
  #[derive(Encode, Decode, MaxEncodedLen, TypeInfo)]
  pub struct FreeCallInfo {
    era_index:            EraIndex,
    free_calls_remaining: FreeCallCount,
  }

  #[pallet::pallet]
  #[pallet::generate_store(pub(super) trait Store)]
  pub struct Pallet<T>(_);

  /// Default number of free calls users get per era.
  ///
  /// To disable free calls altogether, set this to `None` or leave it unitialized.
  #[pallet::storage]
  #[pallet::getter(fn free_calls_per_era_raw)]
  pub type FreeCallsPerEra<T: Config> = StorageValue<_, FreeCallCount>;

  /// Stores how many free calls a user has left for this era.
  ///
  /// What the query value means:
  ///
  /// - `Some` where `EraIndex == current_era_index`: the user has `FreeCalls` left to use in this
  ///   era.
  /// - `None` OR `Some` where `EraIndex != current_era_index`: user has not used any free calls
  ///   this era. If using a free call, reset their value to `(FreeCallsPerEra - 1,
  ///   current_era_index)`
  #[pallet::storage]
  #[pallet::getter(fn free_calls_remaining_raw)]
  pub type FreeCallsRemaining<T: Config> =
    StorageMap<_, Blake2_128Concat, T::AccountId, FreeCallInfo, OptionQuery>;

  #[pallet::event]
  #[pallet::generate_deposit(pub(super) fn deposit_event)]
  pub enum Event<T: Config> {
    /// A user used a free call to dispatch a transaction; the account did not pay any transaction
    /// fees.
    FreeCallIssued(T::AccountId, DispatchResult),
  }

  #[pallet::error]
  pub enum Error<T> {
    /// Free calls have been disabled
    FreeCallsDisabled,
    /// Account has no free calls left. Call the extrinsic directly or use `try_free_call_or_pay()`
    NoFreeCallsAvailable,
    /// Are you fuzzing, or are you just dumb?
    WastingFreeCalls,
  }

  // #[pallet::hooks]
  // impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
  // 	fn on_idle(_block: T::BlockNumber, remaining_weight: Weight) -> Weight {
  //     // TODO for when we want to prune FreeCallsRemaining
  // 	}
  // }

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

      Self::try_consume_free_call(&sender)?;

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

    /// Sets the number of free calls each account gets per era.
    /// To disable free calls, set this to `0`.
    /// TODO: weight
    #[pallet::weight(10_000)]
    pub fn set_free_calls_per_era(
      origin: OriginFor<T>,
      free_calls_per_era: FreeCallCount,
    ) -> DispatchResult {
      let _ = ensure_root(origin)?;
      if free_calls_per_era == 0 {
        // make sure that <FreeCallsPerEra<T>>::get() returns None instead of Some(0)
        <FreeCallsPerEra<T>>::kill();
      } else {
        <FreeCallsPerEra<T>>::put(free_calls_per_era);
      }
      Ok(())
    }

    // Resets free call count for all accounts during this era. Count will still be reset every
    // era, and this does not change the era length.
    //
    // TODO: weight
    // #[pallet::weight(10_000)]
    // pub fn reset_free_calls(origin: OriginFor<T>) -> DispatchResult {
    //   ensure_root(origin)?;
    //   // TODO
    //   Ok(())
    // }
  }

  impl<T: Config> Pallet<T> {
    // TODO make sure this is right before moving on
    // if OK(()), a free call for the provided account was available and was consumed
    pub fn try_consume_free_call(account_id: &<T>::AccountId) -> Result<(), Error<T>> {
      // We can check if free calls are disabled and get free calls per era from the same query
      let free_calls_per_era = Self::free_calls_per_era().ok_or(Error::<T>::FreeCallsDisabled)?;

      <FreeCallsRemaining<T>>::try_mutate(account_id, |call_info| {
        let current_era_index = <T as StakingCurrentEra>::current_era().unwrap();

        let update_info = |remaining| {
          Some(FreeCallInfo {
            era_index:            current_era_index,
            free_calls_remaining: remaining as FreeCallCount,
          })
        };

        // update their call data
        match call_info {
          Some(prev_info) => {
            let FreeCallInfo { era_index, free_calls_remaining } = *prev_info;

            // if there's a new era, free calls were last used in a prev era. fill up free calls.
            if era_index != current_era_index {
              *call_info = update_info(free_calls_per_era.saturating_sub(1));
              return Ok(());
            }

            // if era is current and no remaining calls left, they've used them all
            if free_calls_remaining == 0 as FreeCallCount {
              return Err(Error::<T>::NoFreeCallsAvailable);
            }
            // otherwise, consume one free call
            *call_info = update_info(free_calls_remaining.saturating_sub(1));
          },

          // if None, then this is the account's first free call ever (or it was pruned)
          None => {
            *call_info = update_info(free_calls_per_era.saturating_sub(1));
          },
        }
        Ok(())
      })
    }

    /// Returns number of free calls a user has, and returns None if free calls are disabled.
    pub fn free_calls_remaining(account_id: &<T>::AccountId) -> FreeCallCount {
      // return 0 if free calls are disabled (and gets free calls per era in the same storage
      // query).
      let free_calls_per_era = Self::free_calls_per_era().unwrap_or_else(|| {
        return 0 as FreeCallCount;
      });

      // if the free call count was last updated this era, return however many free calls they have
      // left
      if let Some(call_info) = <FreeCallsRemaining<T>>::get(account_id) {
        let FreeCallInfo { era_index, free_calls_remaining } = call_info;
        if era_index == <T as StakingCurrentEra>::current_era().unwrap() {
          return free_calls_remaining;
        };
      };

      // otherwise they have the default number of free calls per era remaining
      free_calls_per_era
    }

    /// Returns the number of free calls per era a user gets, or returns None if free calls are
    /// disabled
    pub fn free_calls_per_era() -> Option<FreeCallCount> {
      if let Some(n) = Self::free_calls_per_era_raw() {
        if n != 0 {
          return Some(n);
        };
      }
      None
    }

    /// Checks if free calls are enabled
    fn free_calls_are_enabled() -> bool { Self::free_calls_per_era().is_some() }
  }

  pub trait StakingCurrentEra {
    type EraIndex;
    fn current_era() -> Option<EraIndex>;
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
      // is there a way to do all this shit better?
      if let Some(local_call) = call.is_sub_type() {
        if let Call::try_free_call { .. } = local_call {
          if Pallet::<T>::free_calls_are_enabled() {
            if Pallet::<T>::free_calls_remaining(who) != 0 {
              return Ok(ValidTransaction::default());
            }
          }
          return Err(TransactionValidityError::Invalid(InvalidTransaction::Payment));
        }
      }
      return Ok(ValidTransaction::default());
    }
  }
}
