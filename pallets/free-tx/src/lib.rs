#![cfg_attr(not(feature = "std"), no_std)]

//! TODO JH: This is NOT SAFE for production yet. This is an MVP and likely DoS-able.

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// <https://docs.substrate.io/reference/frame-pallets/>
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

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
    use sp_std::{cmp::min, fmt::Debug, prelude::*};

    // use super::*;
    pub use crate::weights::WeightInfo;

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_staking::Config {
        /// Pallet emits events
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        /// Requirements for callable functions
        type Call: Parameter
            + Dispatchable<Origin = Self::Origin, PostInfo = PostDispatchInfo>
            + GetDispatchInfo
            + From<frame_system::Call<Self>>;

        // Counsil (or another) can update the number of free transactions per era
        type UpdateOrigin: EnsureOrigin<Self::Origin>;

        // The weight information of this pallet.
        type WeightInfo: WeightInfo;
    }

    pub const MAX_FREE_CALLS_PER_ACCOUNT: u8 = 10;

    /// Represents a number of free calls
    pub type FreeCallCount = u32;

    /// Shows the number of free calls used in the previously used era
    #[derive(Encode, Decode, MaxEncodedLen, TypeInfo)]
    pub struct RecentCallCount {
        pub latest_era: EraIndex,
        pub count: FreeCallCount,
    }

    #[derive(Encode, Decode, MaxEncodedLen, TypeInfo)]
    /// Keeps track of the number of free calls a user has and the number of free calls they've used
    /// this era
    pub struct FreeCallMetadata {
        pub rechargable_calls_allocated: FreeCallCount,
        pub fixed_calls_remaining: FreeCallCount,
        pub calls_used: RecentCallCount,
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    /// Maximum number of free calls a user can use per era.
    ///
    /// `None`: users can use as many free calls as they own.
    /// `Some(0)`: free calls are disabled.
    /// `Some(n)`: users can use up to `n` free calls per era
    #[pallet::storage]
    #[pallet::getter(fn max_individual_free_calls_per_era)]
    pub type MaxIndividualFreeCallsPerEra<T: Config> = StorageValue<_, FreeCallCount>;

    /// Stores a list of `` that are owned by an account.
    #[pallet::storage]
    #[pallet::getter(fn free_call_data)]
    pub type FreeCallData<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, FreeCallMetadata, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A user used a free call to dispatch a transaction; the account did not pay any
        /// transaction fees.
        FreeCallIssued(T::AccountId, DispatchResult),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Free calls have been disabled
        FreeCallsDisabled,
        /// Account has no free calls left. Call the extrinsic directly or use
        /// `try_free_call_or_pay()`
        NoFreeCallsAvailable,
        /// Account has hit max number of free calls that can be used this era
        MaxFreeCallsPerEra,
        /// Are you fuzzing, or are you just dumb?
        WastingFreeCalls,
    }

    // TODO: https://linear.app/entropyxyz/issue/ENT-58/free-tx-on-idle-hook-for-pruning-old-free-tx-entries
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
        /// If no free calls are available, account pays the stupidity fee of ((base fee) +
        /// (WeightAsFee for querying free calls)).
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
            // - make sure `call` isn't another `try_free_call()` or get WastingFreeCalls

            // cool, now dispatch call with account's origin
            let res = call.dispatch(RawOrigin::Signed(sender.clone()).into());
            Self::deposit_event(Event::FreeCallIssued(
                sender,
                res.map(|_| ()).map_err(|e| e.error),
            ));

            res
        }

        /// Sets the number of free calls each account gets per era.
        /// To disable free calls, set this to `0`.
        /// TODO: weight
        #[pallet::weight(<T as crate::Config>::WeightInfo::set_max_free_calls_per_era())]
        pub fn set_max_free_calls_per_era(
            origin: OriginFor<T>,
            call_count: FreeCallCount,
        ) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;
            if call_count == 0 {
                // make sure that <FreeCallsPerEra> returns None instead of
                // Some(0)
                <MaxIndividualFreeCallsPerEra<T>>::kill();
            } else {
                <MaxIndividualFreeCallsPerEra<T>>::put(call_count);
            }
            Ok(())
        }

        /// Set the number of rechargable calls an account gets. Setting is safer than always
        /// incrementing.
        #[pallet::weight(<T as crate::Config>::WeightInfo::set_rechargable_call_count())]
        pub fn set_rechargable_call_count(
            origin: OriginFor<T>,
            account: T::AccountId,
            call_count: FreeCallCount,
        ) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;
            <FreeCallData<T>>::mutate(&account, |data: &mut Option<FreeCallMetadata>| match data {
                Some(data) => {
                    data.rechargable_calls_allocated += call_count;
                },
                None => {
                    *data = Some(FreeCallMetadata {
                        rechargable_calls_allocated: call_count,
                        fixed_calls_remaining: 0,
                        calls_used: RecentCallCount { latest_era: 0, count: 0 },
                    });
                },
            });
            Ok(())
        }

        /// Give the recipient some free calls
        #[pallet::weight(<T as crate::Config>::WeightInfo::give_fixed_calls())]
        pub fn give_fixed_calls(
            origin: OriginFor<T>,
            recipient: T::AccountId,
            call_count: FreeCallCount,
        ) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;
            <FreeCallData<T>>::mutate(
                &recipient,
                |data: &mut Option<FreeCallMetadata>| match data {
                    Some(data) => {
                        data.fixed_calls_remaining += call_count;
                    },
                    None => {
                        *data = Some(FreeCallMetadata {
                            rechargable_calls_allocated: 0,
                            fixed_calls_remaining: call_count,
                            calls_used: RecentCallCount { latest_era: 0, count: 0 },
                        });
                    },
                },
            );
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        // TODO make sure this is right before moving on
        // if OK(()), a free call for the provided account was available and was consumed
        pub fn try_consume_free_call(account_id: &<T>::AccountId) -> Result<(), Error<T>> {
            // gets max free call count per era or return error if free calls are disabled
            let max_free_call_count_per_era = Self::max_free_calls_per_era();
            if max_free_call_count_per_era == 0 as FreeCallCount {
                return Err(Error::<T>::FreeCallsDisabled);
            }

            <FreeCallData<T>>::mutate(account_id, |call_data: &mut Option<FreeCallMetadata>| {
                let current_era_index = pallet_staking::Pallet::<T>::current_era().unwrap();

                match call_data {
                    // User has at least had free calls at some point
                    Some(current_call_data) => {
                        let era_index_is_current = |data: &mut FreeCallMetadata| -> bool {
                            data.calls_used.latest_era == current_era_index
                        };

                        let user_has_spent_more_free_calls_than_max_this_era =
                            |data: &mut FreeCallMetadata| -> Result<bool, Error<T>> {
                                if era_index_is_current(data)
                                    && data.calls_used.count >= max_free_call_count_per_era
                                {
                                    return Err(Error::<T>::MaxFreeCallsPerEra);
                                }

                                Ok(false)
                            };

                        let spend_call = |data: &mut FreeCallMetadata| {
                            if era_index_is_current(data) {
                                data.calls_used.count += 1;
                            } else {
                                data.calls_used =
                                    RecentCallCount { latest_era: current_era_index, count: 1 }
                            }
                        };

                        let use_rechargable_call = |data: &mut FreeCallMetadata| {
                            spend_call(data);
                        };

                        let spend_fixed_call = |data: &mut FreeCallMetadata| {
                            let count = data.fixed_calls_remaining;

                            data.fixed_calls_remaining =
                                count.saturating_sub(1u32 as FreeCallCount);
                            spend_call(data);
                        };

                        let user_can_use_rechargable_calls =
                            |data: &mut FreeCallMetadata| -> Result<bool, Error<T>> {
                                let user_has_free_calls_to_spend =
                                    !user_has_spent_more_free_calls_than_max_this_era(data)?;

                                Ok(user_has_free_calls_to_spend
                                    && (data.rechargable_calls_allocated > 0 as FreeCallCount)
                                    && ((era_index_is_current(data)
                                        && data.calls_used.count
                                            < data.rechargable_calls_allocated)
                                        || (data.calls_used.latest_era < current_era_index)))
                            };

                        let user_can_spend_fixed_calls =
                            |data: &mut FreeCallMetadata| -> Result<bool, Error<T>> {
                                let user_has_free_calls_to_spend =
                                    !user_has_spent_more_free_calls_than_max_this_era(data)?;

                                Ok(user_has_free_calls_to_spend
                                    && data.fixed_calls_remaining > 0
                                    && era_index_is_current(data))
                            };

                        // everything boils down this...
                        if user_can_use_rechargable_calls(current_call_data)? {
                            use_rechargable_call(current_call_data);
                        } else if user_can_spend_fixed_calls(current_call_data)? {
                            spend_fixed_call(current_call_data);
                        } else {
                            return Err(Error::<T>::NoFreeCallsAvailable);
                        }
                    },
                    // if None, then account has no free calls to use
                    None => return Err(Error::<T>::NoFreeCallsAvailable),
                };
                Ok(())
            })

            // Ok(())
        }

        /// Returns number of free calls a user has, and returns None if free calls are disabled.
        pub fn free_calls_remaining(account_id: &<T>::AccountId) -> FreeCallCount {
            if !Self::free_calls_are_enabled() {
                return 0 as FreeCallCount;
            }

            // if the free call count was last updated this era, return however many free calls they
            // have left
            if let Some(data) = Self::free_call_data(account_id) {
                let FreeCallMetadata {
                    rechargable_calls_allocated,
                    fixed_calls_remaining,
                    calls_used,
                } = data;

                let total_free_calls =
                    rechargable_calls_allocated.saturating_add(fixed_calls_remaining);

                // TODO refactor era_index_is_current() out of try_consume_free_call() for reuse
                // here.
                if calls_used.latest_era == pallet_staking::Pallet::<T>::current_era().unwrap() {
                    return min(
                        Self::max_free_calls_per_era().saturating_sub(calls_used.count),
                        total_free_calls.saturating_sub(calls_used.count),
                    );
                } else {
                    return min(Self::max_free_calls_per_era(), total_free_calls);
                }
            };

            return 0 as FreeCallCount;
        }

        /// Returns the number of free calls per era a user gets, or returns None if free calls are
        /// disabled
        pub fn max_free_calls_per_era() -> FreeCallCount {
            match Self::max_individual_free_calls_per_era() {
                Some(n) => n,
                None => FreeCallCount::MAX,
            }
        }

        /// Checks if free calls are enabled
        fn free_calls_are_enabled() -> bool { Self::max_free_calls_per_era() != 0 as FreeCallCount }
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
                    if Pallet::<T>::free_calls_are_enabled()
                        && Pallet::<T>::free_calls_remaining(who) != 0
                    {
                        return Ok(ValidTransaction::default());
                    }
                    return Err(TransactionValidityError::Invalid(InvalidTransaction::Payment));
                }
            }
            Ok(ValidTransaction::default())
        }
    }
}
