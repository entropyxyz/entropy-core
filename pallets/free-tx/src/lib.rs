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

    /// Batteries and zaps are represented in the base unit of electricity: coulombs. One coulomb
    /// can be used to do one action)
    pub type Coulombs = u32;

    /// Shows the number of coulombs that were used in the previously used era
    /// ie. `latest_era` stores the `EraIndex` that the count is valid for
    #[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Debug, Eq, PartialEq)]
    pub struct ElectricityMeter {
        pub latest_era: EraIndex,
        pub count: Coulombs,
    }

    /// Keeps track of the electricity a user has and has spent this era
    #[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Debug, Eq, PartialEq)]
    pub struct ElectricalPanel {
        pub batteries: Coulombs,
        pub zaps: Coulombs,
        pub used: ElectricityMeter,
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    /// Maximum number of coulombs a user can use per era.
    ///
    /// `None`: users can use as many coulombs as they own.
    /// `Some(0)`: coulombs are disabled.
    /// `Some(n)`: users can use up to `n` coulombs per era
    #[pallet::storage]
    #[pallet::getter(fn max_user_electricity_usage_per_era)]
    pub type MaxUserElectricityUsagePerEra<T: Config> = StorageValue<_, Coulombs>;

    /// Stores the balance of batteries, zaps, and usage of electricity of a user
    #[pallet::storage]
    #[pallet::getter(fn electrical_account)]
    pub type ElectricalAccount<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, ElectricalPanel, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A user spent electricity to dispatch a transaction; the account did not pay any
        /// transaction fees.
        ElectricitySpent(T::AccountId, DispatchResult),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Coulomb usage has been disabled
        ElectricityIsDisabled,
        /// Account has no coulombs left. Call the extrinsic directly or use
        /// `call_using_electricity()`
        NoCoulombsAvailable,
        /// Account has hit max number of coulombs that can be used this era
        ElectricityEraLimitReached,
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
        /// Try to call an extrinsic using the account's available electricity.
        ///
        /// If electricity is available, a coulumb is used and the account will pay zero tx fees,
        /// regardless of the call's result.
        #[pallet::weight({
            let dispatch_info = call.get_dispatch_info();
            let base_weight = <T as Config>::WeightInfo::call_using_electricity();
            (base_weight.saturating_add(dispatch_info.weight), dispatch_info.class, Pays::No)
        })]
        #[allow(clippy::boxed_local)]
        pub fn call_using_electricity(
            origin: OriginFor<T>,
            call: Box<<T as Config>::Call>,
        ) -> DispatchResultWithPostInfo {
            let sender = ensure_signed(origin)?;

            Self::try_spend_coulomb(&sender)?;

            let res = call.dispatch(RawOrigin::Signed(sender.clone()).into());
            Self::deposit_event(Event::ElectricitySpent(
                sender,
                res.map(|_| ()).map_err(|e| e.error),
            ));

            res
        }

        /// Put a cap on the number of coulombs individual accounts can use per era.
        /// To disable electricity temporary, set this to `0`.
        #[pallet::weight(<T as crate::Config>::WeightInfo::set_individual_electricity_era_limit())]
        pub fn set_individual_electricity_era_limit(
            origin: OriginFor<T>,
            max_coulombs: Option<Coulombs>,
        ) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;

            match max_coulombs {
                Some(n) => MaxUserElectricityUsagePerEra::<T>::put(n),
                None => MaxUserElectricityUsagePerEra::<T>::kill(),
            }

            Ok(())
        }

        /// Set the number of batteries an account has. Since they are rechargable, setting (vs
        /// giving) makes more sense in this context.
        #[pallet::weight(<T as crate::Config>::WeightInfo::set_battery_count())]
        pub fn set_battery_count(
            origin: OriginFor<T>,
            account: T::AccountId,
            battery_count: Coulombs,
        ) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;
            <ElectricalAccount<T>>::mutate(
                &account,
                |electrical_panel: &mut Option<ElectricalPanel>| match electrical_panel {
                    Some(electrical_panel) => {
                        electrical_panel.batteries = battery_count;
                    },
                    None => {
                        *electrical_panel = Some(ElectricalPanel {
                            batteries: battery_count,
                            zaps: 0,
                            used: ElectricityMeter { latest_era: 0, count: 0 },
                        });
                    },
                },
            );
            Ok(())
        }

        /// Give the recipient some zaps
        #[pallet::weight(<T as crate::Config>::WeightInfo::give_zaps())]
        pub fn give_zaps(
            origin: OriginFor<T>,
            recipient: T::AccountId,
            coulombs: Coulombs,
        ) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;
            <ElectricalAccount<T>>::mutate(
                &recipient,
                |electrical_panel: &mut Option<ElectricalPanel>| match electrical_panel {
                    Some(electrical_panel) => {
                        electrical_panel.zaps += coulombs;
                    },
                    None => {
                        *electrical_panel = Some(ElectricalPanel {
                            batteries: 0,
                            zaps: coulombs,
                            used: ElectricityMeter { latest_era: 0, count: 0 },
                        });
                    },
                },
            );
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        // if OK(()), a electricity for the account was available
        pub fn try_spend_coulomb(account_id: &<T>::AccountId) -> Result<(), Error<T>> {
            // gets max coulombs per era or return error if electricity is disabled
            let max_coulombs_per_era = Self::individual_electricity_era_limit();
            if max_coulombs_per_era == 0 as Coulombs {
                return Err(Error::<T>::ElectricityIsDisabled);
            }

            <ElectricalAccount<T>>::mutate(account_id, |panel: &mut Option<ElectricalPanel>| {
                let current_era_index = pallet_staking::Pallet::<T>::current_era().unwrap();

                match panel {
                    // User has at least had electricity at some point
                    Some(electrical_panel) => {
                        let era_index_is_current =
                            |electrical_panel: &mut ElectricalPanel| -> bool {
                                electrical_panel.used.latest_era == current_era_index
                            };

                        let user_has_used_max_electricity_allowed_this_era =
                            |electrical_panel: &mut ElectricalPanel| -> Result<bool, Error<T>> {
                                if era_index_is_current(electrical_panel)
                                    && electrical_panel.used.count >= max_coulombs_per_era
                                {
                                    return Err(Error::<T>::ElectricityEraLimitReached);
                                }

                                Ok(false)
                            };

                        let spend_coulomb = |electrical_panel: &mut ElectricalPanel| {
                            if era_index_is_current(electrical_panel) {
                                electrical_panel.used.count += 1;
                            } else {
                                electrical_panel.used =
                                    ElectricityMeter { latest_era: current_era_index, count: 1 }
                            }
                        };

                        let use_battery = |electrical_panel: &mut ElectricalPanel| {
                            spend_coulomb(electrical_panel);
                        };

                        let spend_zap = |electrical_panel: &mut ElectricalPanel| {
                            let count = electrical_panel.zaps;

                            electrical_panel.zaps = count.saturating_sub(1u32 as Coulombs);
                            spend_coulomb(electrical_panel);
                        };

                        let user_can_use_batteries =
                            |electrical_panel: &mut ElectricalPanel| -> Result<bool, Error<T>> {
                                let user_has_electricity_to_spend =
                                    !user_has_used_max_electricity_allowed_this_era(
                                        electrical_panel,
                                    )?;

                                Ok(user_has_electricity_to_spend
                                    && (electrical_panel.batteries > 0 as Coulombs)
                                    && ((era_index_is_current(electrical_panel)
                                        && electrical_panel.used.count
                                            < electrical_panel.batteries)
                                        || (electrical_panel.used.latest_era < current_era_index)))
                            };

                        let user_can_spend_zaps =
                            |electrical_panel: &mut ElectricalPanel| -> Result<bool, Error<T>> {
                                let user_has_electricity_to_spend =
                                    !user_has_used_max_electricity_allowed_this_era(
                                        electrical_panel,
                                    )?;

                                Ok(user_has_electricity_to_spend
                                    && electrical_panel.zaps > 0
                                    && ((era_index_is_current(electrical_panel)
                                        && electrical_panel.used.count < electrical_panel.zaps)
                                        || (electrical_panel.used.latest_era < current_era_index)))
                            };

                        // everything boils down this...
                        if user_can_use_batteries(electrical_panel)? {
                            use_battery(electrical_panel);
                        } else if user_can_spend_zaps(electrical_panel)? {
                            spend_zap(electrical_panel);
                        } else {
                            return Err(Error::<T>::NoCoulombsAvailable);
                        }
                    },
                    // if None, then account has no coulombs to use
                    None => return Err(Error::<T>::NoCoulombsAvailable),
                };
                Ok(())
            })

            // Ok(())
        }

        /// Returns number of coulombs a user can use this era
        pub fn coulombs_usable_this_era(account_id: &<T>::AccountId) -> Coulombs {
            if !Self::electricity_is_enabled() {
                return 0 as Coulombs;
            }

            // if the electricity was last used this era, return however many coulombs they
            // have left
            if let Some(data) = Self::electrical_account(account_id) {
                let ElectricalPanel { batteries, zaps, used } = data;

                // TODO refactor era_index_is_current() out of try_spend_coulomb() for reuse
                // here.
                if used.latest_era == pallet_staking::Pallet::<T>::current_era().unwrap() {
                    return min(
                        Self::individual_electricity_era_limit().saturating_sub(used.count),
                        batteries.saturating_sub(used.count).saturating_add(zaps),
                    );
                } else {
                    return min(
                        Self::individual_electricity_era_limit(),
                        batteries.saturating_add(zaps),
                    );
                }
            };

            0 as Coulombs
        }

        /// Returns the max number of coulombs a user can use per era
        pub fn individual_electricity_era_limit() -> Coulombs {
            match Self::max_user_electricity_usage_per_era() {
                Some(n) => n,
                None => Coulombs::MAX,
            }
        }

        /// Checks if electricity is enabled
        fn electricity_is_enabled() -> bool {
            Self::individual_electricity_era_limit() != 0 as Coulombs
        }
    }

    /// Verifies that the account has coulombs available before executing or broadcasting to other
    /// validators.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct ValidateElectricityPayment<T: Config + Send + Sync>(sp_std::marker::PhantomData<T>)
    where <T as frame_system::Config>::Call: IsSubType<Call<T>>;

    impl<T: Config + Send + Sync> Debug for ValidateElectricityPayment<T>
    where <T as frame_system::Config>::Call: IsSubType<Call<T>>
    {
        #[cfg(feature = "std")]
        fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
            write!(f, "ValidateElectricityPayment")
        }

        #[cfg(not(feature = "std"))]
        fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result { Ok(()) }
    }

    impl<T: Config + Send + Sync> ValidateElectricityPayment<T>
    where <T as frame_system::Config>::Call: IsSubType<Call<T>>
    {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self { Self(sp_std::marker::PhantomData) }
    }

    impl<T: Config + Send + Sync> SignedExtension for ValidateElectricityPayment<T>
    where <T as frame_system::Config>::Call: IsSubType<Call<T>>
    {
        type AccountId = T::AccountId;
        type AdditionalSigned = ();
        type Call = <T as frame_system::Config>::Call;
        type Pre = ();

        const IDENTIFIER: &'static str = "ValidateElectricityPayment";

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
                if let Call::call_using_electricity { .. } = local_call {
                    if Pallet::<T>::electricity_is_enabled()
                        && Pallet::<T>::coulombs_usable_this_era(who) != 0
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
