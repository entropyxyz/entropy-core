#![cfg_attr(not(feature = "std"), no_std)]
//! # Slashing Pallet
//!
//!
//! ## Overview
//!
//! Allows for customizable slashes to occur on chain
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
        sp_runtime::{Perbill, RuntimeDebug},
        traits::{ValidatorSet, ValidatorSetWithIdentification},
    };
    use frame_system::pallet_prelude::*;
    use scale_info::prelude::vec;
    use sp_application_crypto::RuntimeAppPublic;
    use sp_runtime::{sp_std::str, traits::Convert};
    use sp_staking::{
        offence::{Kind, Offence, ReportOffence},
        SessionIndex,
    };

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type AuthorityId: Member
            + Parameter
            + RuntimeAppPublic
            + Ord
            + MaybeSerializeDeserialize
            + MaxEncodedLen;
        /// A type that gives us the ability to submit unresponsiveness offence reports.
        type ReportBad: ReportOffence<
            Self::AccountId,
            IdentificationTuple<Self>,
            TuxAngry<IdentificationTuple<Self>>,
        >;
        type ValidatorIdOf: Convert<Self::AccountId, Option<ValidatorId<Self>>>;

        /// A type for retrieving the validators supposed to be online in a session.
        type ValidatorSet: ValidatorSetWithIdentification<Self::AccountId>;
        type MinValidators: Get<u32>;
    }

    /// A type for representing the validator id in a session.
    pub type ValidatorId<T> = <<T as Config>::ValidatorSet as ValidatorSet<
        <T as frame_system::Config>::AccountId,
    >>::ValidatorId;

    /// A tuple of (ValidatorId, Identification) where `Identification` is the full identification
    /// of `ValidatorId`.
    pub type IdentificationTuple<T> = (
        ValidatorId<T>,
        <<T as Config>::ValidatorSet as ValidatorSetWithIdentification<
            <T as frame_system::Config>::AccountId,
        >>::Identification,
    );

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A custom offence has been logged. [who, offenders]
        Offence(T::AccountId, Vec<T::AccountId>),
    }

    // Dispatchable functions allows users to interact with the pallet and invoke state changes.
    // These functions materialize as "extrinsics", which are often compared to transactions.
    // Dispatchable functions must be annotated with a weight and must return a DispatchResult.
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// An example dispatchable that may throw a custom error.
        #[pallet::call_index(0)]
        #[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1).ref_time())]
        pub fn demo_offence(origin: OriginFor<T>, offenders: Vec<T::AccountId>) -> DispatchResult {
            // TODO remove this function, it is for demo purposes only
            let who = ensure_signed(origin)?;
            Self::do_offence(who, offenders)?;
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn do_offence(
            who: T::AccountId,
            offender_addresses: Vec<T::AccountId>,
        ) -> DispatchResult {
            let offenders = offender_addresses
				.clone()
				.into_iter()
				.filter_map(T::ValidatorIdOf::convert)
				.filter_map(|id| {
					<T::ValidatorSet as ValidatorSetWithIdentification<T::AccountId>>::IdentificationOf::convert(
				id.clone()
			).map(|full_id| (id, full_id))
				})
				.collect::<Vec<IdentificationTuple<T>>>();

            let session_index = T::ValidatorSet::session_index();
            let current_validators = T::ValidatorSet::validators();
            let validator_set_count = current_validators.len() as u32;
            if validator_set_count.saturating_sub(offender_addresses.len() as u32)
                <= T::MinValidators::get()
            {
                log::info!("Min validators not slashed: {:?}", offenders);
            } else {
                log::info!("session_index: {:?}", session_index);
                log::info!("offenders: {:?}", offenders);

                let offence = TuxAngry { session_index, validator_set_count, offenders };

                log::info!("offence: {:?}", offence);
                if let Err(e) = T::ReportBad::report_offence(vec![who.clone()], offence) {
                    log::error!("error: {:?}", e);
                };
            }
            Self::deposit_event(Event::Offence(who, offender_addresses));
            Ok(())
        }
    }

    /// An offence that is filed if a validator didn't send a heartbeat message.
    #[derive(RuntimeDebug)]
    #[cfg_attr(feature = "std", derive(Clone, PartialEq, Eq))]
    pub struct TuxAngry<Offender> {
        /// The current session index in which we report the unresponsive validators.
        ///
        /// It acts as a time measure for unresponsiveness reports and effectively will always
        /// point at the end of the session.
        pub session_index: SessionIndex,
        /// The size of the validator set in current session/era.
        pub validator_set_count: u32,
        /// Authorities that were unresponsive during the current era.
        pub offenders: Vec<Offender>,
    }

    impl<Offender: Clone> Offence<Offender> for TuxAngry<Offender> {
        type TimeSlot = SessionIndex;

        const ID: Kind = *b"tux-really-angry";

        fn offenders(&self) -> Vec<Offender> { self.offenders.clone() }

        fn session_index(&self) -> SessionIndex { self.session_index }

        fn validator_set_count(&self) -> u32 { self.validator_set_count }

        fn time_slot(&self) -> Self::TimeSlot { self.session_index }

        fn slash_fraction(&self, _offenders_count: u32) -> Perbill { Perbill::from_perthousand(0) }
    }
}
