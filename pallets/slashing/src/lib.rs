// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#![cfg_attr(not(feature = "std"), no_std)]

//! # Slashing Pallet
//!
//! ## Overview
//!
//! The Slashing pallet is responsible for tracking misbehaviour from validators and, if required,
//! triggering offence reporting (a.k.a slashing).
//!
//! The pallet doesn't concern itself with the specific details of why a validator was reported.
//! Instead it offers a place for already verified reports to be tracked.
//!
//! For example, the Registry pallet may determine that a validator misbehaved during registration,
//! at which point it can call the Slashing pallet to deal with any actual slashing.

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

use frame_support::{
    dispatch::DispatchResult,
    pallet_prelude::*,
    sp_runtime::{Perbill, RuntimeDebug},
    traits::{ValidatorSet, ValidatorSetWithIdentification},
};
use sp_application_crypto::RuntimeAppPublic;
use sp_runtime::{sp_std::str, traits::Convert};
use sp_staking::{
    offence::{Kind, Offence, ReportOffence},
    SessionIndex,
};
use sp_std::vec;
use sp_std::vec::Vec;

/// A type for representing the validator id in a session.
pub type ValidatorId<T> = <<T as Config>::ValidatorSet as ValidatorSet<
    <T as frame_system::Config>::AccountId,
>>::ValidatorId;

/// A tuple of (ValidatorId, Identification) where `Identification` is the full identification of
/// `ValidatorId`.
pub type IdentificationTuple<T> = (
    ValidatorId<T>,
    <<T as Config>::ValidatorSet as ValidatorSetWithIdentification<
        <T as frame_system::Config>::AccountId,
    >>::Identification,
);

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// The identifier type for an authority.
        type AuthorityId: Member
            + Parameter
            + RuntimeAppPublic
            + Ord
            + MaybeSerializeDeserialize
            + MaxEncodedLen;

        /// The number of reports it takes before a validator gets slashed.
        ///
        /// This is a simple counter for now, but we could do something more elaborate in the
        /// future. For example, making sure that a certain percentage of the validator set also
        /// reported this peer.
        type ReportThreshold: Get<u32>;

        /// A type that gives us the ability to submit unresponsiveness offence reports.
        type ReportUnresponsiveness: ReportOffence<
            Self::AccountId,
            IdentificationTuple<Self>,
            UnresponsivenessOffence<IdentificationTuple<Self>>,
        >;

        /// A type which represents the current validator set.
        ///
        /// We use an identifiable variant in order to be compatible with the Offences pallet's
        /// reporting traits.
        type ValidatorSet: ValidatorSetWithIdentification<Self::AccountId>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Keeps track of all the failed registrations that a validator has been involved in.
    ///
    /// If enough of these are tallied up over the course of a session the validator will get kicked
    /// out of the active set.
    #[pallet::storage]
    #[pallet::getter(fn failed_registrations)]
    pub type FailedRegistrations<T: Config> =
        StorageMap<_, Identity, T::AccountId, u32, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A report about an unstable peer has been submitted and taken note of ([who, offender]).
        NoteReport(T::AccountId, T::AccountId),

        // The following peers have been reported as unresponsive in this session.
        UnresponsivenessOffence(Vec<IdentificationTuple<T>>),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {}

    impl<T: Config> Pallet<T> {
        /// Notes down when a peer was reported.
        ///
        /// If a peer is reported enough times in a session it will end up getting kicked from the
        /// validator set.
        pub fn note_report(who: T::AccountId, offender: T::AccountId) -> DispatchResult {
            FailedRegistrations::<T>::mutate(&offender, |report_count| {
                *report_count = report_count.saturating_add(1)
            });

            Self::deposit_event(Event::NoteReport(who, offender));

            Ok(())
        }
    }
}

/// An offence that is filed if a validator was unresponsive during their protocol
/// responsibilies (i.e registration and signing).
#[derive(RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Clone, PartialEq, Eq))]
pub struct UnresponsivenessOffence<Offender> {
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

impl<Offender: Clone> Offence<Offender> for UnresponsivenessOffence<Offender> {
    type TimeSlot = SessionIndex;

    const ID: Kind = *b"unresponsivepeer";

    fn offenders(&self) -> Vec<Offender> {
        self.offenders.clone()
    }

    fn session_index(&self) -> SessionIndex {
        self.session_index
    }

    fn validator_set_count(&self) -> u32 {
        self.validator_set_count
    }

    fn time_slot(&self) -> Self::TimeSlot {
        self.session_index
    }

    fn slash_fraction(&self, _offenders_count: u32) -> Perbill {
        Perbill::from_perthousand(0)
    }
}

impl<T: Config> sp_runtime::BoundToRuntimeAppPublic for Pallet<T> {
    type Public = T::AuthorityId;
}

impl<T: Config> frame_support::traits::OneSessionHandler<T::AccountId> for Pallet<T> {
    type Key = T::AuthorityId;

    fn on_genesis_session<'a, I>(_validators: I)
    where
        I: 'a + Iterator<Item = (&'a T::AccountId, T::AuthorityId)>,
    {
        // No work for us to do on genesis
    }

    fn on_new_session<'a, I>(_changed: bool, _validators: I, _queued_validators: I)
    where
        I: 'a + Iterator<Item = (&'a T::AccountId, T::AuthorityId)>,
    {
        // We reset the reports for this upcoming session.
        //
        // We don't expect more than 1000 validators on the network, so this operation shouldn't be
        // prohibitively expensive.
        let limit = 1_000;
        let _ = FailedRegistrations::<T>::clear(limit, None);
    }

    fn on_before_session_ending() {
        let offenders = FailedRegistrations::<T>::iter()
            .filter(|report| report.1 >= T::ReportThreshold::get())
            .map(|report| report.0)
            .filter_map(|account_id| {
                <T::ValidatorSet as frame_support::traits::ValidatorSet<T::AccountId>>::
                    ValidatorIdOf::convert(account_id)
            })
            .filter_map(|validator_id| {
                <T::ValidatorSet as ValidatorSetWithIdentification<T::AccountId>>::
                    IdentificationOf::convert(validator_id.clone()
                )
                .map(|full_id| (validator_id, full_id))
            })
            .collect::<Vec<IdentificationTuple<T>>>();

        let session_index = T::ValidatorSet::session_index();
        let validator_set_count = T::ValidatorSet::validators().len() as u32;

        // We don't keep track of the reporters since we don't reward them for the report.
        // Depending on the direction we take with offence reporting we might want to change this
        // in the future.
        let reporters = vec![];
        let offence = UnresponsivenessOffence {
            session_index,
            validator_set_count,
            offenders: offenders.clone(),
        };

        if !offenders.is_empty() {
            if let Err(e) = T::ReportUnresponsiveness::report_offence(reporters, offence) {
                sp_runtime::print(e);
            }
            Self::deposit_event(Event::UnresponsivenessOffence(offenders));
        }
    }

    fn on_disabled(_i: u32) {
        // Not really sure what we'd do here, so let's ignore it
    }
}
