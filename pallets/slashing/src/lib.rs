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

use frame_support::{
    dispatch::DispatchResult,
    pallet_prelude::*,
    sp_runtime::{Perbill, RuntimeDebug},
    traits::{ValidatorSet, ValidatorSetWithIdentification},
};
use frame_system::pallet_prelude::*;
use sp_application_crypto::RuntimeAppPublic;
use sp_runtime::{sp_std::str, traits::Convert};
use sp_staking::{
    offence::{Kind, Offence, ReportOffence},
    SessionIndex,
};
use sp_std::vec;
use sp_std::vec::Vec;

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

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
            Self::AccountId,
            UnresponsivenessOffence<Self::AccountId>,
        >;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Keeps track of all the failed registrations that a validator has been involved in.
    ///
    /// If enough of these are tallied up over the course of a session the validator will get kicked
    /// out of the active set.
    #[pallet::storage]
    pub type FailedRegistrations<T: Config> =
        StorageMap<_, Identity, T::AccountId, u32, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A report about an unstable peer has been submitted and taken note of ([who, offender]).
        NoteReport(T::AccountId, T::AccountId),

        // The following peers have been reported as unresponsive in this session.
        UnresponsivenessOffence(Vec<T::AccountId>),
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
                report_count.saturating_add(1)
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

    fn on_genesis_session<'a, I: 'a>(_validators: I)
    where
        I: Iterator<Item = (&'a T::AccountId, T::AuthorityId)>,
    {
        // No work for us to do on genesis
    }

    fn on_new_session<'a, I: 'a>(_changed: bool, _validators: I, _queued_validators: I)
    where
        I: Iterator<Item = (&'a T::AccountId, T::AuthorityId)>,
    {
        // We set the reports for this upcoming session.
        //
        // Might be an expensive operation, but let's go with it for now.
        let _ = FailedRegistrations::<T>::drain();
    }

    fn on_before_session_ending() {
        let offenders = FailedRegistrations::<T>::iter()
            .filter(|report| report.1 >= T::ReportThreshold::get())
            .map(|report| report.0)
            .collect::<Vec<_>>();

        // let session_index = T::ValidatorSet::session_index();
        // let keys = Keys::<T>::get();
        // let current_validators = T::ValidatorSet::validators();
        let session_index = 0;
        let validator_set_count = 0;

        let reporters = vec![];
        let offence = UnresponsivenessOffence {
            session_index,
            validator_set_count,
            offenders: offenders.clone(),
        };
        if let Err(e) = T::ReportUnresponsiveness::report_offence(reporters, offence) {
            sp_runtime::print(e);
        }

        Self::deposit_event(Event::UnresponsivenessOffence(offenders));
    }

    fn on_disabled(_i: u32) {
        // Not really sure what we'd do here, so let's ignore it
    }
}
