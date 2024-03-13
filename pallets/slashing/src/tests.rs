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

use frame_support::assert_ok;

use super::*;
use crate::mock::*;

#[test]
fn can_note_report() {
    new_test_ext().execute_with(|| {
        let (alice, mallory) = (1, 2);

        assert_eq!(Slashing::failed_registrations(mallory), 0);
        assert_ok!(Slashing::note_report(alice, mallory));
        assert_eq!(Slashing::failed_registrations(mallory), 1);
    })
}

#[test]
fn offence_report_submitted_if_above_threshold() {
    new_test_ext().execute_with(|| {
        let (alice, mallory) = (1, 2);

        // A peer was reported, but not enough to for an offence to be filed
        let below_threshold = <Test as Config>::ReportThreshold::get() - 1;
        for _ in 0..below_threshold {
            assert_ok!(Slashing::note_report(alice, mallory));
        }
        assert_eq!(Slashing::failed_registrations(mallory), below_threshold);

        // New session, the reports should be reset for our peer, and no offences should've been
        // filed
        Session::rotate_session();
        assert_eq!(Slashing::failed_registrations(mallory), 0);
        assert!(Offences::get().len() == 0);

        // Now our peer has been reported enough times to get an Offence filed
        let above_threshold = <Test as Config>::ReportThreshold::get();
        for _ in 0..above_threshold {
            assert_ok!(Slashing::note_report(alice, mallory));
        }

        // New session, reports should have been reset and we should see the offence report for
        // Mallory
        Session::rotate_session();
        assert_eq!(Slashing::failed_registrations(mallory), 0);

        let offences = Offences::get();
        assert!(offences.len() == 1);

        let offenders = &offences[0].offenders;
        assert!(offenders[0] == (mallory, mallory));
    })
}

#[test]
fn reported_validator_is_disabled() {
    new_test_ext().execute_with(|| {
        let (alice, mallory) = (1, 2);

        // Our peer has been reported enough times to get an Offence filed
        let above_threshold = <Test as Config>::ReportThreshold::get();
        for _ in 0..above_threshold {
            assert_ok!(Slashing::note_report(alice, mallory));
        }

        // New session, we should see the offence report for Mallory
        Session::rotate_session();

        // let now = System::block_number().max(1);
        // System::set_block_number(now + 1);

        let offences = Offences::get();
        assert!(offences.len() == 1);

        let offenders = &offences[0].offenders;
        assert!(offenders[0] == (mallory, mallory));

        // We should now see Mallory kicked from the validator set
        let _ = <Test as Config>::ValidatorSet::validators().iter().inspect(|id| {
            dbg!(id);
            ()
        });
        dbg!(<Test as Config>::ValidatorSet::validators().len());

        let validator_index = match Session::validators().iter().position(|v| *v == mallory) {
            Some(index) => dbg!(index) as u32,
            None => 0, // TODO (Nando): Don't just return `0` here
        };

        use frame_support::traits::DisabledValidators;
        dbg!(Session::disabled_validators());
        dbg!(Session::is_disabled(validator_index));

        panic!("test end");
    })
}
