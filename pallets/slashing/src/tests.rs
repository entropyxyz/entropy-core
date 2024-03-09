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

// use frame_support::{assert_err, assert_ok};
// use sp_runtime::Perbill;
// use sp_staking::offence::Offence;
//
// use super::*;
// use crate::mock::*;
//
// #[test]
// fn slash_fraction_works() {
//     new_test_ext().execute_with(|| {
//         let offence = TuxAngry { session_index: 0, validator_set_count: 50, offenders: vec![()] };
//         assert_eq!(offence.slash_fraction(1), Perbill::from_perthousand(0));
//     });
// }
//
// #[test]
// fn offence_test() {
//     new_test_ext().execute_with(|| {
//         assert_ok!(Staking::force_new_era_always(RuntimeOrigin::root()));
//         assert!(Session::validators().contains(&1));
//
//         // slash would cause min validators to drop below min validators no offence
//         assert_ok!(Slashing::demo_offence(RuntimeOrigin::root(), 1, vec![1u64, 2u64]));
//         let mut offences = OFFENCES.with(|l| l.replace(vec![]));
//         assert_eq!(offences.len(), 0);
//
//         // causes offence
//         assert_ok!(Slashing::demo_offence(RuntimeOrigin::root(), 1, vec![1u64]));
//         offences = OFFENCES.with(|l| l.replace(vec![]));
//         assert_eq!(offences.len(), 1);
//     });
// }
//
// #[test]
// fn signed_origin_cannot_initiate_demo_offence() {
//     new_test_ext().execute_with(|| {
//         assert_err!(
//             Slashing::demo_offence(RuntimeOrigin::signed(1), 1, vec![1u64, 2u64]),
//             sp_runtime::DispatchError::BadOrigin
//         );
//     })
// }
