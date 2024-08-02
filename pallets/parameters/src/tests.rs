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

//! Unit tests for the parameters pallet.

#![cfg(test)]

use entropy_shared::MAX_SIGNERS;
use frame_support::{assert_noop, assert_ok};
use mock::*;
use sp_runtime::traits::BadOrigin;

use super::*;

#[test]
fn request_limit_changed() {
    new_test_ext().execute_with(|| {
        assert_eq!(Parameters::request_limit(), 5, "Inital request limit set");

        assert_ok!(Parameters::change_request_limit(RuntimeOrigin::root(), 10));

        assert_eq!(Parameters::request_limit(), 10, "Inital request limit changed");

        // Fails not root
        assert_noop!(Parameters::change_request_limit(RuntimeOrigin::signed(2), 15), BadOrigin,);
    });
}

#[test]
fn max_instructions_per_programs_changed() {
    new_test_ext().execute_with(|| {
        assert_eq!(
            Parameters::max_instructions_per_programs(),
            5,
            "Inital max instructions per program set"
        );

        assert_ok!(Parameters::change_max_instructions_per_programs(RuntimeOrigin::root(), 10));

        assert_eq!(
            Parameters::max_instructions_per_programs(),
            10,
            "Inital max instructions per program changed"
        );

        // Fails not root
        assert_noop!(
            Parameters::change_max_instructions_per_programs(RuntimeOrigin::signed(2), 15),
            BadOrigin,
        );
    });
}

#[test]
fn signer_info_changed() {
    new_test_ext().execute_with(|| {
        let signer_info = SignersSize { total_signers: 5, threshold: 3 };
        let new_signer_info = SignersSize { total_signers: 6, threshold: 4 };

        assert_eq!(Parameters::signers_info(), signer_info, "Inital signer info set");

        assert_ok!(Parameters::change_signers_info(
            RuntimeOrigin::root(),
            new_signer_info.total_signers,
            new_signer_info.threshold
        ));

        assert_eq!(Parameters::signers_info(), new_signer_info, "Inital signer info changed");

        // Fails not root
        assert_noop!(
            Parameters::change_signers_info(
                RuntimeOrigin::signed(2),
                signer_info.total_signers,
                signer_info.threshold
            ),
            BadOrigin,
        );

        // Fails threhsold greater then signers
        assert_noop!(
            Parameters::change_signers_info(RuntimeOrigin::root(), 2, 3),
            Error::<Runtime>::ThresholdGreaterThenSigners,
        );

        // Fails threhsold is 0
        assert_noop!(
            Parameters::change_signers_info(RuntimeOrigin::root(), 0, 0),
            Error::<Runtime>::ThrehsoldTooLow,
        );

        // Fails too many signers
        assert_noop!(
            Parameters::change_signers_info(RuntimeOrigin::root(), MAX_SIGNERS + 1, 1),
            Error::<Runtime>::TooManySigners,
        );
    });
}
