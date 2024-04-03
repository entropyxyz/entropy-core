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

use frame_support::{assert_noop, assert_ok};
use mock::*;
use sp_runtime::traits::BadOrigin;

use super::*;

#[test]
fn request_limit_changed() {
    ExtBuilder.build().execute_with(|| {
        assert_eq!(Parameters::request_limit(), 0, "Inital request limit set");

        assert_ok!(Parameters::change_request_limit(RuntimeOrigin::root(), 10));

        assert_eq!(Parameters::request_limit(), 10, "Inital request limit changed");

        // Fails not root
        assert_noop!(Parameters::change_request_limit(RuntimeOrigin::signed(2), 15), BadOrigin,);
    });
}

#[test]
fn max_instructions_per_programs_changed() {
    ExtBuilder.build().execute_with(|| {
        assert_eq!(Parameters::max_instructions_per_programs(), 0, "Inital max instructions per program set");

        assert_ok!(Parameters::change_max_instructions_per_programs(RuntimeOrigin::root(), 10));

        assert_eq!(Parameters::max_instructions_per_programs(), 10, "Inital max instructions per program changed");

        // Fails not root
        assert_noop!(
            Parameters::change_max_instructions_per_programs(RuntimeOrigin::signed(2), 15),
            BadOrigin,
        );
    });
}
